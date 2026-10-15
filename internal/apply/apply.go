// Package apply keeps the overlay file equal to the settings and the
// bound hooks: rendered at start, after every settings change and every
// binding change, and every resync interval (a file someone replaced).
package apply

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

const resync = 30 * time.Second

// ErrNotWritten: the overlay has not been written yet.
var ErrNotWritten = errors.New("the overlay has not been written yet")

// Applier owns the overlay file.
type Applier struct {
	deps.Component

	path     string
	mode     os.FileMode
	settings config.Live[overlay.Settings]
	flows    *flows.Flows
	wiring   overlay.Wiring

	kick chan struct{}

	mu    sync.Mutex
	state State
}

// State is what the applier last did.
type State struct {
	// Path of the file; empty: snippets mode (nothing written).
	Path string
	// Content is the last rendering (secrets in it).
	Content []byte
	// Hash of Content; WrittenAt when it reached the file.
	Hash      string
	WrittenAt time.Time
	// Err is why the last rendering was not written; the file keeps the
	// previous one.
	Err error
}

// New creates the applier; an empty path renders without writing.
func New(
	parent deps.Scope,
	path string,
	mode os.FileMode,
	settings config.Live[overlay.Settings],
	f *flows.Flows,
	w overlay.Wiring,
) *Applier {
	a := &Applier{
		Component: deps.NewComponent(
			parent,
			"overlay",
		), path: path, mode: mode, settings: settings, flows: f, wiring: w,
		kick: make(chan struct{}, 1), state: State{Path: path},
	}
	a.wiring.Bound = f.Bound

	settings.Watch(func(overlay.Settings) { a.Kick() })
	a.Go(a.loop)

	return a
}

// Kick asks for a rendering now.
func (a *Applier) Kick() {
	select {
	case a.kick <- struct{}{}:
	default:
	}
}

// State is the last rendering.
func (a *Applier) State() State {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.state
}

// Ready: in file mode the overlay was written once (Kratos needs it).
func (a *Applier) Ready(context.Context) error {
	st := a.State()
	if st.Path == "" || !st.WrittenAt.IsZero() {
		return nil
	}

	if st.Err != nil {
		return fmt.Errorf("%w: %w", ErrNotWritten, st.Err)
	}

	return ErrNotWritten
}

// Render is the overlay for the current settings, validated.
func (a *Applier) Render() ([]byte, error) {
	doc, err := overlay.Render(a.settings.Get(), a.wiring)
	if err != nil {
		return nil, err
	}

	if err := overlay.Validate(doc); err != nil {
		return nil, err
	}

	return overlay.Encode(doc)
}

// Validate checks candidate settings as the applier would render them.
func (a *Applier) Validate(s overlay.Settings) error {
	doc, err := overlay.Render(s, a.wiring)
	if err != nil {
		return err
	}

	return overlay.Validate(doc)
}

// firstBindings bounds the wait for the bound hooks before the first
// rendering: rendered before they are known, every hook counts as bound.
const firstBindings = 3 * time.Second

func (a *Applier) loop(ctx context.Context) error {
	bindings := a.flows.BindingChanges(ctx)

	select {
	case <-ctx.Done():
		return nil
	case <-bindings:
	case <-time.After(firstBindings):
	}

	tick := time.NewTicker(resync)
	defer tick.Stop()

	for {
		a.apply(ctx)

		select {
		case <-ctx.Done():
			return nil
		case <-bindings:
		case <-a.kick:
		case <-tick.C:
		}
	}
}

func (a *Applier) apply(ctx context.Context) {
	content, err := a.Render()

	a.mu.Lock()
	prev := a.state
	a.mu.Unlock()

	next := prev
	next.Err = err

	if err == nil {
		sum := sha256.Sum256(content)
		next.Content, next.Hash = content, hex.EncodeToString(sum[:8])

		if a.path != "" {
			changed, werr := overlay.Write(a.path, content, a.mode)

			switch {
			case werr != nil:
				next.Err = werr
			case changed || prev.WrittenAt.IsZero():
				next.WrittenAt = time.Now()
			}

			if changed {
				a.Log().
					Ctx().
					Info(ctx, "kratos overlay written", xlog.String("path", a.path), xlog.String("hash", next.Hash))
			}
		}
	}

	if next.Err != nil && (prev.Err == nil || prev.Err.Error() != next.Err.Error()) {
		a.Log().Ctx().Warn(ctx, "kratos overlay not applied: the file keeps the previous settings", xlog.Err(next.Err))
	}

	a.mu.Lock()
	a.state = next
	a.mu.Unlock()
}

// mask is what a secret shows as outside the file.
const mask = "••••••"

// Masked is the overlay for the current settings with every secret
// (client secrets, headers, the callbacks key) masked.
func (a *Applier) Masked() ([]byte, error) {
	s := a.settings.Get()

	providers := make([]overlay.OIDCProvider, len(s.Methods.OIDC.Providers))
	for i := range s.Methods.OIDC.Providers {
		providers[i] = s.Methods.OIDC.Providers[i]
		if providers[i].ClientSecret.Reveal() != "" {
			providers[i].ClientSecret = mask
		}
	}

	s.Methods.OIDC.Providers = providers

	headers := make(map[string]config.Secret, len(s.OAuth2Provider.Headers))
	for k := range s.OAuth2Provider.Headers {
		headers[k] = mask
	}

	s.OAuth2Provider.Headers = headers

	w := a.wiring
	w.Key = mask

	doc, err := overlay.Render(s, w)
	if err != nil {
		return nil, err
	}

	return overlay.Encode(doc)
}

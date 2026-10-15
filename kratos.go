// Package kratos is backplane-kratos as a library: Main runs it. It joins
// an Ory Kratos installation to Backplane: the courier's messages and the
// self-service flows become hooks and events, the admin API becomes
// activities and a console module, and the settings an operator edits are
// written to a configuration overlay Kratos reloads.
package kratos

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane"
	"github.com/backplane-labs/backplane/pkg/backplane/api"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/drivers/standard"
	"google.golang.org/grpc"

	"github.com/gopherex/xprobe/pkg/probe"

	"github.com/backplane-labs/backplane-kratos/internal/activities"
	"github.com/backplane-labs/backplane-kratos/internal/admin"
	"github.com/backplane-labs/backplane-kratos/internal/apply"
	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	"github.com/backplane-labs/backplane-kratos/internal/ui"
	kratosconsolev1 "github.com/backplane-labs/backplane-kratos/proto/kratos/console/v1"
)

// Config is the whole configuration: file (BACKPLANE_CONFIG_FILE) < env
// KRATOS_* (BACKPLANE_* for the SDK block) < Consul KV for Live fields.
type Config struct {
	config.Backplane `json:"backplane"`

	// Kratos is the installation.
	Kratos Connection `json:"kratos"`
	// Callbacks is the listener Kratos calls (courier, hooks, events).
	Callbacks Callbacks `json:"callbacks"`
	// Overlay is the file Kratos loads after its own (-c base -c overlay),
	// shared with the Kratos container; empty: nothing is written, the
	// console shows the configuration to paste.
	Overlay string `json:"overlay,omitempty" schemapb:"description=Path of the overlay file Kratos loads (empty: snippets only)"`
	// OverlayMode is the file's permission bits (octal): Kratos's user
	// must read it.
	OverlayMode string `json:"overlay_mode,omitempty" schemapb:"default=0644"`
	// Settings are Kratos's settings rendered into the overlay; live.
	Settings config.Live[overlay.Settings] `json:"settings"`
	// OIDCSecrets are the OIDC providers' client secrets by provider id;
	// live, kept apart from the settings.
	OIDCSecrets config.Live[map[string]config.Secret] `json:"oidc_secrets,omitempty" schemapb:"description=Client secrets of the OIDC providers by provider id"`
	// OAuth2ProviderHeaders go with Kratos's requests to Hydra; live.
	OAuth2ProviderHeaders config.Live[map[string]config.Secret] `json:"oauth2_provider_headers,omitempty" schemapb:"description=Headers of Kratos's requests to Hydra's admin API"`
	// FailOpen names flow hooks whose failure lets the flow continue.
	FailOpen config.Live[[]string] `json:"fail_open,omitempty" schemapb:"description=Flow hooks (e.g. AfterLogin) whose failure lets the flow continue"`
}

// Connection to Kratos.
type Connection struct {
	AdminURL  string                   `json:"admin_url"         schemapb:"default=http://127.0.0.1:4434"`
	PublicURL string                   `json:"public_url"        schemapb:"default=http://127.0.0.1:4433"`
	Headers   map[string]config.Secret `json:"headers,omitempty" schemapb:"description=Headers of every request (a proxy's authorization)"`
	Timeout   time.Duration            `json:"timeout"           schemapb:"default=10s"`
}

// Callbacks listener.
type Callbacks struct {
	Listen string `json:"listen" schemapb:"default=:8090"`
	// URL is the listener as Kratos reaches it.
	URL string `json:"url" schemapb:"default=http://127.0.0.1:8090"`
	// Key authenticates Kratos; empty: derived from the internal secret,
	// the same on every replica.
	Key config.Secret `json:"key,omitempty"`
}

// Validate what the schema cannot: the settings must render into a
// configuration Kratos accepts.
func (c *Config) Validate() error {
	every := func(string) bool { return true }

	doc, err := overlay.Render(
		c.Settings.Get(), overlay.Secrets{},
		overlay.Wiring{URL: c.Callbacks.URL, Key: "k", Bound: every, Events: true},
	)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	if err := overlay.Validate(doc); err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	return nil
}

// callbackKey is the configured key or one derived from the internal
// secret.
func (c *Config) callbackKey() (string, error) {
	if k := c.Callbacks.Key.Reveal(); k != "" {
		return k, nil
	}

	secret := c.InternalSecret.Reveal()
	if secret == "" {
		return "", ErrNoKey
	}

	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("backplane-kratos callbacks"))

	return hex.EncodeToString(m.Sum(nil)), nil
}

// ErrOverlayMode: overlay_mode is not octal permission bits.
var ErrOverlayMode = errors.New("kratos: overlay_mode must be octal permission bits like 0640")

// ErrNoKey: neither a callbacks key nor an internal secret is configured.
var ErrNoKey = errors.New("kratos: callbacks.key or backplane.internal_secret is required")

// State is the service's tree.
type State struct {
	Kratos     deps.Dependency[ory.Client]
	Flows      *flows.Flows
	Applier    *apply.Applier
	Activities *activities.Activities
	Admin      *admin.Admin

	callbacks string // listen address of the callbacks
}

// Main runs backplane-kratos until a signal stops it, exiting on error.
func Main() {
	if err := Run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Run runs backplane-kratos until ctx ends or a signal stops it.
func Run(ctx context.Context) error {
	svc, err := backplane.Open(ctx, newState, standard.Drivers())
	if err != nil {
		return fmt.Errorf("kratos: %w", err)
	}

	st := svc.State()

	svc.HTTP("/", st.Flows.Handler(), api.Listen(st.callbacks))
	svc.Internal(func(r grpc.ServiceRegistrar) { kratosconsolev1.RegisterAdminServiceServer(r, st.Admin) })

	if bundle := ui.Bundle(); bundle != nil {
		svc.UI(bundle)
	}

	svc.ReadinessProbe(probe.FromError(st.Applier.Ready))

	if err := svc.Run(ctx); err != nil {
		return fmt.Errorf("kratos: %w", err)
	}

	return nil
}

func newState(root backplane.Root[Config]) (*State, error) {
	cfg := root.Config()

	key, err := cfg.callbackKey()
	if err != nil {
		return nil, err
	}

	headers := map[string]string{}
	for k, v := range cfg.Kratos.Headers {
		headers[k] = v.Reveal()
	}

	client, err := ory.New(ory.Options{
		Admin: cfg.Kratos.AdminURL, Public: cfg.Kratos.PublicURL, Headers: headers, Timeout: cfg.Kratos.Timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("kratos: %w", err)
	}

	st := &State{
		Kratos:    deps.NewDependency[ory.Client](root, dependency{client: client}),
		callbacks: cfg.Callbacks.Listen,
	}
	st.Flows = flows.New(root, key, cfg.FailOpen)

	mode, err := strconv.ParseUint(cfg.OverlayMode, 8, 32)
	if err != nil || mode > 0o777 {
		return nil, fmt.Errorf("%w: %q", ErrOverlayMode, cfg.OverlayMode)
	}

	st.Applier = apply.New(
		root,
		cfg.Overlay,
		os.FileMode(mode),
		cfg.Settings,
		apply.Secrets{
			OIDC:                  cfg.OIDCSecrets,
			OAuth2ProviderHeaders: cfg.OAuth2ProviderHeaders,
		},
		st.Flows,
		overlay.Wiring{
			URL: cfg.Callbacks.URL, Key: key, Events: cfg.NATS.Enabled(),
		},
	)
	st.Activities = activities.New(root, client)
	st.Admin = admin.New(root, client, st.Flows, st.Applier, cfg.FailOpen, cfg.NATS.Enabled())

	return st, nil
}

// dependency is the Kratos installation: ready while its admin API is.
type dependency struct{ client ory.Client }

func (dependency) Name() string { return "kratos" }

func (d dependency) Provide(context.Context, deps.Scope) (ory.Client, error) { return d.client, nil }

func (d dependency) Probe(ctx context.Context, _ ory.Client) error {
	if err := d.client.Ready(ctx); err != nil {
		return fmt.Errorf("kratos at %s: %w", d.client.AdminURL(), err)
	}

	return nil
}

func (dependency) Close(context.Context, ory.Client) error { return nil }

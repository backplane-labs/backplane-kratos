package events

import (
	"context"
	"encoding/json"
	"slices"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/sections"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// LoginSectionName is the section backplane-kratos offers live.
const LoginSectionName = "kratos.login"

// Schemas reads the identity schemas Kratos runs with.
type Schemas interface {
	ListSchemas(ctx context.Context) ([]ory.Schema, error)
}

// Login offers the section kratos.login and keeps it following the
// settings. Its identifiers come from the identity schemas the settings
// set; when they set none, Kratos runs its base file's, read from Kratos
// every poll.
type Login struct {
	deps.Component

	section  sections.Live[*kratoseventsv1.LoginSection]
	settings config.Live[overlay.Settings]
	kratos   Schemas
	poll     time.Duration

	mu      sync.Mutex
	base    []json.RawMessage // Kratos's schemas, last read
	failing bool
}

// NewLogin offers kratos.login under scope.
func NewLogin(scope deps.Scope, settings config.Live[overlay.Settings], kratos Schemas, poll time.Duration) *Login {
	l := &Login{
		Component: deps.NewComponent(scope, "login section"),
		section:   sections.OfferLive[*kratoseventsv1.LoginSection](scope, LoginSectionName),
		settings:  settings, kratos: kratos, poll: poll,
	}

	l.offer(settings.Get())
	settings.Watch(l.offer)
	l.Go(l.follow)

	return l
}

func (l *Login) offer(s overlay.Settings) {
	schemas := settingsSchemas(s)
	if len(schemas) == 0 {
		l.mu.Lock()
		schemas = l.base
		l.mu.Unlock()
	}

	// A generated message always marshals.
	_ = l.section.Set(LoginSection(s, schemas))
}

// follow reads Kratos's schemas while the settings set none.
func (l *Login) follow(ctx context.Context) error {
	t := time.NewTicker(l.poll)
	defer t.Stop()

	for {
		if s := l.settings.Get(); len(s.Identity.Schemas) == 0 {
			l.read(ctx)
			l.offer(s)
		}

		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
	}
}

// read keeps Kratos's schemas; a failure keeps the last ones and is
// logged once until a read succeeds.
func (l *Login) read(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, l.poll)
	defer cancel()

	list, err := l.kratos.ListSchemas(ctx)

	l.mu.Lock()
	defer l.mu.Unlock()

	if err != nil {
		if !l.failing && ctx.Err() == nil {
			l.Log().Ctx().Warn(ctx, "identity schemas not read from kratos", xlog.Err(err))
		}

		l.failing = true

		return
	}

	l.failing = false
	l.base = make([]json.RawMessage, 0, len(list))

	for _, s := range list {
		l.base = append(l.base, s.Schema)
	}
}

// settingsSchemas are the schemas the settings set, by id.
func settingsSchemas(s overlay.Settings) []json.RawMessage {
	ids := make([]string, 0, len(s.Identity.Schemas))
	for id := range s.Identity.Schemas {
		ids = append(ids, id)
	}

	slices.Sort(ids)

	out := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		out = append(out, json.RawMessage(s.Identity.Schemas[id]))
	}

	return out
}

// LoginSection is the public part of settings: how identities sign up and
// sign in, without secrets or provider credentials; identifiers from
// schemas.
func LoginSection(s overlay.Settings, schemas []json.RawMessage) *kratoseventsv1.LoginSection {
	m := s.Methods
	out := &kratoseventsv1.LoginSection{
		RegistrationEnabled: s.Registration.Enabled, RegistrationStyle: s.Registration.Style,
		LoginStyle:         s.Login.Style,
		SessionRequiredAal: s.Session.WhoamiRequiredAAL, SettingsRequiredAal: s.Settings.RequiredAAL,
		RequireVerifiedAddress: s.Login.RequireVerifiedAddress,
		RecoveryEnabled:        s.Recovery.Enabled, VerificationEnabled: s.Verification.Enabled,
	}

	first := map[string]bool{
		"password": m.Password.Enabled,
		"code":     m.Code.Enabled && m.Code.Passwordless,
		"webauthn": m.WebAuthn.Enabled && m.WebAuthn.Passwordless,
		"passkey":  m.Passkey.Enabled,
		"oidc":     m.OIDC.Enabled,
	}
	second := map[string]bool{
		"totp":          m.TOTP.Enabled,
		"lookup_secret": m.LookupSecret.Enabled,
		"webauthn":      m.WebAuthn.Enabled && !m.WebAuthn.Passwordless,
		"code":          m.Code.Enabled && m.Code.MFA,
	}

	for _, method := range []string{"password", "code", "webauthn", "passkey", "oidc"} {
		if first[method] {
			out.FirstFactors = append(out.FirstFactors, method)
		}
	}

	for _, method := range []string{"totp", "lookup_secret", "webauthn", "code"} {
		if second[method] {
			out.SecondFactors = append(out.SecondFactors, method)
		}
	}

	if m.OIDC.Enabled {
		for i := range m.OIDC.Providers {
			p := &m.OIDC.Providers[i]
			out.OidcProviders = append(out.OidcProviders, &kratoseventsv1.OIDCProvider{
				Id: p.ID, Provider: p.Provider, Label: p.Label,
			})
		}
	}

	out.Identifiers = Identifiers(schemas, out.GetFirstFactors())

	return out
}

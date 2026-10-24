package events

import (
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/sections"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// LoginSectionName is the section backplane-kratos offers live.
const LoginSectionName = "kratos.login"

// OfferLogin offers the section kratos.login under scope and keeps it
// following settings.
func OfferLogin(scope deps.Scope, settings config.Live[overlay.Settings]) {
	login := sections.OfferLive[*kratoseventsv1.LoginSection](scope, LoginSectionName)
	offer := func(s overlay.Settings) {
		// A generated message always marshals.
		_ = login.Set(LoginSection(s))
	}

	offer(settings.Get())
	settings.Watch(offer)
}

// LoginSection is the public part of settings: how identities sign up and
// sign in, without secrets or provider credentials.
func LoginSection(s overlay.Settings) *kratoseventsv1.LoginSection {
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

	return out
}

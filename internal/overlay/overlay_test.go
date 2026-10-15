package overlay_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// defaults are the schema defaults of Settings: Kratos's own.
func defaults() overlay.Settings {
	return overlay.Settings{
		Registration: overlay.Registration{
			Enabled:    true,
			Lifespan:   time.Hour,
			LoginAfter: true,
			Style:      "profile_first",
		},
		Login: overlay.Login{Lifespan: time.Hour, Style: "unified"},
		Settings: overlay.SettingsFlow{
			Lifespan:                time.Hour,
			PrivilegedSessionMaxAge: time.Hour,
			RequiredAAL:             "highest_available",
		},
		Recovery:     overlay.Recovery{Lifespan: time.Hour, Use: "code"},
		Verification: overlay.Verification{Lifespan: time.Hour, Use: "code"},
		Methods: overlay.Methods{
			Password: overlay.Password{
				Enabled:                   true,
				MinLength:                 8,
				IdentifierSimilarityCheck: true,
				HaveIBeenPwned:            true,
			},
			Code:    overlay.Code{Enabled: true, Lifespan: time.Hour},
			Profile: overlay.ToggleOn{Enabled: true},
		},
		Session: overlay.Session{
			Lifespan:          24 * time.Hour,
			WhoamiRequiredAAL: "highest_available",
			CookiePersistent:  true,
			CookieSameSite:    "Lax",
		},
	}
}

func all(string) bool { return true }

func at(t *testing.T, doc map[string]any, path string) any {
	t.Helper()

	var cur any = doc

	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			t.Fatalf("%s: %T at %s", path, cur, k)
		}

		cur = m[k]
	}

	return cur
}

// Everything on, every hook bound: Kratos's schema accepts the result and
// the hook lists keep session last.
func TestRenderValid(t *testing.T) {
	t.Parallel()

	s := defaults()
	s.Registration.ShowVerificationUI = true
	s.Login.RequireVerifiedAddress, s.Login.RevokeOtherSessions = true, true
	s.Recovery.Enabled, s.Recovery.RevokeSessions = true, true
	s.Verification.Enabled = true
	s.Methods.TOTP = overlay.TOTP{Enabled: true, Issuer: "Shop"}
	s.Methods.LookupSecret.Enabled = true
	s.Methods.WebAuthn = overlay.WebAuthn{
		Enabled: true,
		RP:      overlay.RelyingParty{ID: "example.com", DisplayName: "Shop", Origins: []string{"https://example.com"}},
	}
	s.Methods.Passkey = overlay.Passkey{Enabled: true, RP: overlay.RelyingParty{ID: "example.com", DisplayName: "Shop"}}
	s.Methods.OIDC = overlay.OIDC{Enabled: true, Providers: []overlay.OIDCProvider{{
		ID: "google", Provider: "google", ClientID: "id",
		Scope: []string{
			"email",
		}, Mapper: "local claims = std.extVar('claims'); {identity: {traits: {email: claims.email}}}",
	}}}
	s.Session.EarliestPossibleExtend = time.Hour
	s.Session.CookieDomain = "example.com"
	s.Identity = overlay.Identity{Schemas: map[string]string{"person": `{"type":"object"}`}}
	s.OAuth2Provider = overlay.OAuth2Provider{URL: "http://hydra:4445"}
	s.DefaultReturnURL, s.ErrorUIURL = "https://example.com/", "https://example.com/error"
	s.AllowedReturnURLs = []string{"https://example.com"}

	sec := overlay.Secrets{
		OIDC:                  map[string]string{"google": "secret"},
		OAuth2ProviderHeaders: map[string]string{"Authorization": "Bearer x"},
	}

	doc, err := overlay.Render(s, sec, overlay.Wiring{URL: "http://127.0.0.1:8090", Key: "k", Bound: all, Events: true})
	if err != nil {
		t.Fatal(err)
	}

	if err := overlay.Validate(doc); err != nil {
		t.Fatal(err)
	}

	hooks := at(t, doc, "selfservice.flows.registration.after.password.hooks").([]any)
	if len(hooks) != 4 || hooks[2].(map[string]any)["hook"] != "session" {
		t.Fatalf("registration hooks: %v", hooks)
	}

	if at(t, doc, "courier.delivery_strategy") != "http" || at(t, doc, "identity.default_schema_id") != "person" {
		t.Fatal("courier or identity not rendered")
	}

	if _, err := overlay.Encode(doc); err != nil {
		t.Fatal(err)
	}
}

// Nothing bound, no events: empty hook lists (the overlay owns them) and
// the base file's courier stays.
func TestRenderUnbound(t *testing.T) {
	t.Parallel()

	doc, err := overlay.Render(defaults(), overlay.Secrets{}, overlay.Wiring{URL: "http://x", Key: "k"})
	if err != nil {
		t.Fatal(err)
	}

	if err := overlay.Validate(doc); err != nil {
		t.Fatal(err)
	}

	if hooks := at(t, doc, "selfservice.flows.login.before.hooks").([]any); len(hooks) != 0 {
		t.Fatalf("before hooks: %v", hooks)
	}

	if _, ok := doc["courier"]; ok {
		t.Fatal("courier rendered without Deliver bound")
	}
}

func TestRenderErrors(t *testing.T) {
	t.Parallel()

	s := defaults()
	s.Overrides = "selfservice:\n  flows:\n    registration:\n      enabled: false\n"

	if _, err := overlay.Render(s, overlay.Secrets{}, overlay.Wiring{}); !errors.Is(err, overlay.ErrConflict) {
		t.Fatalf("override of an owned key: %v", err)
	}

	s.Overrides = "hashers:\n  algorithm: bcrypt\n"

	doc, err := overlay.Render(s, overlay.Secrets{}, overlay.Wiring{})
	if err != nil || at(t, doc, "hashers.algorithm") != "bcrypt" {
		t.Fatalf("override merged: %v", err)
	}

	s = defaults()
	s.Identity = overlay.Identity{Schemas: map[string]string{"a": "{}", "b": "{}"}}

	if _, err := overlay.Render(s, overlay.Secrets{}, overlay.Wiring{}); !errors.Is(err, overlay.ErrSchema) {
		t.Fatalf("two schemas without a default: %v", err)
	}

	s = defaults()
	s.Recovery.Use = "sms"

	doc, err = overlay.Render(s, overlay.Secrets{}, overlay.Wiring{})
	if err != nil {
		t.Fatal(err)
	}

	if err := overlay.Validate(doc); !errors.Is(err, overlay.ErrInvalid) ||
		!strings.Contains(err.Error(), "recovery/use") {
		t.Fatalf("invalid recovery.use: %v", err)
	}
}

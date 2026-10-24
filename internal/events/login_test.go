package events_test

import (
	"slices"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

func offered(t *testing.T, h *backplanetest.Harness) *kratoseventsv1.LoginSection {
	t.Helper()

	var section kratoseventsv1.LoginSection
	if err := backplanetest.Offered(h, events.LoginSectionName).UnmarshalTo(&section); err != nil {
		t.Fatal(err)
	}

	return &section
}

// kratos.login follows the settings and holds no provider credentials.
func TestOfferLogin(t *testing.T) {
	t.Parallel()

	var s overlay.Settings

	s.Registration.Enabled = true
	s.Methods.Password.Enabled = true
	s.Methods.Code = overlay.Code{Enabled: true, MFA: true}
	s.Methods.TOTP.Enabled = true
	s.Methods.OIDC = overlay.OIDC{Enabled: true, Providers: []overlay.OIDCProvider{
		{ID: "google", Provider: "google", Label: "Google", ClientID: "client-secretish", Mapper: "local x = 1; x"},
	}}

	cfg := struct {
		Settings config.Live[overlay.Settings] `json:"settings"`
	}{Settings: config.LiveOf(s)}

	h := backplanetest.New(t, backplanetest.Name("kratos"))
	events.OfferLogin(h.Root(), cfg.Settings)

	got := offered(t, h)
	if !got.GetRegistrationEnabled() || !slices.Equal(got.GetFirstFactors(), []string{"password", "oidc"}) ||
		!slices.Equal(got.GetSecondFactors(), []string{"totp", "code"}) || len(got.GetOidcProviders()) != 1 ||
		got.GetOidcProviders()[0].GetLabel() != "Google" {
		t.Fatalf("section %v", got)
	}

	s.Registration.Enabled = false
	s.Methods.Code.Passwordless = true
	backplanetest.SetLive(&cfg.Settings, s)

	got = offered(t, h)
	if got.GetRegistrationEnabled() || !slices.Equal(got.GetFirstFactors(), []string{"password", "code", "oidc"}) {
		t.Fatalf("after change %v", got)
	}
}

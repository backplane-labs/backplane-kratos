package events_test

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
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
	events.NewLogin(h.Root(), cfg.Settings, &kratosSchemas{}, time.Hour)

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

// kratosSchemas is Kratos's /schemas: its list, swapped by set.
type kratosSchemas struct {
	mu   sync.Mutex
	list []ory.Schema
	err  error
}

func (k *kratosSchemas) ListSchemas(context.Context) ([]ory.Schema, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.list, k.err
}

func (k *kratosSchemas) set(list []ory.Schema, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.list, k.err = list, err
}

// phones are the tel identifiers of the offered section.
func phones(t *testing.T, h *backplanetest.Harness) int {
	t.Helper()

	n := 0

	for _, id := range offered(t, h).GetIdentifiers() {
		if id.GetKind() == "tel" {
			n++
		}
	}

	return n
}

// Identifiers come from the settings' schemas; without them, from
// Kratos's, read every poll; a failed read keeps the last ones.
func TestLoginIdentifiers(t *testing.T) {
	t.Parallel()

	var s overlay.Settings

	s.Methods.Code = overlay.Code{Enabled: true, Passwordless: true}

	cfg := struct {
		Settings config.Live[overlay.Settings] `json:"settings"`
	}{Settings: config.LiveOf(s)}

	kratos := &kratosSchemas{list: []ory.Schema{{ID: "default", Schema: schema(phoneTrait)}}}

	h := backplanetest.New(t, backplanetest.Name("kratos"))
	events.NewLogin(h.Root(), cfg.Settings, kratos, 10*time.Millisecond)
	h.Start()

	await := func(want int) {
		t.Helper()

		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if phones(t, h) == want {
				return
			}
		}

		t.Fatalf("tel identifiers: %d, want %d", phones(t, h), want)
	}

	await(1)

	kratos.set(nil, errors.New("kratos down"))
	time.Sleep(50 * time.Millisecond)
	await(1)

	// The settings' schemas win, at once.
	s.Identity.Schemas = map[string]string{"default": string(schema(emailTrait))}
	backplanetest.SetLive(&cfg.Settings, s)

	if got := offered(t, h).GetIdentifiers(); len(got) != 1 || got[0].GetKind() != "email" {
		t.Fatalf("from the settings: %v", got)
	}
}

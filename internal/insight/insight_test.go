package insight_test

import (
	"slices"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/insight"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// healthy: every flow has its UI, codes go through Deliver.
func healthy() overlay.Settings {
	return overlay.Settings{
		Registration: overlay.Registration{Enabled: true, UIURL: "https://app/registration"},
		Login:        overlay.Login{UIURL: "https://app/login"},
		Settings:     overlay.SettingsFlow{UIURL: "https://app/settings"},
		Recovery:     overlay.Recovery{Enabled: true, UIURL: "https://app/recovery", Use: "code"},
		Verification: overlay.Verification{Enabled: true, UIURL: "https://app/verification", Use: "code"},
		Methods:      overlay.Methods{Password: overlay.Password{Enabled: true}, Code: overlay.Code{Enabled: true}},
		Features:     overlay.Features{ContinueWith: true},
	}
}

func bound(hooks ...string) func(string) bool {
	return func(h string) bool { return slices.Contains(hooks, h) }
}

func fields(fs []insight.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Level+":"+f.Flow+":"+f.Field)
	}

	return out
}

func TestHealthy(t *testing.T) {
	t.Parallel()

	if got := insight.Check(insight.State{Settings: healthy(), Bound: bound("Deliver")}); len(got) != 0 {
		t.Fatalf("findings of healthy settings: %v", fields(got))
	}
}

func TestFindings(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		edit  func(*overlay.Settings)
		hooks []string
		want  string
	}{
		{"nobody signs in", func(s *overlay.Settings) { s.Methods.Password.Enabled = false }, []string{"Deliver"}, "error::methods"},
		{"sms without Deliver", func(s *overlay.Settings) {
			s.Identity.Schemas = map[string]string{"p": `{"ory.sh/kratos": {"verification": {"via": "sms"}}}`}
		}, nil, "error::"},
		{"no recovery UI", func(s *overlay.Settings) { s.Recovery.UIURL = "" }, []string{"Deliver"}, "warning:recovery:recovery.ui_url"},
		{"links without the method", func(s *overlay.Settings) { s.Verification.Use = "link" }, []string{"Deliver"}, "error:verification:methods.link.enabled"},
		{"verified login without verification", func(s *overlay.Settings) {
			s.Login.RequireVerifiedAddress, s.Verification.Enabled = true, false
		}, []string{"Deliver"}, "error:login:verification.enabled"},
		{"native recovery", func(s *overlay.Settings) { s.Features.ContinueWith = false }, []string{"Deliver"}, "info:recovery:features.continue_with"},
		{"hooks of an off flow", func(s *overlay.Settings) { s.Registration.Enabled = false }, []string{"Deliver", "AfterRegistration"}, "info:registration:"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			s := healthy()
			tc.edit(&s)

			got := fields(insight.Check(insight.State{Settings: s, Bound: bound(tc.hooks...)}))
			if !slices.Contains(got, tc.want) {
				t.Fatalf("want %s in %v", tc.want, got)
			}
		})
	}
}

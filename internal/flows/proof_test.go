package flows_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
)

func newProver(t *testing.T, key string) *flows.Flows {
	t.Helper()

	h := backplanetest.New(t, backplanetest.Name("kratos"))

	return flows.New(h.Root(), key, config.LiveOf([]string(nil)), nil)
}

// A proof opens only for its purpose, under its key, intact and in time.
func TestProof(t *testing.T) {
	t.Parallel()

	f, other := newProver(t, "k-1"), newProver(t, "k-2")
	live := flows.Proof{Kind: "login", Flow: "f-1", To: "https://idp.example/a?state=s", Exp: time.Now().Add(time.Hour).Unix()}
	sealed := f.Seal(flows.PurposeHop, live)

	payload, sum, _ := strings.Cut(sealed, ".")

	tests := []struct {
		name    string
		f       *flows.Flows
		purpose string
		sealed  string
		ok      bool
	}{
		{name: "intact", f: f, purpose: flows.PurposeHop, sealed: sealed, ok: true},
		{name: "another purpose", f: f, purpose: flows.PurposeHeader, sealed: sealed},
		{name: "another key", f: other, purpose: flows.PurposeHop, sealed: sealed},
		{name: "tampered payload", f: f, purpose: flows.PurposeHop, sealed: "x" + payload + "." + sum},
		{name: "tampered mac", f: f, purpose: flows.PurposeHop, sealed: payload + "." + sum + "x"},
		{name: "no mac", f: f, purpose: flows.PurposeHop, sealed: payload},
		{name: "empty", f: f, purpose: flows.PurposeHop, sealed: ""},
		{
			name: "expired", f: f, purpose: flows.PurposeHop,
			sealed: f.Seal(flows.PurposeHop, flows.Proof{Kind: "login", Flow: "f-1", Exp: time.Now().Add(-time.Second).Unix()}),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := tc.f.Open(tc.purpose, tc.sealed)
			if ok != tc.ok || (ok && got != live) {
				t.Fatalf("open = %+v, %v; want ok %v", got, ok, tc.ok)
			}
		})
	}
}

// An expired or foreign hop link is refused: 400, no redirect, no cookie.
func TestHopRefuses(t *testing.T) {
	t.Parallel()

	f := newProver(t, "k-1")
	hop := f.Hop()
	to := "https://idp.example/authorize?state=s&redirect_uri=" + url.QueryEscape("https://id.example/self-service/methods/oidc/callback/m")

	tests := map[string]string{
		"expired": f.Seal(flows.PurposeHop, flows.Proof{Kind: "login", Flow: "f-1", To: to, Exp: time.Now().Add(-time.Second).Unix()}),
		"foreign": newProver(t, "k-2").Seal(flows.PurposeHop, flows.Proof{Kind: "login", Flow: "f-1", To: to, Exp: time.Now().Add(time.Hour).Unix()}),
		"cookie":  f.Seal(flows.PurposeCookie("s"), flows.Proof{Kind: "login", Flow: "f-1", To: to, Exp: time.Now().Add(time.Hour).Unix()}),
		"no state": f.Seal(flows.PurposeHop, flows.Proof{
			Kind: "login", Flow: "f-1", To: "https://idp.example/authorize", Exp: time.Now().Add(time.Hour).Unix(),
		}),
	}

	for name, sealed := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			w := httptest.NewRecorder()
			hop.ServeHTTP(w, httptest.NewRequestWithContext(t.Context(), http.MethodGet,
				flows.OIDCStartPath+"?t="+url.QueryEscape(sealed), nil))

			if w.Code != http.StatusBadRequest || w.Header().Get("Location") != "" || len(w.Header().Values("Set-Cookie")) > 0 {
				t.Fatalf("hop: %d %v", w.Code, w.Header())
			}
		})
	}
}

func BenchmarkProof(b *testing.B) {
	h := backplanetest.New(b, backplanetest.Name("kratos"))
	f := flows.New(h.Root(), "k-1", config.LiveOf([]string(nil)), nil)
	p := flows.Proof{Kind: "login", Flow: "0b4c1d7e-0b4c-4d7e-9b4c-1d7e0b4c1d7e", Exp: time.Now().Add(time.Hour).Unix()}

	for b.Loop() {
		_, _ = f.Open(flows.PurposeHeader, f.Seal(flows.PurposeHeader, p))
	}
}

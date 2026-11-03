package flows_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

// upstream plays Kratos's public API: it answers status and records what
// reached it.
type upstream struct {
	mu   sync.Mutex
	got  []string // method path?query body, header X-Auth
	srv  *httptest.Server
	code int
}

func newUpstream(t *testing.T, code int) *upstream {
	t.Helper()

	u := &upstream{code: code}
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		u.mu.Lock()
		u.got = append(u.got, r.Method+" "+r.URL.RequestURI()+" "+string(body)+" "+r.Header.Get("X-Auth"))
		u.mu.Unlock()

		w.WriteHeader(u.code)
	}))
	t.Cleanup(u.srv.Close)

	return u
}

// A logout goes to Kratos unchanged; once Kratos ended the session,
// LoggedOut carries the identity and the session.
func TestLogout(t *testing.T) {
	t.Parallel()

	signedIn := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	who := &ory.Session{
		ID: "s-1", Active: true, AuthenticatedAt: &signedIn, AuthenticatorAssuranceLevel: "aal1",
		Devices:  []ory.Device{{IPAddress: "203.0.113.9", UserAgent: "browser"}},
		Identity: &ory.Identity{ID: "i-1", SchemaID: "default", Traits: []byte(`{"email":"a@example.com"}`)},
	}

	for _, tc := range []struct {
		name      string
		method    string
		path      string
		body      string
		cookie    string
		who       *ory.Session
		after     ory.Session
		code      int
		seen      []string
		published bool
	}{
		{
			name: "api", method: http.MethodDelete, path: "/self-service/logout/api",
			body: `{"session_token":"tok"}`, who: who, code: http.StatusNoContent,
			seen: []string{"tok"}, published: true,
		},
		{
			name: "browser", method: http.MethodGet, path: "/self-service/logout?token=lt", cookie: "ory_kratos_session=c",
			who: who, code: http.StatusSeeOther, seen: []string{"ory_kratos_session=c"}, published: true,
		},
		{
			name: "refused", method: http.MethodGet, path: "/self-service/logout?token=bad", cookie: "ory_kratos_session=c",
			who: who, after: ory.Session{Active: true}, code: http.StatusSeeOther, seen: []string{"ory_kratos_session=c"},
		},
		{
			name: "no session", method: http.MethodDelete, path: "/self-service/logout/api",
			body: `{"session_token":"gone"}`, code: http.StatusUnauthorized, seen: []string{"gone"},
		},
		{
			name: "logout url", method: http.MethodGet, path: "/self-service/logout/browser", cookie: "ory_kratos_session=c",
			who: who, code: http.StatusOK,
		},
		{
			name: "bad body", method: http.MethodDelete, path: "/self-service/logout/api", body: `{`,
			who: who, code: http.StatusBadRequest,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kratos := &sessions{who: tc.who, after: tc.after}
			h, f, _ := harnessWith(t, kratos)
			kratosPublic := newUpstream(t, tc.code)

			public, err := url.Parse(kratosPublic.srv.URL)
			if err != nil {
				t.Fatal(err)
			}

			proxy := httptest.NewServer(f.Logout(public, map[string]string{"X-Auth": "edge"}))
			t.Cleanup(proxy.Close)

			req, err := http.NewRequestWithContext(t.Context(), tc.method, proxy.URL+tc.path, strings.NewReader(tc.body))
			if err != nil {
				t.Fatal(err)
			}

			if tc.cookie != "" {
				req.Header.Set("Cookie", tc.cookie)
			}

			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

			res, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			_ = res.Body.Close()

			kratosPublic.mu.Lock()
			proxied := kratosPublic.got
			kratosPublic.mu.Unlock()

			want := tc.method + " " + tc.path + " " + tc.body + " edge"
			if res.StatusCode != tc.code || len(proxied) != 1 || proxied[0] != want {
				t.Fatalf("proxied: %d %q, want %d %q", res.StatusCode, proxied, tc.code, want)
			}

			kratos.mu.Lock()
			seen := strings.Join(kratos.seen, ",")
			kratos.mu.Unlock()

			if seen != strings.Join(tc.seen, ",") {
				t.Fatalf("whoami asked %q, want %q", seen, tc.seen)
			}

			got := backplanetest.Events(h, f.LoggedOut())
			if !tc.published {
				if len(got) != 0 {
					t.Fatalf("published %+v", got)
				}

				return
			}

			if len(got) != 1 {
				t.Fatalf("events %+v", got)
			}

			ev := got[0]
			if ev.GetIdentityId() != "i-1" || ev.GetSchemaId() != "default" || ev.GetMethod() != "logout" ||
				ev.GetTraits().GetFields()["email"].GetStringValue() != "a@example.com" ||
				ev.GetSession().GetId() != "s-1" || !ev.GetSession().GetAuthenticatedAt().AsTime().Equal(signedIn) ||
				ev.GetSession().GetAal() != "aal1" || ev.GetSession().GetIpAddress() != "203.0.113.9" {
				t.Fatalf("event %+v", ev)
			}
		})
	}
}

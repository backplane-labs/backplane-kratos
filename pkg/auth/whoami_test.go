package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"

	"github.com/backplane-labs/backplane-kratos/pkg/auth"
)

const whoamiBody = `{
  "id": "s-1", "active": true, "expires_at": "2030-01-01T00:00:00Z", "authenticated_at": "2026-10-16T10:00:00Z",
  "authenticator_assurance_level": "aal1",
  "authentication_methods": [{"method": "password", "aal": "aal1", "completed_at": "2026-10-16T10:00:00Z"}],
  "identity": {"id": "id-1", "schema_id": "default", "state": "active",
    "traits": {"email": "ada@example.com"}, "metadata_public": {"roles": ["operator"]}},
  "devices": [{"id": "d-1", "ip_address": "10.0.0.1", "user_agent": "test"}],
  "tokenized": "x.y.z"
}`

// kratos answers whoami for the cookie ory_kratos_session=good or the token
// ory_st_good; calls counts the calls.
func kratos(t *testing.T, calls *atomic.Int32, revoked *atomic.Bool) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)

		good := r.Header.Get("X-Session-Token") == "ory_st_good" || r.Header.Get("Cookie") == "a=1; ory_kratos_session=good"

		switch {
		case r.Header.Get("X-Session-Token") == "ory_st_aal1":
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"id":"session_aal2_required","reason":"second factor"}}`))
		case !good || revoked.Load():
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":401,"reason":"No valid session credentials found in the request."}}`))
		default:
			_, _ = w.Write([]byte(whoamiBody))
		}
	}))
	t.Cleanup(srv.Close)

	return srv.URL
}

func TestSessionsAskEveryTime(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	var revoked atomic.Bool

	s, err := auth.NewSessions(kratos(t, &calls, &revoked), nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()

	a, err := s.Verify(ctx, auth.Credential{Cookie: "a=1; ory_kratos_session=good"})
	if err != nil {
		t.Fatal(err)
	}

	if a.IdentityID != "id-1" || a.Email != "ada@example.com" || !a.HasRole("operator") || a.Source != auth.FromSession ||
		a.Session == nil || len(a.Session.Devices) != 1 {
		t.Fatalf("auth = %+v", a)
	}

	// No cache: the revocation shows on the very next call.
	revoked.Store(true)

	if _, err := s.Verify(ctx, auth.Credential{Cookie: "a=1; ory_kratos_session=good"}); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}

	if n := calls.Load(); n != 2 {
		t.Fatalf("calls = %d, want 2", n)
	}

	if _, err := s.Verify(ctx, auth.Credential{Token: "ory_st_aal1"}); !errors.Is(err, auth.ErrSecondFactor) {
		t.Fatalf("err = %v, want ErrSecondFactor", err)
	}

	if _, err := s.Verify(ctx, auth.Credential{}); !errors.Is(err, auth.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
}

func TestSessionsTokenize(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32

	var revoked atomic.Bool

	s, _ := auth.NewSessions(kratos(t, &calls, &revoked), nil)

	token, err := s.Tokenize(context.Background(), auth.Credential{Token: "ory_st_good"}, "backplane")
	if err != nil || token != "x.y.z" {
		t.Fatalf("token %q, err %v", token, err)
	}
}

func TestMiddleware(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")

	now := time.Now()
	tokens := verifier(t, issuer, &now)
	jwt := issuer.sign("k1", session(now, nil))

	who := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, ok := auth.FromContext(r.Context())
		if !ok {
			_, _ = w.Write([]byte("anonymous"))

			return
		}

		_, _ = w.Write([]byte(got.Source + ":" + got.IdentityID))
	})

	cases := []struct {
		name     string
		optional bool
		header   map[string]string
		code     int
		body     string
		whoamied bool
	}{
		{"token", false, map[string]string{"Authorization": "Bearer " + jwt}, 200, "token:id-1", false},
		{"session token", false, map[string]string{"Authorization": "Bearer ory_st_good"}, 200, "session:id-1", true},
		{"cookie", false, map[string]string{"Cookie": "a=1; ory_kratos_session=good"}, 200, "session:id-1", true},
		{"other cookies only", false, map[string]string{"Cookie": "a=1"}, 401, "", false},
		{"anonymous required", false, nil, 401, "", false},
		{"anonymous optional", true, nil, 200, "anonymous", false},
		{"bad token optional", true, map[string]string{"Authorization": "Bearer a.b.c"}, 401, "", false},
		{"second factor", false, map[string]string{"X-Session-Token": "ory_st_aal1"}, 403, "", true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()

			var calls atomic.Int32

			var revoked atomic.Bool

			sessions, _ := auth.NewSessions(kratos(t, &calls, &revoked), nil)
			a := auth.Authenticator{Tokens: tokens, Sessions: sessions}

			h := a.Required(who)
			if c.optional {
				h = a.Optional(who)
			}

			req := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			for k, v := range c.header {
				req.Header.Set(k, v)
			}

			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != c.code || (c.body != "" && rec.Body.String() != c.body) {
				t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), c.code, c.body)
			}

			if asked := calls.Load() > 0; asked != c.whoamied {
				t.Fatalf("whoami called %v, want %v", asked, c.whoamied)
			}
		})
	}
}

func TestCodes(t *testing.T) {
	t.Parallel()

	if auth.GRPCCode(auth.ErrUnavailable) != codes.Unavailable || auth.GRPCCode(auth.ErrExpired) != codes.Unauthenticated ||
		auth.HTTPStatus(auth.ErrSecondFactor) != http.StatusForbidden {
		t.Fatal("codes")
	}
}

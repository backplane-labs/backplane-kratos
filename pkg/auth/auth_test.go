package auth_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/backplane-labs/backplane-kratos/pkg/auth"
)

// keyIssuer serves a JWK set and signs tokens; fetches counts the set's fetches.
type keyIssuer struct {
	t       *testing.T
	mu      sync.Mutex
	keys    map[string]*ecdsa.PrivateKey
	order   []string
	down    atomic.Bool
	fetches atomic.Int32
	srv     *httptest.Server
}

func newIssuer(t *testing.T) *keyIssuer {
	t.Helper()

	issuer := &keyIssuer{t: t, keys: map[string]*ecdsa.PrivateKey{}}
	issuer.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		issuer.fetches.Add(1)

		if issuer.down.Load() {
			http.Error(w, "down", http.StatusBadGateway)

			return
		}

		issuer.mu.Lock()
		defer issuer.mu.Unlock()

		var set jose.JSONWebKeySet
		for _, kid := range issuer.order {
			set.Keys = append(set.Keys, jose.JSONWebKey{Key: &issuer.keys[kid].PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
		}

		_ = json.NewEncoder(w).Encode(set)
	}))
	t.Cleanup(issuer.srv.Close)

	return issuer
}

func (issuer *keyIssuer) add(kid string) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		issuer.t.Fatal(err)
	}

	issuer.mu.Lock()
	issuer.keys[kid] = key
	issuer.order = append([]string{kid}, issuer.order...)
	issuer.mu.Unlock()
}

func (issuer *keyIssuer) sign(kid string, claims map[string]any) string {
	issuer.t.Helper()

	issuer.mu.Lock()
	key := issuer.keys[kid]
	issuer.mu.Unlock()

	if key == nil {
		// A key the keyIssuer never published.
		var err error
		if key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			issuer.t.Fatal(err)
		}
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", kid))
	if err != nil {
		issuer.t.Fatal(err)
	}

	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		issuer.t.Fatal(err)
	}

	return token
}

func session(now time.Time, extra map[string]any) map[string]any {
	c := map[string]any{
		"iss": "https://auth.example", "sub": "id-1", "sid": "s-1",
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix(),
		"aal": "aal2", "amr": []string{"password", "totp"}, "authenticated_at": now.Add(-time.Minute).Format(time.RFC3339),
		"email": "ada@example.com", "schema_id": "default", "metadata": map[string]any{"roles": []string{"operator"}},
	}
	for k, v := range extra {
		c[k] = v
	}

	return c
}

func verifier(t *testing.T, issuer *keyIssuer, now *time.Time) *auth.Tokens {
	t.Helper()

	v, err := auth.NewTokens(auth.TokensOptions{
		KeysURL: issuer.srv.URL, Issuer: "https://auth.example", Now: func() time.Time { return *now },
		KeysMinRefresh: time.Minute, KeysMaxAge: 10 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}

	return v
}

func TestTokenVerifies(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")

	now := time.Now()
	v := verifier(t, issuer, &now)

	a, err := v.Verify(context.Background(), issuer.sign("k1", session(now, nil)))
	if err != nil {
		t.Fatal(err)
	}

	if a.IdentityID != "id-1" || a.SessionID != "s-1" || a.Email != "ada@example.com" || a.Source != auth.FromToken {
		t.Fatalf("auth = %+v", a)
	}

	if !a.HasRole("operator") || !a.AtLeast(auth.AAL2) || a.AtLeast(auth.AAL3) || !a.UsedMethod("totp") {
		t.Fatalf("roles %v, aal %s, methods %v", a.Roles(), a.AAL, a.Methods)
	}

	if !a.AuthenticatedWithin(2*time.Minute, now) || a.AuthenticatedWithin(30*time.Second, now) {
		t.Fatalf("authenticated at %v", a.AuthenticatedAt)
	}

	// A thousand verifications later, still the one fetch.
	for range 1000 {
		if _, err := v.Verify(context.Background(), issuer.sign("k1", session(now, nil))); err != nil {
			t.Fatal(err)
		}
	}

	if n := issuer.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestTokenRefusals(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")

	now := time.Now()
	v := verifier(t, issuer, &now)

	cases := map[string]struct {
		token string
		want  error
	}{
		"expired":     {issuer.sign("k1", session(now, map[string]any{"exp": now.Add(-time.Minute).Unix()})), auth.ErrExpired},
		"not yet":     {issuer.sign("k1", session(now, map[string]any{"nbf": now.Add(time.Minute).Unix()})), auth.ErrExpired},
		"keyIssuer":   {issuer.sign("k1", session(now, map[string]any{"iss": "https://evil.example"})), auth.ErrInvalid},
		"no subject":  {issuer.sign("k1", session(now, map[string]any{"sub": ""})), auth.ErrInvalid},
		"garbage":     {"a.b.c", auth.ErrInvalid},
		"foreign key": {issuer.sign("k1", nil), auth.ErrInvalid},
	}

	// A token signed by another key under a published kid.
	forged := newIssuer(t)
	forged.add("k1")
	cases["foreign key"] = struct {
		token string
		want  error
	}{forged.sign("k1", session(now, nil)), auth.ErrInvalid}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := v.Verify(context.Background(), c.token); !errors.Is(err, c.want) {
				t.Fatalf("err = %v, want %v", err, c.want)
			}
		})
	}
}

func TestKeyRotationFetchesOnce(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")

	now := time.Now()
	v := verifier(t, issuer, &now)

	if _, err := v.Verify(context.Background(), issuer.sign("k1", session(now, nil))); err != nil {
		t.Fatal(err)
	}

	// The issuer rotates: a token of the new key fetches the set once, the
	// old key's tokens keep verifying.
	issuer.add("k2")

	now = now.Add(2 * time.Minute)

	for range 100 {
		if _, err := v.Verify(context.Background(), issuer.sign("k2", session(now, nil))); err != nil {
			t.Fatal(err)
		}

		if _, err := v.Verify(context.Background(), issuer.sign("k1", session(now, nil))); err != nil {
			t.Fatal(err)
		}
	}

	if n := issuer.fetches.Load(); n != 2 {
		t.Fatalf("fetches = %d, want 2", n)
	}
}

func TestUnknownKidsDoNotDriveTheIssuer(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")

	now := time.Now()
	v := verifier(t, issuer, &now)

	if _, err := v.Verify(context.Background(), issuer.sign("k1", session(now, nil))); err != nil {
		t.Fatal(err)
	}

	// Made-up kids within KeysMinRefresh: no fetch at all.
	for range 100 {
		if _, err := v.Verify(context.Background(), issuer.sign("made-up", session(now, nil))); !errors.Is(err, auth.ErrUnknownKey) {
			t.Fatalf("err = %v, want ErrUnknownKey", err)
		}
	}

	if n := issuer.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestConcurrentFirstUseFetchesOnce(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")

	now := time.Now()
	v := verifier(t, issuer, &now)
	token := issuer.sign("k1", session(now, nil))

	var group sync.WaitGroup
	for range 50 {
		group.Go(func() {
			if _, err := v.Verify(context.Background(), token); err != nil {
				t.Error(err)
			}
		})
	}

	group.Wait()

	if n := issuer.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}
}

func TestKeysDown(t *testing.T) {
	t.Parallel()

	issuer := newIssuer(t)
	issuer.add("k1")
	issuer.down.Store(true)

	now := time.Now()
	v := verifier(t, issuer, &now)
	token := issuer.sign("k1", session(now, nil))

	// Never fetched: unavailable, and asked again only after KeysMinRefresh.
	for range 10 {
		if _, err := v.Verify(context.Background(), token); !errors.Is(err, auth.ErrUnavailable) {
			t.Fatalf("err = %v, want ErrUnavailable", err)
		}
	}

	if n := issuer.fetches.Load(); n != 1 {
		t.Fatalf("fetches = %d, want 1", n)
	}

	issuer.down.Store(false)

	now = now.Add(2 * time.Minute)
	token = issuer.sign("k1", session(now, nil))

	if _, err := v.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}

	// Down again, keys old: the known set keeps verifying.
	issuer.down.Store(true)

	now = now.Add(time.Hour)

	if _, err := v.Verify(context.Background(), issuer.sign("k1", session(now, nil))); err != nil {
		t.Fatalf("a known key failed while the keyIssuer issuer down: %v", err)
	}
}

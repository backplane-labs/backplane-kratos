package it_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/go-jose/go-jose/v4"

	"github.com/backplane-labs/backplane-kratos/internal/jwks"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	"github.com/backplane-labs/backplane-kratos/pkg/auth"
)

// signingKey is a fresh ES256 key as token_key and its public half as
// settings.tokens.keys hold them.
func signingKey(t *testing.T, kid string) (string, string) {
	t.Helper()

	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	priv, err := json.Marshal(jose.JSONWebKey{Key: k, KeyID: kid, Algorithm: "ES256", Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}

	pub, err := json.Marshal(jose.JSONWebKey{Key: &k.PublicKey, KeyID: kid, Algorithm: "ES256", Use: "sig"})
	if err != nil {
		t.Fatal(err)
	}

	return string(priv), string(pub)
}

// TestSessionTokens: Kratos signs a session's token with token_key and the
// default claims; pkg/auth verifies it with the keys backplane-kratos
// serves, and asks Kratos for the session without a cache.
func TestSessionTokens(t *testing.T) {
	t.Parallel()

	priv, pub := signingKey(t, "it-key-1")

	e := startKeyed(t, priv, func(s *overlay.Settings) {
		s.Tokens = overlay.Tokens{TTL: 2 * time.Minute, Keys: []string{pub}}
	}, nil)

	ctx := t.Context()
	email := unique("tokens")
	id := e.newUser(t, email)
	setMetadata(t, id, `{"roles":["operator"]}`)

	// Sign in as a native app: a session token.
	_, flow := call(t, http.MethodGet, "/self-service/login/api", nil)

	status, body := call(t, http.MethodPost, fmt.Sprintf("/self-service/login?flow=%v", flow["id"]),
		map[string]any{"method": "password", "identifier": email, "password": password})
	if status != http.StatusOK {
		t.Fatalf("login: %d %v", status, body)
	}

	sessionToken, _ := body["session_token"].(string)
	sessionID := fmt.Sprint(body["session"].(map[string]any)["id"])

	sessions, err := auth.NewSessions(publicURL, nil)
	if err != nil {
		t.Fatal(err)
	}

	token, err := sessions.Tokenize(ctx, auth.Credential{Token: sessionToken}, overlay.TokenTemplate)
	if err != nil {
		t.Fatalf("tokenize: %v", err)
	}

	keys := httptest.NewServer(jwks.Handler(e.settings))
	t.Cleanup(keys.Close)

	tokens, err := auth.NewTokens(auth.TokensOptions{KeysURL: keys.URL + jwks.Path, Issuer: publicURL + "/"})
	if err != nil {
		t.Fatal(err)
	}

	got, err := tokens.Verify(ctx, token)
	if err != nil {
		t.Fatalf("verify: %v (token %s)", err, token)
	}

	t.Logf("claims: %v", got.Claims)

	if got.IdentityID != id || got.SessionID != sessionID || got.Email != email || got.SchemaID != "default" {
		t.Fatalf("token auth: %+v", got)
	}

	if got.AAL != auth.AAL1 || !got.UsedMethod("password") || !got.HasRole("operator") {
		t.Fatalf("aal %s, methods %v, roles %v", got.AAL, got.Methods, got.Roles())
	}

	if got.AuthenticatedAt.IsZero() || time.Until(got.ExpiresAt) > 2*time.Minute+time.Second {
		t.Fatalf("authenticated at %v, expires at %v", got.AuthenticatedAt, got.ExpiresAt)
	}

	// The same session through whoami, the authenticator choosing by shape.
	a := auth.Authenticator{Tokens: tokens, Sessions: sessions}

	for _, header := range []string{"Bearer " + token, "Bearer " + sessionToken} {
		h := http.Header{"Authorization": {header}}
		if who, err := a.Authenticate(ctx, h); err != nil || who.IdentityID != id || !who.HasRole("operator") {
			t.Fatalf("%s: %+v %v", header[:20], who, err)
		}
	}

	// Revoked: whoami refuses at once, no new token is issued, the token
	// already issued lives out its TTL (the model's promise).
	revoke(t, sessionID)

	if _, err := sessions.Verify(ctx, auth.Credential{Token: sessionToken}); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("whoami after revoke: %v", err)
	}

	if _, err := sessions.Tokenize(ctx, auth.Credential{Token: sessionToken}, overlay.TokenTemplate); !errors.Is(err, auth.ErrUnauthenticated) {
		t.Fatalf("tokenize after revoke: %v", err)
	}

	if _, err := tokens.Verify(ctx, token); err != nil {
		t.Fatalf("the issued token within its TTL: %v", err)
	}
}

// TestTokenKeyRotation: a new signing key goes first, the old one stays in
// tokens.keys; tokens of both verify.
func TestTokenKeyRotation(t *testing.T) {
	t.Parallel()

	oldPriv, oldPub := signingKey(t, "it-old")
	newPriv, newPub := signingKey(t, "it-new")

	e := startKeyed(t, oldPriv, func(s *overlay.Settings) {
		s.Tokens = overlay.Tokens{TTL: time.Minute, Keys: []string{oldPub}}
	}, nil)

	ctx := t.Context()
	email := unique("rotate")
	e.newUser(t, email)

	sessionToken := login(t, email)

	sessions, _ := auth.NewSessions(publicURL, nil)

	oldToken, err := sessions.Tokenize(ctx, auth.Credential{Token: sessionToken}, overlay.TokenTemplate)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate: the new key signs, the old public key stays (one revision
	// changes both, they reach the applier one after the other).
	s := e.settings.Get()
	s.Tokens.Keys = []string{newPub, oldPub}

	backplanetest.SetLive(&e.tokenKey, config.Secret(newPriv))
	backplanetest.SetLive(&e.settings, s)

	waitFor(t, "the overlay holds the new key", func() bool {
		raw, err := os.ReadFile(os.Getenv("KRATOS_IT_OVERLAY"))

		return err == nil && bytes.Contains(raw, []byte(base64.StdEncoding.EncodeToString([]byte(`{"keys":[`+newPriv+`]}`))))
	})
	time.Sleep(reload)

	newToken, err := sessions.Tokenize(ctx, auth.Credential{Token: sessionToken}, overlay.TokenTemplate)
	if err != nil {
		t.Fatal(err)
	}

	if kid(t, newToken) != "it-new" || kid(t, oldToken) != "it-old" {
		t.Fatalf("kids: old %s, new %s", kid(t, oldToken), kid(t, newToken))
	}

	keys := httptest.NewServer(jwks.Handler(e.settings))
	t.Cleanup(keys.Close)

	tokens, _ := auth.NewTokens(auth.TokensOptions{KeysURL: keys.URL + jwks.Path})

	for _, tok := range []string{oldToken, newToken} {
		if _, err := tokens.Verify(ctx, tok); err != nil {
			t.Fatalf("%s: %v", kid(t, tok), err)
		}
	}
}

func kid(t *testing.T, token string) string {
	t.Helper()

	sig, err := jose.ParseSigned(token, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		t.Fatal(err)
	}

	return sig.Signatures[0].Header.KeyID
}

func login(t *testing.T, email string) string {
	t.Helper()

	_, flow := call(t, http.MethodGet, "/self-service/login/api", nil)

	status, body := call(t, http.MethodPost, fmt.Sprintf("/self-service/login?flow=%v", flow["id"]),
		map[string]any{"method": "password", "identifier": email, "password": password})
	if status != http.StatusOK {
		t.Fatalf("login: %d %v", status, body)
	}

	token, _ := body["session_token"].(string)

	return token
}

// setMetadata sets an identity's public metadata through the admin API.
func setMetadata(t *testing.T, id, metadata string) {
	t.Helper()

	patch := fmt.Sprintf(`[{"op":"add","path":"/metadata_public","value":%s}]`, metadata)
	admin(t, http.MethodPatch, "/admin/identities/"+id, patch)
}

// revoke revokes a session through the admin API.
func revoke(t *testing.T, sessionID string) {
	t.Helper()

	admin(t, http.MethodDelete, "/admin/sessions/"+sessionID, "")
}

func admin(t *testing.T, method, path, body string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, adminURL+path, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		b, _ := io.ReadAll(res.Body)
		t.Fatalf("%s %s: %s %s", method, path, res.Status, b)
	}
}

package it_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/backplane-labs/backplane-kratos/internal/backchannel"
)

// TestBackchannelLogout: the IdP ends the person's login; Kratos's session
// ends with it, the identity stays active, and the person signs in again.
func TestBackchannelLogout(t *testing.T) {
	t.Parallel()

	e := startWith(t, nativeSettings, nil)
	forget(t, e)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "it"}}})
	}))
	t.Cleanup(jwks.Close)

	const issuer = "https://idp.it.test"

	if err := backplanetest.SetLive(&e.logoutProviders, []backchannel.Provider{
		{ID: "returning", Issuer: issuer, Audience: "kratos", JWKSURL: jwks.URL},
	}); err != nil {
		t.Fatal(err)
	}

	id := e.directory(t, "corp").create(unique("logout"))

	token, err := signIn(t, e)
	if err != nil {
		t.Fatal(err)
	}

	receiver := httptest.NewServer(e.backchannel.Handler())
	t.Cleanup(receiver.Close)

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithType("logout+jwt").WithHeader(jose.HeaderKey("kid"), "it"))
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()

	logout, err := jwt.Signed(signer).Claims(map[string]any{
		"iss": issuer, "aud": "kratos", "sub": subject, "jti": unique("jti"), "iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(), "events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, receiver.URL+backchannel.Path+"returning",
		strings.NewReader(url.Values{"logout_token": {logout}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := httpClient(t).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("logout: %d", res.StatusCode)
	}

	if status, _ := whoami(t, token); status != http.StatusUnauthorized {
		t.Fatalf("whoami after the IdP's logout: %d", status)
	}

	if got, err := e.kratos.GetIdentity(t.Context(), id); err != nil || got.State != "active" {
		t.Fatalf("a logout must not deactivate: %+v %v", got, err)
	}

	revoked := backplanetest.Events(e.h, e.activities.RevokedEvent())
	if len(revoked) != 1 || revoked[0].GetIdentityId() != id || revoked[0].GetBy() != backchannel.ByBackchannel {
		t.Fatalf("revoked %+v", revoked)
	}

	if _, err := signIn(t, e); err != nil {
		t.Fatalf("signing in again after a logout: %v", err)
	}
}

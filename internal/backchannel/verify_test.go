package backchannel_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/backplane-labs/backplane-kratos/internal/backchannel"
)

const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// idp signs logout tokens with an RSA key under kid "k1".
type idp struct {
	key *rsa.PrivateKey
	set jose.JSONWebKeySet
}

func newIdP(tb testing.TB) idp {
	tb.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		tb.Fatal(err)
	}

	return idp{key: key, set: jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &key.PublicKey, KeyID: "k1", Algorithm: string(jose.RS256), Use: "sig"},
	}}}
}

var provider = backchannel.Provider{
	ID: "corp", Issuer: "https://idp.test", Audience: "kratos", JWKSURL: "https://idp.test/jwks",
}

// claims of a valid token at now, with overrides (a nil value deletes).
func claims(now time.Time, over map[string]any) map[string]any {
	c := map[string]any{
		"iss": provider.Issuer, "aud": provider.Audience, "sub": "person-1", "jti": "jti-1",
		"iat": now.Unix(), "exp": now.Add(2 * time.Minute).Unix(),
		"events": map[string]any{logoutEvent: map[string]any{}},
	}

	maps.Copy(c, over)

	for k, v := range c {
		if v == nil {
			delete(c, k)
		}
	}

	return c
}

func (i idp) sign(tb testing.TB, kid string, c map[string]any) string {
	tb.Helper()

	opts := (&jose.SignerOptions{}).WithType("logout+jwt")
	if kid != "" {
		opts = opts.WithHeader(jose.HeaderKey("kid"), kid)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.key}, opts)
	if err != nil {
		tb.Fatal(err)
	}

	raw, err := jwt.Signed(signer).Claims(c).Serialize()
	if err != nil {
		tb.Fatal(err)
	}

	return raw
}

func TestVerify(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	issuer := newIdP(t)
	stranger := newIdP(t)

	tests := []struct {
		name  string
		token func() string
		want  error // nil: valid
	}{
		{name: "valid", token: func() string { return issuer.sign(t, "k1", claims(now, nil)) }},
		{name: "valid without kid", token: func() string { return issuer.sign(t, "", claims(now, nil)) }},
		{name: "audience in a list", token: func() string {
			return issuer.sign(t, "k1", claims(now, map[string]any{"aud": []string{"other", "kratos"}}))
		}},
		{
			name: "another key", token: func() string { return stranger.sign(t, "k1", claims(now, nil)) },
			want: backchannel.ErrUnknownKey,
		},
		{
			name: "unknown kid", token: func() string { return issuer.sign(t, "k9", claims(now, nil)) },
			want: backchannel.ErrUnknownKey,
		},
		{name: "wrong issuer", token: func() string {
			return issuer.sign(t, "k1", claims(now, map[string]any{"iss": "https://evil.test"}))
		}, want: backchannel.ErrToken},
		{name: "wrong audience", token: func() string {
			return issuer.sign(t, "k1", claims(now, map[string]any{"aud": "someone-else"}))
		}, want: backchannel.ErrToken},
		{name: "expired", token: func() string {
			return issuer.sign(t, "k1", claims(now, map[string]any{"exp": now.Add(-time.Hour).Unix()}))
		}, want: backchannel.ErrToken},
		{
			name: "no exp", token: func() string { return issuer.sign(t, "k1", claims(now, map[string]any{"exp": nil})) },
			want: backchannel.ErrToken,
		},
		{
			name: "no iat", token: func() string { return issuer.sign(t, "k1", claims(now, map[string]any{"iat": nil})) },
			want: backchannel.ErrToken,
		},
		{name: "no logout event", token: func() string {
			return issuer.sign(t, "k1", claims(now, map[string]any{"events": map[string]any{"x": map[string]any{}}}))
		}, want: backchannel.ErrToken},
		{
			name: "a nonce", token: func() string { return issuer.sign(t, "k1", claims(now, map[string]any{"nonce": "n"})) },
			want: backchannel.ErrToken,
		},
		{name: "sid only", token: func() string {
			return issuer.sign(t, "k1", claims(now, map[string]any{"sub": nil, "sid": "s"}))
		}, want: backchannel.ErrToken},
		{
			name: "no jti", token: func() string { return issuer.sign(t, "k1", claims(now, map[string]any{"jti": nil})) },
			want: backchannel.ErrToken,
		},
		{name: "alg none", token: func() string {
			return "eyJhbGciOiJub25lIn0.eyJzdWIiOiJwZXJzb24tMSJ9."
		}, want: backchannel.ErrToken},
		{name: "an ID token's HMAC", token: func() string {
			signer, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: []byte("0123456789abcdef0123456789abcdef")}, nil)
			raw, _ := jwt.Signed(signer).Claims(claims(now, nil)).Serialize()

			return raw
		}, want: backchannel.ErrToken},
		{name: "not a JWT", token: func() string { return "garbage" }, want: backchannel.ErrToken},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := backchannel.Verify(tc.token(), provider, issuer.set, now)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("Verify: %v, want %v", err, tc.want)
				}

				return
			}

			if err != nil || got.Subject != "person-1" || got.JTI != "jti-1" || !got.Expiry.Equal(now.Add(2*time.Minute)) {
				t.Fatalf("Verify = %+v, %v", got, err)
			}
		})
	}
}

func TestVerifyES256(t *testing.T) {
	t.Parallel()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_800_000_000, 0)

	raw, err := jwt.Signed(signer).Claims(claims(now, nil)).Serialize()
	if err != nil {
		t.Fatal(err)
	}

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey}}}
	if _, err := backchannel.Verify(raw, provider, set, now); err != nil {
		t.Fatal(err)
	}
}

func BenchmarkVerify(b *testing.B) {
	issuer := newIdP(b)
	now := time.Unix(1_800_000_000, 0)
	raw := issuer.sign(b, "k1", claims(now, nil))

	for b.Loop() {
		_, _ = backchannel.Verify(raw, provider, issuer.set, now)
	}
}

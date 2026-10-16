package overlay

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// TokenTemplate is the tokenizer template backplane-kratos configures:
// GET /sessions/whoami?tokenize_as=backplane returns the session and, in
// its "tokenized" field, a JWT of it.
const TokenTemplate = "backplane"

// DefaultTokenTTL is a token's life when the settings name none.
const DefaultTokenTTL = 5 * time.Minute

// DefaultClaims is the Jsonnet the tokens' claims come from when the
// settings name none.
//
//go:embed claims.jsonnet
var DefaultClaims string

// Tokens turn a session into a short JWT services verify with public keys,
// without calling Kratos.
type Tokens struct {
	// TTL of a token: a revoked session stops getting new tokens at once,
	// but one already issued stays valid this long.
	TTL time.Duration `json:"ttl,omitempty" schemapb:"default=5m;description=How long a token stays valid (also how long a revoked session keeps working)"`
	// Claims is the Jsonnet mapping the session to the token's claims
	// (std.extVar('session')); empty: DefaultClaims.
	Claims string `json:"claims,omitempty" schemapb:"description=Jsonnet from the session to the token's claims (empty: the default)"`
	// Keys are the public signing keys (JWK JSON) services verify with. The
	// first is the key token_key holds and signs with now, the others the
	// keys before it, kept until the tokens they signed expire.
	Keys []string `json:"keys,omitempty" schemapb:"description=Public JWKs: the current signing key first, earlier ones after it"`
}

// Errors of the tokens.
var (
	// ErrTokenKey: token_key is not a private JWK or not the first public key.
	ErrTokenKey = errors.New("token_key")
	// ErrPublicKey: a public key is not a public JWK with a kid.
	ErrPublicKey = errors.New("tokens.keys")
)

// jwk is the part of a JWK the overlay checks.
type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	D   string `json:"d"`
	K   string `json:"k"`
}

// PublicKeys parses keys: public JWKs, each with a kid and an alg, no two
// with one kid.
func PublicKeys(keys []string) ([]json.RawMessage, error) {
	out := make([]json.RawMessage, 0, len(keys))
	seen := map[string]bool{}

	for i, raw := range keys {
		var k jwk
		if err := json.Unmarshal([]byte(raw), &k); err != nil {
			return nil, fmt.Errorf("%w[%d]: not JSON: %w", ErrPublicKey, i, err)
		}

		switch {
		case k.Kid == "" || k.Kty == "" || k.Alg == "":
			return nil, fmt.Errorf("%w[%d]: a JWK needs kid, kty and alg", ErrPublicKey, i)
		case k.D != "" || k.K != "":
			return nil, fmt.Errorf("%w[%d] (kid %s): a private key, keys hold public ones", ErrPublicKey, i, k.Kid)
		case seen[k.Kid]:
			return nil, fmt.Errorf("%w[%d]: kid %s twice", ErrPublicKey, i, k.Kid)
		}

		seen[k.Kid] = true

		out = append(out, json.RawMessage(raw))
	}

	return out, nil
}

// signingSet is the JWK set Kratos signs with: key alone, a private JWK
// whose public half is the first of public.
func signingSet(key string, public []json.RawMessage) ([]byte, error) {
	var k jwk
	if err := json.Unmarshal([]byte(key), &k); err != nil {
		return nil, fmt.Errorf("%w: not JSON: %w", ErrTokenKey, err)
	}

	if k.D == "" || k.Alg == "" || k.Kid == "" {
		return nil, fmt.Errorf("%w: a private JWK with kid and alg", ErrTokenKey)
	}

	if len(public) == 0 {
		return nil, fmt.Errorf("%w (kid %s): its public key is not in tokens.keys", ErrTokenKey, k.Kid)
	}

	var first jwk

	_ = json.Unmarshal(public[0], &first) // PublicKeys parsed it

	if first.Kid != k.Kid {
		return nil, fmt.Errorf("%w (kid %s): the first of tokens.keys is %s, it must be the signing key's public key",
			ErrTokenKey, k.Kid, first.Kid)
	}

	set, err := json.Marshal(map[string][]json.RawMessage{"keys": {json.RawMessage(key)}})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrTokenKey, err)
	}

	return set, nil
}

// tokens renders the tokenizer template when a signing key is set.
func (r renderer) tokens() error {
	key := r.sec.TokenKey
	if key == "" {
		return nil
	}

	t := r.s.Tokens

	public, err := PublicKeys(t.Keys)
	if err != nil {
		return err
	}

	// The masked rendering shows where the key goes, not the key.
	jwks := "base64://***"

	if !r.sec.Masked {
		set, err := signingSet(key, public)
		if err != nil {
			return err
		}

		jwks = "base64://" + base64.StdEncoding.EncodeToString(set)
	}

	claims := t.Claims
	if claims == "" {
		claims = DefaultClaims
	}

	ttl := t.TTL
	if ttl <= 0 {
		ttl = DefaultTokenTTL
	}

	r.set("session.whoami.tokenizer.templates."+TokenTemplate, map[string]any{
		"ttl":               ttl.String(),
		"jwks_url":          jwks,
		"claims_mapper_url": "base64://" + base64.StdEncoding.EncodeToString([]byte(claims)),
		"subject_source":    "id",
	})

	return nil
}

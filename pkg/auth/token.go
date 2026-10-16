package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// Tokens verifies session tokens locally against the issuer's public keys.
// One Tokens serves every goroutine; it holds the keys' cache.
type Tokens struct {
	keys     *keys
	issuer   string
	audience string
	leeway   time.Duration
	now      func() time.Time
}

// TokensOptions configure NewTokens.
type TokensOptions struct {
	// KeysURL is the public keys, backplane-kratos's
	// <public URL>/.well-known/jwks.json. Required.
	KeysURL string
	// Issuer is the iss tokens must carry: Kratos's public base URL as
	// Kratos knows it (serve.public.base_url). Empty: not checked.
	Issuer string
	// Audience is a value tokens' aud must hold. Empty: not checked (the
	// default template sets none).
	Audience string
	// Leeway is the clock skew tolerated on exp, nbf and iat. Default 30s.
	Leeway time.Duration
	// HTTPClient fetches the keys. Default: a client with a 10s timeout.
	HTTPClient *http.Client
	// KeysMaxAge is how old the keys may get before a background refetch.
	// Default 10m. A token with an unknown kid fetches at once anyway.
	KeysMaxAge time.Duration
	// KeysMinRefresh is the least time between two fetches. Default 30s.
	KeysMinRefresh time.Duration
	// Now is the clock (tests). Default time.Now.
	Now func() time.Time
}

// algorithms a token may be signed with: asymmetric only.
//
//nolint:gochecknoglobals // constant list
var algorithms = []jose.SignatureAlgorithm{
	jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
}

// Defaults.
const (
	defaultLeeway     = 30 * time.Second
	defaultMaxAge     = 10 * time.Minute
	defaultMinRefresh = 30 * time.Second
	defaultTimeout    = 10 * time.Second
)

// ErrOptions: an option is missing or wrong.
var ErrOptions = errors.New("auth: options")

// NewTokens creates the verifier; it fetches nothing until the first token.
func NewTokens(o TokensOptions) (*Tokens, error) {
	if o.KeysURL == "" {
		return nil, fmt.Errorf("%w: KeysURL is required", ErrOptions)
	}

	if o.Leeway <= 0 {
		o.Leeway = defaultLeeway
	}

	if o.KeysMaxAge <= 0 {
		o.KeysMaxAge = defaultMaxAge
	}

	if o.KeysMinRefresh <= 0 {
		o.KeysMinRefresh = defaultMinRefresh
	}

	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: defaultTimeout}
	}

	if o.Now == nil {
		o.Now = time.Now
	}

	return &Tokens{
		keys:   newKeys(o.KeysURL, o.HTTPClient, o.KeysMaxAge, o.KeysMinRefresh, o.Now),
		issuer: o.Issuer, audience: o.Audience, leeway: o.Leeway, now: o.Now,
	}, nil
}

// claims are the token's claims the package reads; the rest stay in Claims.
type claims struct {
	jwt.Claims

	SessionID       string         `json:"sid"`
	AAL             string         `json:"aal"`
	Methods         []string       `json:"amr"`
	AuthenticatedAt *time.Time     `json:"authenticated_at"`
	Email           string         `json:"email"`
	SchemaID        string         `json:"schema_id"`
	Metadata        map[string]any `json:"metadata"`
}

// Verify checks token's signature and claims and returns who it is.
func (t *Tokens) Verify(ctx context.Context, token string) (Auth, error) {
	parsed, err := jwt.ParseSigned(token, algorithms)
	if err != nil {
		return Auth{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	if len(parsed.Headers) != 1 || parsed.Headers[0].KeyID == "" {
		return Auth{}, fmt.Errorf("%w: one signature with a kid", ErrInvalid)
	}

	header := parsed.Headers[0]

	key, err := t.keys.key(ctx, header.KeyID)
	if err != nil {
		return Auth{}, err
	}

	// The key decides the algorithm, not the token: a key published for
	// ES256 verifies only ES256.
	if key.Algorithm != "" && key.Algorithm != header.Algorithm {
		return Auth{}, fmt.Errorf("%w: signed %s with a key for %s", ErrInvalid, header.Algorithm, key.Algorithm)
	}

	var (
		c   claims
		all map[string]any
	)

	if err := parsed.Claims(key.Key, &c, &all); err != nil {
		return Auth{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	expected := jwt.Expected{Issuer: t.issuer, Time: t.now()}
	if t.audience != "" {
		expected.AnyAudience = jwt.Audience{t.audience}
	}

	if err := c.ValidateWithLeeway(expected, t.leeway); err != nil {
		if errors.Is(err, jwt.ErrExpired) || errors.Is(err, jwt.ErrNotValidYet) {
			return Auth{}, fmt.Errorf("%w: %w", ErrExpired, err)
		}

		return Auth{}, fmt.Errorf("%w: %w", ErrInvalid, err)
	}

	if c.Subject == "" || c.Expiry == nil {
		return Auth{}, fmt.Errorf("%w: sub and exp are required", ErrInvalid)
	}

	a := Auth{
		IdentityID: c.Subject, SessionID: c.SessionID, AAL: c.AAL, Methods: c.Methods,
		ExpiresAt: c.Expiry.Time(), Email: c.Email, SchemaID: c.SchemaID, Metadata: c.Metadata,
		Source: FromToken, Claims: all,
	}
	if c.AuthenticatedAt != nil {
		a.AuthenticatedAt = *c.AuthenticatedAt
	}

	return a, nil
}

// Package backchannel receives OpenID Connect Back-Channel Logout 1.0
// tokens: an IdP ending a person's login ends their Kratos sessions. It never
// deactivates anyone; only a directory (SCIM) decides who may sign in.
package backchannel

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// logoutEvent is the event a logout token carries (spec 2.4).
const logoutEvent = "http://schemas.openid.net/event/backchannel-logout"

// leeway is the clock skew allowed on iat and exp.
const leeway = time.Minute

// algorithms a logout token may be signed with: asymmetric only, never none.
func algorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512, jose.EdDSA,
	}
}

// Claims are the checked claims of a logout token.
type Claims struct {
	Subject string
	JTI     string
	Expiry  time.Time
}

// extra are the claims go-jose's jwt.Claims leaves out.
type extra struct {
	Events map[string]json.RawMessage `json:"events"`
	Nonce  *string                    `json:"nonce"`
}

var (
	// ErrToken: the logout token is not one this provider signed for us.
	ErrToken = errors.New("backchannel: invalid logout token")
	// ErrUnknownKey: no key of the provider's set verifies the token.
	ErrUnknownKey = errors.New("backchannel: the token's key is not in the provider's key set")
)

// KeyID is the key id a compact JWS names; empty when it names none.
func KeyID(raw string) (string, error) {
	tok, err := jwt.ParseSigned(raw, algorithms())
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrToken, err)
	}

	return tok.Headers[0].KeyID, nil
}

// Verify checks raw as the specification requires (2.6): the signature by a
// key of keys, iss, aud, iat and exp, the back-channel logout event, no
// nonce; and a sub and a jti, which this receiver needs.
func Verify(raw string, p Provider, keys jose.JSONWebKeySet, now time.Time) (Claims, error) {
	tok, err := jwt.ParseSigned(raw, algorithms())
	if err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrToken, err)
	}

	candidates := keys.Keys
	if kid := tok.Headers[0].KeyID; kid != "" {
		candidates = keys.Key(kid)
	}

	var (
		std   jwt.Claims
		more  extra
		valid bool
	)

	for i := range candidates {
		if tok.Claims(candidates[i].Key, &std, &more) == nil {
			valid = true

			break
		}
	}

	if !valid {
		return Claims{}, ErrUnknownKey
	}

	if err := std.ValidateWithLeeway(jwt.Expected{
		Issuer: p.Issuer, AnyAudience: jwt.Audience{p.Audience}, Time: now,
	}, leeway); err != nil {
		return Claims{}, fmt.Errorf("%w: %w", ErrToken, err)
	}

	return checked(std, more)
}

// checked applies the rules go-jose does not: iat and exp present, the
// logout event, no nonce, sub and jti present.
func checked(std jwt.Claims, more extra) (Claims, error) {
	switch {
	case std.IssuedAt == nil || std.Expiry == nil:
		return Claims{}, fmt.Errorf("%w: iat and exp are required", ErrToken)
	case more.Events[logoutEvent] == nil:
		return Claims{}, fmt.Errorf("%w: no back-channel logout event", ErrToken)
	case more.Nonce != nil:
		return Claims{}, fmt.Errorf("%w: a logout token carries no nonce", ErrToken)
	case std.Subject == "":
		return Claims{}, fmt.Errorf("%w: sub is required (Kratos keeps no link from the IdP's sid)", ErrToken)
	case std.ID == "":
		return Claims{}, fmt.Errorf("%w: jti is required", ErrToken)
	}

	return Claims{Subject: std.Subject, JTI: std.ID, Expiry: std.Expiry.Time()}, nil
}

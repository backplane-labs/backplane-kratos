package backchannel

import (
	"errors"
	"fmt"
	"net/url"
)

// Provider is a Kratos OIDC provider whose IdP sends logout tokens.
type Provider struct {
	// ID is the Kratos OIDC provider id: a token's sub is the identity's
	// credential <id>:<sub>.
	ID string `json:"id" schemapb:"description=Kratos OIDC provider id"`
	// Issuer is the token's iss.
	Issuer string `json:"issuer" schemapb:"description=The IdP's issuer (the token's iss)"`
	// Audience is the client id Kratos signs in with (the token's aud).
	Audience string `json:"audience" schemapb:"description=Kratos's client id at the IdP (the token's aud)"`
	// JWKSURL is where the IdP publishes its signing keys.
	JWKSURL string `json:"jwks_url" schemapb:"description=URL of the IdP's signing keys (JWKS)"`
}

var (
	// ErrProvider: a provider misses its id, issuer or audience.
	ErrProvider = errors.New("backchannel: a provider needs id, issuer and audience")
	// ErrJWKSURL: jwks_url is not an absolute https URL.
	ErrJWKSURL = errors.New("backchannel: jwks_url must be an absolute https URL")
	// ErrDuplicateProvider: two entries name one provider.
	ErrDuplicateProvider = errors.New("backchannel: provider ids must be unique")
)

// Validate checks the providers of a configuration; allowHTTP lets the
// tests serve keys over plain HTTP.
func Validate(providers []Provider, allowHTTP bool) error {
	seen := map[string]bool{}

	for _, p := range providers {
		if p.ID == "" || p.Issuer == "" || p.Audience == "" {
			return fmt.Errorf("%w: %q", ErrProvider, p.ID)
		}

		if seen[p.ID] {
			return fmt.Errorf("%w: %q", ErrDuplicateProvider, p.ID)
		}

		seen[p.ID] = true

		u, err := url.Parse(p.JWKSURL)
		if err != nil || u.Host == "" || (u.Scheme != "https" && (!allowHTTP || u.Scheme != "http")) {
			return fmt.Errorf("%w: %q", ErrJWKSURL, p.JWKSURL)
		}
	}

	return nil
}

func find(providers []Provider, id string) (Provider, bool) {
	for _, p := range providers {
		if p.ID == id {
			return p, true
		}
	}

	return Provider{}, false
}

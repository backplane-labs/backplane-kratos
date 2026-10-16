// Package auth tells a service who made a request, from the credentials Ory
// Kratos gives a signed-in user. Two ways, one result (Auth):
//
//   - Tokens: a short JWT the user's client gets from
//     /sessions/whoami?tokenize_as=backplane (backplane-kratos configures
//     the template and serves its public keys). Verified locally, without
//     a call: a revoked session stops getting tokens at once, a token
//     already issued stays valid until it expires (the settings' TTL).
//   - Sessions: the session cookie or session token itself, asked of
//     Kratos's /sessions/whoami on every call. Nothing is cached: a revoked
//     session fails the next call, at the price of a call.
//
// Neither caches users: tokens need no cache, sessions have none, so every
// replica of a service answers alike. The only cache is of the public keys,
// fetched on first use, on an unknown kid and in the background when old.
package auth

import (
	"errors"
	"slices"
	"time"
)

// Errors. Every error of the package wraps one of them.
var (
	// ErrNoCredential: the request carries no token, cookie or session token.
	ErrNoCredential = errors.New("auth: no credential")
	// ErrInvalid: the token is malformed, badly signed or its claims fail.
	ErrInvalid = errors.New("auth: invalid token")
	// ErrExpired: the token's exp has passed (or its nbf has not come).
	ErrExpired = errors.New("auth: token expired")
	// ErrUnknownKey: the token is signed with a key the issuer does not
	// publish.
	ErrUnknownKey = errors.New("auth: token signed with an unknown key")
	// ErrUnauthenticated: Kratos knows no active session for the credential.
	ErrUnauthenticated = errors.New("auth: no active session")
	// ErrSecondFactor: the session has to complete a second factor first
	// (whoami's required_aal is highest_available).
	ErrSecondFactor = errors.New("auth: the session needs its second factor")
	// ErrUnavailable: Kratos or the keys could not be reached.
	ErrUnavailable = errors.New("auth: unavailable")
)

// Source of an Auth.
const (
	// FromToken: verified from a token, locally.
	FromToken = "token"
	// FromSession: Kratos answered for the session.
	FromSession = "session"
)

// Assurance levels, weakest first.
const (
	AAL1 = "aal1"
	AAL2 = "aal2"
	AAL3 = "aal3"
)

// Auth is who made a request and how they signed in.
type Auth struct {
	// IdentityID is the Kratos identity (a token's sub).
	IdentityID string
	// SessionID is the Kratos session (a token's sid).
	SessionID string
	// AAL is the session's assurance level: aal1 one factor, aal2 two.
	AAL string
	// Methods are how the session authenticated (password, code, totp,
	// webauthn, passkey, oidc, lookup_secret...), in order.
	Methods []string
	// AuthenticatedAt is when the user last proved who they are.
	AuthenticatedAt time.Time
	// ExpiresAt is when the token or the session expires.
	ExpiresAt time.Time
	// Email is the identity's email trait, when it has one.
	Email string
	// SchemaID is the identity's schema.
	SchemaID string
	// Metadata is the identity's public metadata (roles live there).
	Metadata map[string]any
	// Source is FromToken or FromSession.
	Source string
	// Claims are all of a token's claims (FromToken).
	Claims map[string]any
	// Session is the whole session Kratos returned (FromSession).
	Session *Session
}

// IsZero reports whether a is the zero Auth (nobody).
func (a Auth) IsZero() bool { return a.IdentityID == "" }

// Roles are the strings of the public metadata's "roles" list.
func (a Auth) Roles() []string {
	list, _ := a.Metadata["roles"].([]any)

	out := make([]string, 0, len(list))

	for _, v := range list {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}

	return out
}

// HasRole reports whether the public metadata's roles hold role.
func (a Auth) HasRole(role string) bool { return slices.Contains(a.Roles(), role) }

// AtLeast reports whether the session's assurance level is aal or higher.
func (a Auth) AtLeast(aal string) bool {
	return aalRank(a.AAL) >= aalRank(aal) && aalRank(aal) > 0
}

// AuthenticatedWithin reports whether the user proved who they are within
// d before now: a sensitive action asks for a fresh sign-in.
func (a Auth) AuthenticatedWithin(d time.Duration, now time.Time) bool {
	return !a.AuthenticatedAt.IsZero() && now.Sub(a.AuthenticatedAt) <= d
}

// UsedMethod reports whether the session authenticated with method.
func (a Auth) UsedMethod(method string) bool { return slices.Contains(a.Methods, method) }

// aalRank orders the levels; an unknown one ranks below them all.
func aalRank(aal string) int { return slices.Index(aals, aal) + 1 }

// aals are the assurance levels, weakest first.
//
//nolint:gochecknoglobals // constant list
var aals = []string{AAL1, AAL2, AAL3}

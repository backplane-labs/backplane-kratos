package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Sessions asks Kratos about a session on every call: no cache, so a revoked
// session fails the next call on every replica.
type Sessions struct {
	whoami string
	client *http.Client
}

// NewSessions asks Kratos's public API at publicURL (as this service reaches
// it); client nil: a client with a 10s timeout.
func NewSessions(publicURL string, client *http.Client) (Sessions, error) {
	if publicURL == "" {
		return Sessions{}, fmt.Errorf("%w: Kratos's public URL is required", ErrOptions)
	}

	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}

	return Sessions{whoami: strings.TrimRight(publicURL, "/") + "/sessions/whoami", client: client}, nil
}

// Credential is what proves a session: the browser's cookies or a native
// app's session token.
type Credential struct {
	// Cookie is the request's whole Cookie header: Kratos picks its own.
	Cookie string
	// Token is a session token (ory_st_...).
	Token string
}

// IsZero reports whether c holds nothing.
func (c Credential) IsZero() bool { return c.Cookie == "" && c.Token == "" }

// Session is Kratos's session as whoami returns it.
type Session struct {
	ID              string          `json:"id"`
	Active          bool            `json:"active"`
	ExpiresAt       time.Time       `json:"expires_at"`
	AuthenticatedAt time.Time       `json:"authenticated_at"`
	IssuedAt        time.Time       `json:"issued_at"`
	AAL             string          `json:"authenticator_assurance_level"`
	Methods         []SessionMethod `json:"authentication_methods"`
	Identity        Identity        `json:"identity"`
	Devices         []Device        `json:"devices"`
	// Tokenized is the session's token when asked for (Tokenize).
	Tokenized string `json:"tokenized,omitempty"`
}

// SessionMethod is one factor of a session.
type SessionMethod struct {
	Method      string    `json:"method"`
	AAL         string    `json:"aal"`
	CompletedAt time.Time `json:"completed_at"`
	// Provider is the OIDC provider of an oidc method.
	Provider string `json:"provider,omitempty"`
}

// Identity is the session's identity.
type Identity struct {
	ID                  string          `json:"id"`
	SchemaID            string          `json:"schema_id"`
	State               string          `json:"state"`
	Traits              json.RawMessage `json:"traits"`
	MetadataPublic      map[string]any  `json:"metadata_public"`
	VerifiableAddresses []Address       `json:"verifiable_addresses"`
	ExternalID          string          `json:"external_id,omitempty"`
}

// Address is a verifiable address of the identity.
type Address struct {
	Value    string `json:"value"`
	Via      string `json:"via"`
	Verified bool   `json:"verified"`
}

// Device is a device the session was used from.
type Device struct {
	ID        string `json:"id"`
	IPAddress string `json:"ip_address"`
	UserAgent string `json:"user_agent"`
	Location  string `json:"location"`
}

// Session returns the active session c proves, asking Kratos.
func (s Sessions) Session(ctx context.Context, c Credential) (Session, error) {
	return s.ask(ctx, c, "")
}

// Verify returns who c proves, asking Kratos.
func (s Sessions) Verify(ctx context.Context, c Credential) (Auth, error) {
	session, err := s.ask(ctx, c, "")
	if err != nil {
		return Auth{}, err
	}

	return session.auth(), nil
}

// Tokenize returns a token of the session c proves (template: the
// tokenizer template, "backplane" for backplane-kratos's): an edge that
// holds the browser's cookie can hand services a token instead.
func (s Sessions) Tokenize(ctx context.Context, c Credential, template string) (string, error) {
	session, err := s.ask(ctx, c, template)
	if err != nil {
		return "", err
	}

	if session.Tokenized == "" {
		return "", fmt.Errorf("%w: Kratos returned no token for template %q", ErrUnavailable, template)
	}

	return session.Tokenized, nil
}

// maxSession bounds whoami's answer.
const maxSession = 1 << 20

func (s Sessions) ask(ctx context.Context, c Credential, template string) (Session, error) {
	if c.IsZero() {
		return Session{}, ErrNoCredential
	}

	u := s.whoami
	if template != "" {
		u += "?tokenize_as=" + url.QueryEscape(template)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, http.NoBody)
	if err != nil {
		return Session{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	req.Header.Set("Accept", "application/json")

	if c.Cookie != "" {
		req.Header.Set("Cookie", c.Cookie)
	}

	if c.Token != "" {
		req.Header.Set("X-Session-Token", c.Token)
	}

	res, err := s.client.Do(req)
	if err != nil {
		return Session{}, fmt.Errorf("%w: whoami: %w", ErrUnavailable, err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, maxSession))
	if err != nil {
		return Session{}, fmt.Errorf("%w: whoami: %w", ErrUnavailable, err)
	}

	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return Session{}, ErrUnauthenticated
	case http.StatusForbidden:
		// session_aal2_required: signed in, second factor pending.
		return Session{}, fmt.Errorf("%w: %s", ErrSecondFactor, reason(body))
	default:
		return Session{}, fmt.Errorf("%w: whoami answered %s: %s", ErrUnavailable, res.Status, reason(body))
	}

	var session Session
	if err := json.Unmarshal(body, &session); err != nil {
		return Session{}, fmt.Errorf("%w: whoami: %w", ErrUnavailable, err)
	}

	if !session.Active {
		return Session{}, ErrUnauthenticated
	}

	return session, nil
}

// reason is an Ory error body's reason, or the body.
func reason(body []byte) string {
	var e struct {
		Error struct {
			ID      string `json:"id"`
			Reason  string `json:"reason"`
			Message string `json:"message"`
		} `json:"error"`
	}

	if json.Unmarshal(body, &e) == nil && (e.Error.Reason != "" || e.Error.Message != "") {
		return strings.TrimSpace(e.Error.ID + " " + e.Error.Reason + " " + e.Error.Message)
	}

	const most = 200
	if len(body) > most {
		body = body[:most]
	}

	return string(body)
}

// auth is the session as an Auth.
func (s Session) auth() Auth {
	methods := make([]string, 0, len(s.Methods))
	for _, m := range s.Methods {
		methods = append(methods, m.Method)
	}

	var traits struct {
		Email string `json:"email"`
	}

	_ = json.Unmarshal(s.Identity.Traits, &traits)

	return Auth{
		IdentityID: s.Identity.ID, SessionID: s.ID, AAL: s.AAL, Methods: methods,
		AuthenticatedAt: s.AuthenticatedAt, ExpiresAt: s.ExpiresAt, Email: traits.Email,
		SchemaID: s.Identity.SchemaID, Metadata: s.Identity.MetadataPublic, Source: FromSession, Session: &s,
	}
}

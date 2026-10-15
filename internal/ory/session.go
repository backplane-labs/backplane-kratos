package ory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// Session as Kratos returns it.
type Session struct {
	ID                          string                 `json:"id"`
	Active                      bool                   `json:"active"`
	AuthenticatedAt             *time.Time             `json:"authenticated_at,omitempty"`
	IssuedAt                    *time.Time             `json:"issued_at,omitempty"`
	ExpiresAt                   *time.Time             `json:"expires_at,omitempty"`
	AuthenticatorAssuranceLevel string                 `json:"authenticator_assurance_level,omitempty"`
	AuthenticationMethods       []AuthenticationMethod `json:"authentication_methods,omitempty"`
	Devices                     []Device               `json:"devices,omitempty"`
	Identity                    *Identity              `json:"identity,omitempty"`
}

// AuthenticationMethod completed in a session.
type AuthenticationMethod struct {
	Method      string     `json:"method"`
	AAL         string     `json:"aal,omitempty"`
	Provider    string     `json:"provider,omitempty"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// Device a session was used from.
type Device struct {
	ID        string `json:"id"`
	IPAddress string `json:"ip_address,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
	Location  string `json:"location,omitempty"`
}

// SessionFilter narrows a session listing.
type SessionFilter struct {
	// Active: nil both, else only active or only inactive ones.
	Active *bool
	// Expand: "identity", "devices".
	Expand    []string
	PageSize  int
	PageToken string
}

func (f SessionFilter) query() url.Values {
	q := url.Values{}
	if f.Active != nil {
		q.Set("active", strconv.FormatBool(*f.Active))
	}

	for _, e := range f.Expand {
		q.Add("expand", e)
	}

	paging(q, f.PageSize, f.PageToken)

	return q
}

// ListSessions pages through every identity's sessions.
func (c Client) ListSessions(ctx context.Context, f SessionFilter) (Page[Session], error) {
	var out []Session

	h, err := c.do(ctx, request{method: http.MethodGet, base: c.admin, path: "/admin/sessions", query: f.query()}, &out)

	return Page[Session]{Items: out, Next: nextToken(h)}, err
}

// ListIdentitySessions pages through one identity's sessions.
func (c Client) ListIdentitySessions(ctx context.Context, id string, f SessionFilter) (Page[Session], error) {
	q := f.query()
	q.Del("expand")

	var out []Session

	h, err := c.do(ctx, request{
		method: http.MethodGet, base: c.admin, path: "/admin/identities/" + url.PathEscape(id) + "/sessions", query: q,
	}, &out)

	return Page[Session]{Items: out, Next: nextToken(h)}, err
}

// GetSession reads one session with its identity and devices.
func (c Client) GetSession(ctx context.Context, id string) (Session, error) {
	var out Session

	_, err := c.do(ctx, request{
		method: http.MethodGet, base: c.admin, path: "/admin/sessions/" + url.PathEscape(id),
		query: url.Values{"expand": {"identity", "devices"}},
	}, &out)

	return out, err
}

// DisableSession revokes one session.
func (c Client) DisableSession(ctx context.Context, id string) error {
	_, err := c.do(
		ctx,
		request{method: http.MethodDelete, base: c.admin, path: "/admin/sessions/" + url.PathEscape(id)},
		nil,
	)

	return err
}

// DeleteIdentitySessions revokes every session of an identity.
func (c Client) DeleteIdentitySessions(ctx context.Context, id string) error {
	_, err := c.do(ctx, request{
		method: http.MethodDelete, base: c.admin, path: "/admin/identities/" + url.PathEscape(id) + "/sessions",
	}, nil)

	return err
}

// ExtendSession extends a session by the configured lifespan.
func (c Client) ExtendSession(ctx context.Context, id string) (Session, error) {
	var out Session

	_, err := c.do(ctx, request{
		method: http.MethodPatch, base: c.admin, path: "/admin/sessions/" + url.PathEscape(id) + "/extend",
	}, &out)

	return out, err
}

// WhoAmI checks a session token or a session cookie header on the public
// API: the session it stands for; a 401 Error when there is none.
func (c Client) WhoAmI(ctx context.Context, token, cookie string) (Session, error) {
	h := http.Header{}
	if token != "" {
		h.Set("X-Session-Token", token)
	}

	if cookie != "" {
		h.Set("Cookie", cookie)
	}

	var out Session

	_, err := c.do(ctx, request{method: http.MethodGet, base: c.public, path: "/sessions/whoami", header: h}, &out)

	return out, err
}

// RecoveryCode is an admin-made recovery: a code with its flow's link,
// or a link alone.
type RecoveryCode struct {
	Link      string     `json:"recovery_link"           schemapb:"secret=true"`
	Code      string     `json:"recovery_code,omitempty" schemapb:"secret=true"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// CreateRecoveryCode creates a recovery code for an identity; expiresIn is
// Kratos's duration ("1h"), empty for the configured one; flowType "api" or
// "browser" (default browser).
func (c Client) CreateRecoveryCode(ctx context.Context, id, expiresIn, flowType string) (RecoveryCode, error) {
	body := map[string]string{"identity_id": id}
	if expiresIn != "" {
		body["expires_in"] = expiresIn
	}

	if flowType != "" {
		body["flow_type"] = flowType
	}

	var out RecoveryCode

	_, err := c.do(ctx, request{method: http.MethodPost, base: c.admin, path: "/admin/recovery/code", body: body}, &out)

	return out, err
}

// CreateRecoveryLink creates a recovery link for an identity.
func (c Client) CreateRecoveryLink(ctx context.Context, id, expiresIn string) (RecoveryCode, error) {
	body := map[string]string{"identity_id": id}
	if expiresIn != "" {
		body["expires_in"] = expiresIn
	}

	var out RecoveryCode

	_, err := c.do(ctx, request{method: http.MethodPost, base: c.admin, path: "/admin/recovery/link", body: body}, &out)

	return out, err
}

// Message is a courier message in Kratos's queue.
type Message struct {
	ID           string     `json:"id"`
	Status       string     `json:"status"`
	Type         string     `json:"type"`
	Channel      string     `json:"channel,omitempty"`
	Recipient    string     `json:"recipient"`
	Subject      string     `json:"subject"              schemapb:"secret=true"`
	Body         string     `json:"body"                 schemapb:"secret=true"`
	TemplateType string     `json:"template_type"`
	SendCount    int        `json:"send_count"`
	Dispatches   []Dispatch `json:"dispatches,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty"`
	UpdatedAt    *time.Time `json:"updated_at,omitempty"`
}

// Dispatch is one delivery attempt of a message.
type Dispatch struct {
	ID        string          `json:"id"`
	Status    string          `json:"status"`
	Error     json.RawMessage `json:"error,omitempty"`
	CreatedAt *time.Time      `json:"created_at,omitempty"`
}

// MessageFilter narrows ListMessages.
type MessageFilter struct {
	Status    string // queued, sent, processing, abandoned
	Recipient string
	PageSize  int
	PageToken string
}

// ListMessages pages through the courier's queue.
func (c Client) ListMessages(ctx context.Context, f MessageFilter) (Page[Message], error) {
	q := url.Values{}
	if f.Status != "" {
		q.Set("status", f.Status)
	}

	if f.Recipient != "" {
		q.Set("recipient", f.Recipient)
	}

	paging(q, f.PageSize, f.PageToken)

	var out []Message

	h, err := c.do(ctx, request{method: http.MethodGet, base: c.admin, path: "/admin/courier/messages", query: q}, &out)

	return Page[Message]{Items: out, Next: nextToken(h)}, err
}

// GetMessage reads one courier message with its dispatches.
func (c Client) GetMessage(ctx context.Context, id string) (Message, error) {
	var out Message

	_, err := c.do(
		ctx,
		request{method: http.MethodGet, base: c.admin, path: "/admin/courier/messages/" + url.PathEscape(id)},
		&out,
	)

	return out, err
}

// Schema is an identity schema the installation serves.
type Schema struct {
	ID     string          `json:"id"`
	Schema json.RawMessage `json:"schema"`
}

// ListSchemas lists the identity schemas (public API).
func (c Client) ListSchemas(ctx context.Context) ([]Schema, error) {
	var out []Schema

	_, err := c.do(ctx, request{
		method: http.MethodGet, base: c.public, path: "/schemas", query: url.Values{"page_size": {"500"}},
	}, &out)

	return out, err
}

// InitFlow starts a self-service flow for native apps (/self-service/<kind>/api)
// and answers it as Kratos sends it: its id, state and UI nodes.
func (c Client) InitFlow(ctx context.Context, kind string) (json.RawMessage, error) {
	var out json.RawMessage

	path := "/self-service/" + url.PathEscape(kind) + "/api"

	_, err := c.do(ctx, request{method: http.MethodGet, base: c.public, path: path}, &out)

	return out, err
}

package ory

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"time"
)

// Identity as Kratos's admin API returns it. Traits, metadata and the
// credentials' configurations keep Kratos's JSON.
type Identity struct {
	ID                  string                 `json:"id"`
	SchemaID            string                 `json:"schema_id"`
	SchemaURL           string                 `json:"schema_url,omitempty"`
	State               string                 `json:"state,omitempty"`
	StateChangedAt      *time.Time             `json:"state_changed_at,omitempty"`
	Traits              json.RawMessage        `json:"traits"`
	MetadataPublic      json.RawMessage        `json:"metadata_public,omitempty"`
	MetadataAdmin       json.RawMessage        `json:"metadata_admin,omitempty"`
	ExternalID          string                 `json:"external_id,omitempty"`
	OrganizationID      *string                `json:"organization_id,omitempty"`
	VerifiableAddresses []VerifiableAddress    `json:"verifiable_addresses,omitempty"`
	RecoveryAddresses   []RecoveryAddress      `json:"recovery_addresses,omitempty"`
	Credentials         map[string]Credentials `json:"credentials,omitempty"`
	CreatedAt           *time.Time             `json:"created_at,omitempty"`
	UpdatedAt           *time.Time             `json:"updated_at,omitempty"`
}

// VerifiableAddress is an address Kratos verifies (email, sms).
type VerifiableAddress struct {
	ID         string     `json:"id,omitempty"`
	Value      string     `json:"value"`
	Via        string     `json:"via"`
	Verified   bool       `json:"verified"`
	VerifiedAt *time.Time `json:"verified_at,omitempty"`
	Status     string     `json:"status"`
}

// RecoveryAddress is an address recovery can go to.
type RecoveryAddress struct {
	ID    string `json:"id,omitempty"`
	Value string `json:"value"`
	Via   string `json:"via"`
}

// Credentials of one type: its identifiers and Kratos's configuration of
// it (hashes, secrets — present only when asked for).
type Credentials struct {
	Type        string          `json:"type"`
	Identifiers []string        `json:"identifiers,omitempty"`
	Config      json.RawMessage `json:"config,omitempty"      schemapb:"secret=true"`
	Version     int             `json:"version,omitempty"`
	CreatedAt   *time.Time      `json:"created_at,omitempty"`
	UpdatedAt   *time.Time      `json:"updated_at,omitempty"`
}

// IdentityFilter narrows ListIdentities.
type IdentityFilter struct {
	// CredentialsIdentifier: an identifier of a credential (email, username).
	CredentialsIdentifier string
	// IDs: these identities only.
	IDs []string
	// IncludeCredential: credential types whose configuration to include.
	IncludeCredential []string
	PageSize          int
	PageToken         string
}

// Page is one page of a listing and the token of the next ("" at the end).
type Page[T any] struct {
	Items []T
	Next  string
}

// ListIdentities pages through identities.
func (c Client) ListIdentities(ctx context.Context, f IdentityFilter) (Page[Identity], error) {
	q := url.Values{}
	if f.CredentialsIdentifier != "" {
		q.Set("credentials_identifier", f.CredentialsIdentifier)
	}

	for _, id := range f.IDs {
		q.Add("ids", id)
	}

	for _, t := range f.IncludeCredential {
		q.Add("include_credential", t)
	}

	paging(q, f.PageSize, f.PageToken)

	var out []Identity

	h, err := c.do(ctx, request{method: http.MethodGet, base: c.admin, path: "/admin/identities", query: q}, &out)

	return Page[Identity]{Items: out, Next: nextToken(h)}, err
}

// GetIdentity reads one identity; includeCredential adds those credential
// types' configurations.
func (c Client) GetIdentity(ctx context.Context, id string, includeCredential ...string) (Identity, error) {
	q := url.Values{}
	for _, t := range includeCredential {
		q.Add("include_credential", t)
	}

	var out Identity

	_, err := c.do(
		ctx,
		request{method: http.MethodGet, base: c.admin, path: "/admin/identities/" + url.PathEscape(id), query: q},
		&out,
	)

	return out, err
}

// GetIdentityByExternalID reads the identity with that external id.
func (c Client) GetIdentityByExternalID(ctx context.Context, externalID string) (Identity, error) {
	var out Identity

	_, err := c.do(ctx, request{
		method: http.MethodGet, base: c.admin, path: "/admin/identities/by/external/" + url.PathEscape(externalID),
	}, &out)

	return out, err
}

// CreateIdentity creates one from Kratos's createIdentityBody.
func (c Client) CreateIdentity(ctx context.Context, body json.RawMessage) (Identity, error) {
	var out Identity

	_, err := c.do(ctx, request{method: http.MethodPost, base: c.admin, path: "/admin/identities", body: body}, &out)

	return out, err
}

// UpdateIdentity replaces one with Kratos's updateIdentityBody.
func (c Client) UpdateIdentity(ctx context.Context, id string, body json.RawMessage) (Identity, error) {
	var out Identity

	_, err := c.do(
		ctx,
		request{method: http.MethodPut, base: c.admin, path: "/admin/identities/" + url.PathEscape(id), body: body},
		&out,
	)

	return out, err
}

// PatchIdentity applies a JSON Patch (RFC 6902) to one.
func (c Client) PatchIdentity(ctx context.Context, id string, patch json.RawMessage) (Identity, error) {
	var out Identity

	_, err := c.do(
		ctx,
		request{method: http.MethodPatch, base: c.admin, path: "/admin/identities/" + url.PathEscape(id), body: patch},
		&out,
	)

	return out, err
}

// DeleteIdentity deletes one, its credentials and sessions.
func (c Client) DeleteIdentity(ctx context.Context, id string) error {
	_, err := c.do(
		ctx,
		request{method: http.MethodDelete, base: c.admin, path: "/admin/identities/" + url.PathEscape(id)},
		nil,
	)

	return err
}

// DeleteCredentials removes one credential type of an identity (a second
// factor, a social sign-in); for oidc and saml, identifier picks the
// provider's credential.
func (c Client) DeleteCredentials(ctx context.Context, id, credentialType, identifier string) error {
	q := url.Values{}
	if identifier != "" {
		q.Set("identifier", identifier)
	}

	_, err := c.do(ctx, request{
		method: http.MethodDelete, base: c.admin,
		path:  "/admin/identities/" + url.PathEscape(id) + "/credentials/" + url.PathEscape(credentialType),
		query: q,
	}, nil)

	return err
}

func paging(q url.Values, size int, token string) {
	if size > 0 {
		q.Set("page_size", strconv.Itoa(size))
	}

	if token != "" {
		q.Set("page_token", token)
	}
}

var linkNext = regexp.MustCompile(`<([^>]+)>;\s*rel="next"`)

// nextToken is the page_token of the Link rel="next" header; "" without one.
func nextToken(h http.Header) string {
	for _, link := range h.Values("Link") {
		m := linkNext.FindStringSubmatch(link)
		if m == nil {
			continue
		}

		u, err := url.Parse(m[1])
		if err != nil {
			continue
		}

		return u.Query().Get("page_token")
	}

	return ""
}

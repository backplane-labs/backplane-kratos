// Package activities offers Kratos's admin API to wiring: identities,
// credentials, sessions, recovery and the courier's queue. Mutations
// publish events, so wiring can react to changes made anywhere.
package activities

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/activity"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

const timeout = 15 * time.Second

// Activities are the admin API as activities.
type Activities struct {
	deps.Component

	kratos ory.Client

	created event.Ref[IdentityEvent]
	updated event.Ref[IdentityEvent]
	deleted event.Ref[IdentityEvent]
	revoked event.Ref[SessionsRevoked]
}

// IdentityEvent is an identity created, updated or deleted through the
// admin API (here or in the console).
type IdentityEvent struct {
	IdentityID string          `json:"identity_id"`
	SchemaID   string          `json:"schema_id,omitempty"`
	Traits     json.RawMessage `json:"traits,omitempty"`
	// By is "wiring" or "console".
	By string `json:"by"`
}

// SessionsRevoked: sessions of an identity were revoked (one, or all
// when SessionID is empty).
type SessionsRevoked struct {
	IdentityID string `json:"identity_id,omitempty"`
	SessionID  string `json:"session_id,omitempty"`
	By         string `json:"by"`
}

// New declares the activities and events under parent.
func New(parent deps.Scope, kratos ory.Client) *Activities {
	a := &Activities{Component: deps.NewComponent(parent, "activities"), kratos: kratos}
	a.created = event.Declare[IdentityEvent](
		a,
		"IdentityCreated",
		event.Describe("an identity was created by an operator or wiring"),
	)
	a.updated = event.Declare[IdentityEvent](
		a,
		"IdentityUpdated",
		event.Describe("an identity was changed by an operator or wiring"),
	)
	a.deleted = event.Declare[IdentityEvent](
		a,
		"IdentityDeleted",
		event.Describe("an identity was deleted by an operator or wiring"),
	)
	a.revoked = event.Declare[SessionsRevoked](
		a,
		"SessionsRevoked",
		event.Describe("sessions were revoked by an operator or wiring"),
	)

	opts := func(desc string) []activity.Option {
		return []activity.Option{activity.StartToClose(timeout), activity.Describe(desc)}
	}

	activity.Handle(
		a,
		"GetIdentity",
		a.getIdentity,
		opts("Read an identity, optionally with credential configurations")...)
	activity.Handle(
		a,
		"FindIdentities",
		a.findIdentities,
		opts("Find identities by credential identifier or ids, a page at a time")...)
	activity.Handle(a, "CreateIdentity", a.createIdentity, opts("Create an identity")...)
	activity.Handle(a, "UpdateIdentity", a.updateIdentity, opts("Replace an identity's traits, state and metadata")...)
	activity.Handle(a, "PatchIdentity", a.patchIdentity, opts("Apply a JSON Patch to an identity")...)
	activity.Handle(
		a,
		"DeleteIdentity",
		a.deleteIdentity,
		opts("Delete an identity with its credentials and sessions")...)
	activity.Handle(
		a,
		"DeleteCredentials",
		a.deleteCredentials,
		opts("Remove a credential type of an identity (a second factor, a social sign-in)")...)
	activity.Handle(a, "ListSessions", a.listSessions, opts("List sessions, of one identity or all")...)
	activity.Handle(
		a,
		"RevokeSessions",
		a.revokeSessions,
		opts("Revoke one session or every session of an identity")...)
	activity.Handle(a, "ExtendSession", a.extendSession, opts("Extend a session by the configured lifespan")...)
	activity.Handle(
		a,
		"CheckSession",
		a.checkSession,
		opts("Resolve a session token or cookie to its session and identity")...)
	activity.Handle(
		a,
		"CreateRecoveryCode",
		a.createRecoveryCode,
		opts("Create a recovery code (and its link) for an identity")...)
	activity.Handle(a, "ListMessages", a.listMessages, opts("List the courier's messages")...)

	return a
}

// failure maps a Kratos error to the activity's retry semantics.
func failure(err error) error {
	if err == nil {
		return nil
	}

	if ory.Temporary(err) {
		return err
	}

	return activity.NonRetryable(err)
}

func (a *Activities) publish(ctx context.Context, ref event.Ref[IdentityEvent], ev IdentityEvent) {
	if err := ref.Publish(ctx, ev, event.Key(ev.IdentityID)); err != nil {
		a.Log().Ctx().Warn(ctx, "identity event not published", xlog.String("identity", ev.IdentityID), xlog.Err(err))
	}
}

// GetIdentityIn reads one identity.
type GetIdentityIn struct {
	ID string `json:"id,omitempty"`
	// ExternalID instead of ID.
	ExternalID string `json:"external_id,omitempty"`
	// IncludeCredential: credential types whose configurations to include
	// (password, totp, webauthn, oidc, …); they are secret.
	IncludeCredential []string `json:"include_credential,omitempty"`
}

// ErrNoID: name the identity.
var ErrNoID = errors.New("id or external_id is required")

func (a *Activities) getIdentity(ctx context.Context, in GetIdentityIn) (ory.Identity, error) {
	var (
		out ory.Identity
		err error
	)

	switch {
	case in.ID != "":
		out, err = a.kratos.GetIdentity(ctx, in.ID, in.IncludeCredential...)
	case in.ExternalID != "":
		out, err = a.kratos.GetIdentityByExternalID(ctx, in.ExternalID)
	default:
		err = ErrNoID
	}

	return out, failure(err)
}

// FindIn narrows FindIdentities.
type FindIn struct {
	CredentialsIdentifier string   `json:"credentials_identifier,omitempty" schemapb:"description=An email, username or phone"`
	IDs                   []string `json:"ids,omitempty"`
	PageSize              int      `json:"page_size,omitempty"`
	PageToken             string   `json:"page_token,omitempty"`
}

// FindOut is a page of identities.
type FindOut struct {
	Identities    []ory.Identity `json:"identities"`
	NextPageToken string         `json:"next_page_token,omitempty"`
}

func (a *Activities) findIdentities(ctx context.Context, in FindIn) (FindOut, error) {
	page, err := a.kratos.ListIdentities(ctx, ory.IdentityFilter{
		CredentialsIdentifier: in.CredentialsIdentifier, IDs: in.IDs, PageSize: in.PageSize, PageToken: in.PageToken,
	})

	return FindOut{Identities: page.Items, NextPageToken: page.Next}, failure(err)
}

// IdentityIn creates or replaces an identity.
type IdentityIn struct {
	// ID of the identity to replace (UpdateIdentity).
	ID             string          `json:"id,omitempty"`
	SchemaID       string          `json:"schema_id"`
	Traits         json.RawMessage `json:"traits"`
	State          string          `json:"state,omitempty"           validate:"omitempty,oneof=active inactive"`
	MetadataPublic json.RawMessage `json:"metadata_public,omitempty"`
	MetadataAdmin  json.RawMessage `json:"metadata_admin,omitempty"`
	ExternalID     string          `json:"external_id,omitempty"`
	// Password sets a password credential; HashedPassword imports a hash.
	Password       string `json:"password,omitempty"        schemapb:"secret=true"`
	HashedPassword string `json:"hashed_password,omitempty" schemapb:"secret=true"`
	// VerifiedAddresses marks these addresses verified (imports).
	VerifiedAddresses []ory.VerifiableAddress `json:"verifiable_addresses,omitempty"`
}

func (in IdentityIn) body(update bool) (json.RawMessage, error) {
	b := map[string]any{"schema_id": in.SchemaID, "traits": in.Traits}
	if in.State != "" {
		b["state"] = in.State
	} else if update {
		b["state"] = "active"
	}

	if len(in.MetadataPublic) > 0 {
		b["metadata_public"] = in.MetadataPublic
	}

	if len(in.MetadataAdmin) > 0 {
		b["metadata_admin"] = in.MetadataAdmin
	}

	if in.ExternalID != "" {
		b["external_id"] = in.ExternalID
	}

	if in.Password != "" || in.HashedPassword != "" {
		cfg := map[string]string{}
		if in.Password != "" {
			cfg["password"] = in.Password
		}

		if in.HashedPassword != "" {
			cfg["hashed_password"] = in.HashedPassword
		}

		b["credentials"] = map[string]any{"password": map[string]any{"config": cfg}}
	}

	if len(in.VerifiedAddresses) > 0 && !update {
		b["verifiable_addresses"] = in.VerifiedAddresses
	}

	raw, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("identity body: %w", err)
	}

	return raw, nil
}

func (a *Activities) createIdentity(ctx context.Context, in IdentityIn) (ory.Identity, error) {
	out, err := CreateIdentity(ctx, a.kratos, in)
	if err != nil {
		return out, failure(err)
	}

	a.publish(
		ctx,
		a.created,
		IdentityEvent{IdentityID: out.ID, SchemaID: out.SchemaID, Traits: out.Traits, By: "wiring"},
	)

	return out, nil
}

// CreateIdentity creates one (shared with the console).
func CreateIdentity(ctx context.Context, k ory.Client, in IdentityIn) (ory.Identity, error) {
	body, err := in.body(false)
	if err != nil {
		return ory.Identity{}, err
	}

	return k.CreateIdentity(ctx, body)
}

// UpdateIdentity replaces one (shared with the console).
func UpdateIdentity(ctx context.Context, k ory.Client, in IdentityIn) (ory.Identity, error) {
	if in.ID == "" {
		return ory.Identity{}, ErrNoID
	}

	body, err := in.body(true)
	if err != nil {
		return ory.Identity{}, err
	}

	return k.UpdateIdentity(ctx, in.ID, body)
}

func (a *Activities) updateIdentity(ctx context.Context, in IdentityIn) (ory.Identity, error) {
	out, err := UpdateIdentity(ctx, a.kratos, in)
	if err != nil {
		return out, failure(err)
	}

	a.publish(
		ctx,
		a.updated,
		IdentityEvent{IdentityID: out.ID, SchemaID: out.SchemaID, Traits: out.Traits, By: "wiring"},
	)

	return out, nil
}

// PatchIn is a JSON Patch of an identity.
type PatchIn struct {
	ID    string          `json:"id"`
	Patch json.RawMessage `json:"patch" schemapb:"description=RFC 6902 operations, e.g. [{op: replace, path: /state, value: inactive}]"`
}

func (a *Activities) patchIdentity(ctx context.Context, in PatchIn) (ory.Identity, error) {
	out, err := a.kratos.PatchIdentity(ctx, in.ID, in.Patch)
	if err != nil {
		return out, failure(err)
	}

	a.publish(
		ctx,
		a.updated,
		IdentityEvent{IdentityID: out.ID, SchemaID: out.SchemaID, Traits: out.Traits, By: "wiring"},
	)

	return out, nil
}

// IDIn names an identity or a session.
type IDIn struct {
	ID string `json:"id"`
}

// Empty is an activity without a result.
type Empty struct{}

func (a *Activities) deleteIdentity(ctx context.Context, in IDIn) (Empty, error) {
	if err := a.kratos.DeleteIdentity(ctx, in.ID); err != nil {
		if ory.IsNotFound(err) {
			return Empty{}, nil // already gone: the retry of a delete that worked
		}

		return Empty{}, failure(err)
	}

	a.publish(ctx, a.deleted, IdentityEvent{IdentityID: in.ID, By: "wiring"})

	return Empty{}, nil
}

// CredentialsIn names a credential type of an identity.
type CredentialsIn struct {
	ID   string `json:"id"`
	Type string `json:"type" validate:"oneof=password oidc totp lookup_secret webauthn code passkey saml"`
	// Identifier picks the provider's credential of oidc and saml.
	Identifier string `json:"identifier,omitempty"`
}

func (a *Activities) deleteCredentials(ctx context.Context, in CredentialsIn) (Empty, error) {
	return Empty{}, failure(a.kratos.DeleteCredentials(ctx, in.ID, in.Type, in.Identifier))
}

// SessionsIn narrows ListSessions.
type SessionsIn struct {
	// IdentityID: that identity's sessions; empty: every session.
	IdentityID string `json:"identity_id,omitempty"`
	// Active: only active (true) or inactive (false) ones; absent: both.
	Active    *bool  `json:"active,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

// SessionsOut is a page of sessions.
type SessionsOut struct {
	Sessions      []ory.Session `json:"sessions"`
	NextPageToken string        `json:"next_page_token,omitempty"`
}

func (a *Activities) listSessions(ctx context.Context, in SessionsIn) (SessionsOut, error) {
	f := ory.SessionFilter{Active: in.Active, PageSize: in.PageSize, PageToken: in.PageToken}

	var (
		page ory.Page[ory.Session]
		err  error
	)

	if in.IdentityID != "" {
		page, err = a.kratos.ListIdentitySessions(ctx, in.IdentityID, f)
	} else {
		f.Expand = []string{"identity"}
		page, err = a.kratos.ListSessions(ctx, f)
	}

	return SessionsOut{Sessions: page.Items, NextPageToken: page.Next}, failure(err)
}

// RevokeIn revokes one session or an identity's sessions.
type RevokeIn struct {
	SessionID  string `json:"session_id,omitempty"`
	IdentityID string `json:"identity_id,omitempty"`
}

// ErrRevokeWhat: name a session or an identity.
var ErrRevokeWhat = errors.New("session_id or identity_id is required")

func (a *Activities) revokeSessions(ctx context.Context, in RevokeIn) (Empty, error) {
	var err error

	switch {
	case in.SessionID != "":
		err = a.kratos.DisableSession(ctx, in.SessionID)
	case in.IdentityID != "":
		err = a.kratos.DeleteIdentitySessions(ctx, in.IdentityID)
	default:
		return Empty{}, activity.NonRetryable(ErrRevokeWhat)
	}

	if err != nil && !ory.IsNotFound(err) {
		return Empty{}, failure(err)
	}

	ev := SessionsRevoked{IdentityID: in.IdentityID, SessionID: in.SessionID, By: "wiring"}
	if err := a.revoked.Publish(ctx, ev); err != nil {
		a.Log().Ctx().Warn(ctx, "sessions event not published", xlog.Err(err))
	}

	return Empty{}, nil
}

func (a *Activities) extendSession(ctx context.Context, in IDIn) (ory.Session, error) {
	out, err := a.kratos.ExtendSession(ctx, in.ID)

	return out, failure(err)
}

// CheckIn is a credential of a session: a token, or a Cookie header.
type CheckIn struct {
	Token  string `json:"token,omitempty"  schemapb:"secret=true"`
	Cookie string `json:"cookie,omitempty" schemapb:"secret=true;description=The Cookie header with Kratos's session cookie"`
}

// CheckOut is the session they stand for; Active false without one.
type CheckOut struct {
	Active  bool         `json:"active"`
	Session *ory.Session `json:"session,omitempty"`
}

func (a *Activities) checkSession(ctx context.Context, in CheckIn) (CheckOut, error) {
	s, err := a.kratos.WhoAmI(ctx, in.Token, in.Cookie)
	if err != nil {
		var e *ory.Error
		if errors.As(err, &e) && (e.Status == 401 || e.Status == 403) {
			return CheckOut{}, nil
		}

		return CheckOut{}, failure(err)
	}

	return CheckOut{Active: s.Active, Session: &s}, nil
}

// RecoveryIn creates a recovery for an identity.
type RecoveryIn struct {
	IdentityID string `json:"identity_id"`
	// ExpiresIn is Kratos's duration ("1h"); empty: the configured one.
	ExpiresIn string `json:"expires_in,omitempty"`
	// Link: a link alone (Kratos's link method) instead of a code.
	Link bool `json:"link,omitempty"`
}

func (a *Activities) createRecoveryCode(ctx context.Context, in RecoveryIn) (ory.RecoveryCode, error) {
	if in.Link {
		out, err := a.kratos.CreateRecoveryLink(ctx, in.IdentityID, in.ExpiresIn)

		return out, failure(err)
	}

	out, err := a.kratos.CreateRecoveryCode(ctx, in.IdentityID, in.ExpiresIn, "")

	return out, failure(err)
}

// MessagesIn narrows ListMessages.
type MessagesIn struct {
	Status    string `json:"status,omitempty"     validate:"omitempty,oneof=queued sent processing abandoned"`
	Recipient string `json:"recipient,omitempty"`
	PageSize  int    `json:"page_size,omitempty"`
	PageToken string `json:"page_token,omitempty"`
}

// MessagesOut is a page of messages.
type MessagesOut struct {
	Messages      []ory.Message `json:"messages"`
	NextPageToken string        `json:"next_page_token,omitempty"`
}

func (a *Activities) listMessages(ctx context.Context, in MessagesIn) (MessagesOut, error) {
	page, err := a.kratos.ListMessages(ctx, ory.MessageFilter{
		Status: in.Status, Recipient: in.Recipient, PageSize: in.PageSize, PageToken: in.PageToken,
	})

	return MessagesOut{Messages: page.Items, NextPageToken: page.Next}, failure(err)
}

// IdentityEvent is a declared identity event by name (IdentityCreated,
// IdentityUpdated, IdentityDeleted).
func (a *Activities) IdentityEvent(name string) event.Ref[IdentityEvent] {
	switch name {
	case "IdentityCreated":
		return a.created
	case "IdentityUpdated":
		return a.updated
	default:
		return a.deleted
	}
}

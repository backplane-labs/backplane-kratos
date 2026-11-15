package scim

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/outbox"
)

// Kratos is the admin API the directories need.
type Kratos interface {
	GetIdentity(ctx context.Context, id string, includeCredential ...string) (ory.Identity, error)
	GetIdentityByExternalID(ctx context.Context, externalID string) (ory.Identity, error)
	ListIdentities(ctx context.Context, f ory.IdentityFilter) (ory.Page[ory.Identity], error)
	CreateIdentity(ctx context.Context, body json.RawMessage) (ory.Identity, error)
	UpdateIdentity(ctx context.Context, id string, body json.RawMessage) (ory.Identity, error)
	PatchIdentity(ctx context.Context, id string, patch json.RawMessage) (ory.Identity, error)
	DeleteIdentity(ctx context.Context, id string) error
	DeleteIdentitySessions(ctx context.Context, id string) error
}

// Outbox keeps a directory's events until the broker took them.
type Outbox interface {
	Register(topic string, p outbox.Publisher)
	Enqueue(ctx context.Context, m outbox.Message) error
}

// Service is the directories' scenarios against Kratos.
type Service struct {
	kratos Kratos
	outbox Outbox
}

// NewService is the scenarios over kratos, their events kept in box.
func NewService(kratos Kratos, box Outbox) Service {
	return Service{kratos: kratos, outbox: box}
}

// errUnavailable: the change is in Kratos but its event is not out yet; the
// IdP's retry publishes it.
var errUnavailable = errors.New("scim: event not published yet")

func notFound() *Error { return refuse(http.StatusNotFound, "", "no such user") }

func uniqueness(detail string) *Error { return refuse(http.StatusConflict, "uniqueness", detail) }

// Create provisions u: a new identity pre-linked to the directory's provider,
// or the existing one holding that credential (the IdP retrying, or a person
// who signed in before the directory created them).
func (s Service) Create(ctx context.Context, d Directory, u User) (ory.Identity, error) {
	ext, _ := u.String("externalId")
	if ext == "" {
		return ory.Identity{}, invalidValue("externalId is required: it links the user to their OIDC login")
	}

	found, ok, err := s.byCredential(ctx, d.Provider, ext)
	if err != nil {
		return ory.Identity{}, err
	}

	if ok {
		r, mine := stored(found)
		if mine && r.Directory != d.ID {
			return ory.Identity{}, uniqueness("the user belongs to another directory")
		}

		kind := eventUpdated
		if mine {
			kind = eventCreated
		}

		return s.write(ctx, d, found, u, kind, ReasonDeactivated)
	}

	name, _ := u.String("userName")

	switch _, err := s.kratos.GetIdentityByExternalID(ctx, externalID(d.ID, name)); {
	case err == nil:
		return ory.Identity{}, uniqueness("userName " + name + " exists")
	case !ory.IsNotFound(err):
		return ory.Identity{}, kratosFailure(err)
	}

	return s.create(ctx, d, u, ext)
}

// createBody is Kratos's createIdentityBody with a pre-linked OIDC credential.
type createBody struct {
	SchemaID       string          `json:"schema_id,omitempty"`
	Traits         json.RawMessage `json:"traits"`
	MetadataPublic json.RawMessage `json:"metadata_public,omitempty"`
	MetadataAdmin  json.RawMessage `json:"metadata_admin"`
	ExternalID     string          `json:"external_id"`
	State          string          `json:"state"`
	Credentials    struct {
		OIDC struct {
			Config struct {
				Providers []oidcLink `json:"providers"`
			} `json:"config"`
		} `json:"oidc"`
	} `json:"credentials"`
}

type oidcLink struct {
	Provider string `json:"provider"`
	Subject  string `json:"subject"`
}

func (s Service) create(ctx context.Context, d Directory, u User, ext string) (ory.Identity, error) {
	mapped, err := d.Map(u)
	if err != nil {
		return ory.Identity{}, err
	}

	meta, err := withRecord(nil, record{Directory: d.ID, User: u})
	if err != nil {
		return ory.Identity{}, fmt.Errorf("scim: metadata: %w", err)
	}

	name, _ := u.String("userName")
	body := createBody{
		SchemaID: d.SchemaID, Traits: mapped.Traits, MetadataPublic: mapped.MetadataPublic, MetadataAdmin: meta,
		ExternalID: externalID(d.ID, name), State: state(u.Active()),
	}
	body.Credentials.OIDC.Config.Providers = []oidcLink{{Provider: d.Provider, Subject: ext}}

	raw, err := json.Marshal(body)
	if err != nil {
		return ory.Identity{}, fmt.Errorf("scim: create body: %w", err)
	}

	created, err := s.kratos.CreateIdentity(ctx, raw)
	if err != nil {
		return ory.Identity{}, kratosFailure(err)
	}

	return s.announce(ctx, d, created, eventCreated, ReasonDeactivated, false)
}

// Get is a directory's user.
func (s Service) Get(ctx context.Context, d Directory, id string) (ory.Identity, error) {
	return s.owned(ctx, d, id)
}

// Replace replaces the user with u (PUT).
func (s Service) Replace(ctx context.Context, d Directory, id string, u User) (ory.Identity, error) {
	cur, err := s.owned(ctx, d, id)
	if err != nil {
		return ory.Identity{}, err
	}

	return s.write(ctx, d, cur, u, eventUpdated, ReasonDeactivated)
}

// Patch applies ops to the user as the directory last wrote it, with active
// as Kratos holds it.
func (s Service) Patch(ctx context.Context, d Directory, id string, ops []Operation) (ory.Identity, error) {
	cur, err := s.owned(ctx, d, id)
	if err != nil {
		return ory.Identity{}, err
	}

	r, _ := stored(cur)
	u := maps.Clone(r.User)
	u.setBool("active", cur.State != state(false))

	if err := u.Apply(ops); err != nil {
		return ory.Identity{}, err
	}

	return s.write(ctx, d, cur, u, eventUpdated, ReasonDeactivated)
}

// Delete deletes the identity, or deactivates it and keeps it readable.
func (s Service) Delete(ctx context.Context, d Directory, id string) error {
	cur, err := s.owned(ctx, d, id)
	if err != nil {
		return err
	}

	if !d.Deletes() {
		r, _ := stored(cur)
		u := maps.Clone(r.User)
		u.setBool("active", false)

		_, err := s.write(ctx, d, cur, u, eventUpdated, ReasonDeleted)

		return err
	}

	// Enqueued first: a deleted identity cannot be announced after; the
	// event is published once the identity is gone, discarded if it never
	// goes.
	if err := s.outbox.Enqueue(ctx, message(eventDeleted, "deleted-"+cur.ID,
		identityPayload{IdentityID: cur.ID}, cur.ID)); err != nil {
		return fmt.Errorf("%w: %w", errUnavailable, err)
	}

	if err := s.kratos.DeleteIdentity(ctx, cur.ID); err != nil && !ory.IsNotFound(err) {
		return kratosFailure(err)
	}

	return nil
}

// Find is the directory's users matching f; none without a filter (Kratos
// cannot list a directory's identities, only look them up).
func (s Service) Find(ctx context.Context, d Directory, f Filter) ([]ory.Identity, error) {
	var (
		candidates []ory.Identity
		err        error
	)

	switch {
	case f.ExternalID != "":
		candidates, err = s.list(ctx, credential(d.Provider, f.ExternalID))
	case f.UserName != "":
		var id ory.Identity

		id, err = s.kratos.GetIdentityByExternalID(ctx, externalID(d.ID, f.UserName))

		switch {
		case err == nil:
			candidates = []ory.Identity{id}
		case ory.IsNotFound(err):
			err = nil
		}
	case f.Email != "":
		candidates, err = s.list(ctx, f.Email)
	}

	if err != nil {
		return nil, kratosFailure(err)
	}

	out := make([]ory.Identity, 0, len(candidates))

	for i := range candidates {
		if r, ok := stored(candidates[i]); ok && r.Directory == d.ID && matches(r.User, f) {
			out = append(out, candidates[i])
		}
	}

	return out, nil
}

// matches reports whether u satisfies every comparison of f.
func matches(u User, f Filter) bool {
	name, _ := u.String("userName")
	ext, _ := u.String("externalId")

	return (f.UserName == "" || strings.EqualFold(name, f.UserName)) &&
		(f.ExternalID == "" || ext == f.ExternalID) &&
		(f.Email == "" || strings.EqualFold(u.Email(), f.Email))
}

func (s Service) list(ctx context.Context, identifier string) ([]ory.Identity, error) {
	page, err := s.kratos.ListIdentities(ctx, ory.IdentityFilter{CredentialsIdentifier: identifier})
	if err != nil {
		return nil, fmt.Errorf("scim: list: %w", err)
	}

	return page.Items, nil
}

// byCredential is the identity holding the OIDC credential <provider>:<ext>.
func (s Service) byCredential(ctx context.Context, provider, ext string) (ory.Identity, bool, error) {
	items, err := s.list(ctx, credential(provider, ext))
	if err != nil {
		return ory.Identity{}, false, kratosFailure(err)
	}

	if len(items) == 0 {
		return ory.Identity{}, false, nil
	}

	return items[0], true, nil
}

// owned is the identity id when it is the directory's.
func (s Service) owned(ctx context.Context, d Directory, id string) (ory.Identity, error) {
	cur, err := s.kratos.GetIdentity(ctx, id)
	if ory.IsNotFound(err) {
		return ory.Identity{}, notFound()
	}

	if err != nil {
		return ory.Identity{}, kratosFailure(err)
	}

	if r, ok := stored(cur); !ok || r.Directory != d.ID {
		return ory.Identity{}, notFound()
	}

	return cur, nil
}

// kratosFailure turns a failed Kratos call into a SCIM refusal where it is
// the request's fault, keeping the cause otherwise.
func kratosFailure(err error) error {
	var e *ory.Error
	if errors.As(err, &e) {
		switch e.Status {
		case http.StatusNotFound:
			return notFound()
		case http.StatusConflict:
			return uniqueness(e.Error())
		case http.StatusBadRequest:
			return invalidValue(e.Error())
		}
	}

	return fmt.Errorf("scim: kratos: %w", err)
}

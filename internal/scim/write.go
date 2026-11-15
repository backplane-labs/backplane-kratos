package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

const inactive = "inactive"

// updateBody is Kratos's updateIdentityBody; credentials stay as they are.
type updateBody struct {
	SchemaID       string          `json:"schema_id"`
	Traits         json.RawMessage `json:"traits"`
	MetadataPublic json.RawMessage `json:"metadata_public,omitempty"`
	MetadataAdmin  json.RawMessage `json:"metadata_admin"`
	ExternalID     string          `json:"external_id"`
	State          string          `json:"state"`
}

// jsonPatch is one RFC 6902 operation.
type jsonPatch struct {
	Op    string          `json:"op"`
	Path  string          `json:"path"`
	Value json.RawMessage `json:"value"`
}

// write makes cur the directory's user u: one Kratos write carrying the
// change and its pending events (kind, and a state change for an active flag
// that moved, a deactivation for offReason), then flush. A user the directory
// already holds unchanged is only flushed.
func (s Service) write(ctx context.Context, d Directory, cur ory.Identity, u User, kind, offReason string) (
	ory.Identity, error,
) {
	r, mine := stored(cur)
	if mine {
		if err := keepExternalID(r.User, u); err != nil {
			return ory.Identity{}, err
		}
	}

	next := state(u.Active())
	moved := (cur.State == inactive) != (next == inactive)

	if mine && r.Directory == d.ID && r.User.Equal(u) && !moved {
		return s.flush(ctx, cur)
	}

	mapped, err := d.Map(u)
	if err != nil {
		return ory.Identity{}, err
	}

	pending := append(slices.Clone(r.Pending), Pending{Kind: kind, ID: eventID()})

	if moved {
		reason := ReasonReactivated
		if next == inactive {
			reason = offReason
		}

		pending = append(pending, Pending{Kind: kindState, Reason: reason, ID: eventID()})
	}

	meta, err := withRecord(cur.MetadataAdmin, record{Directory: d.ID, User: u, Pending: pending})
	if err != nil {
		return ory.Identity{}, err
	}

	public := mapped.MetadataPublic
	if public == nil {
		public = cur.MetadataPublic
	}

	name, _ := u.String("userName")

	raw, err := json.Marshal(updateBody{
		SchemaID: cur.SchemaID, Traits: mapped.Traits, MetadataPublic: public, MetadataAdmin: meta,
		ExternalID: externalID(d.ID, name), State: next,
	})
	if err != nil {
		return ory.Identity{}, fmt.Errorf("scim: update body: %w", err)
	}

	updated, err := s.kratos.UpdateIdentity(ctx, cur.ID, raw)
	if err != nil {
		return ory.Identity{}, kratosFailure(err)
	}

	return s.flush(ctx, updated)
}

// keepExternalID refuses a change of externalId (it is the OIDC credential
// the identity was linked with) and keeps it when u leaves it out.
func keepExternalID(was, u User) error {
	old, _ := was.String("externalId")
	if old == "" {
		return nil
	}

	now, ok := u.String("externalId")

	switch {
	case !ok || now == "":
		u["externalId"] = was["externalId"]
	case now != old:
		return refuse(http.StatusBadRequest, "mutability", "externalId links the user to their OIDC login and cannot change")
	}

	return nil
}

// flush publishes cur's pending events and clears them. A deactivation ends
// every session before it is published: Kratos's state alone keeps them.
func (s Service) flush(ctx context.Context, cur ory.Identity) (ory.Identity, error) {
	r, ok := stored(cur)
	if !ok || len(r.Pending) == 0 {
		return cur, nil
	}

	if cur.State == inactive && slices.ContainsFunc(r.Pending, func(p Pending) bool { return p.Kind == kindState }) {
		if err := s.kratos.DeleteIdentitySessions(ctx, cur.ID); err != nil && !ory.IsNotFound(err) {
			return ory.Identity{}, fmt.Errorf("%w: sessions: %w", errUnavailable, err)
		}
	}

	for _, p := range r.Pending {
		if err := s.events.Publish(ctx, cur, r.Directory, p); err != nil {
			return ory.Identity{}, fmt.Errorf("%w: %w", errUnavailable, err)
		}
	}

	r.Pending = nil

	meta, err := withRecord(cur.MetadataAdmin, r)
	if err != nil {
		return ory.Identity{}, err
	}

	patch, err := json.Marshal([]jsonPatch{{Op: "replace", Path: "/metadata_admin", Value: meta}})
	if err != nil {
		return ory.Identity{}, fmt.Errorf("scim: patch: %w", err)
	}

	out, err := s.kratos.PatchIdentity(ctx, cur.ID, patch)
	if err != nil {
		return ory.Identity{}, fmt.Errorf("%w: clear pending: %w", errUnavailable, err)
	}

	return out, nil
}

package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/outbox"
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

// write makes cur the directory's user u in Kratos (a user the directory
// already holds unchanged is not written again), then announces it: kind
// when it was written, and the identity's state (a deactivation for
// offReason).
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
		return s.announce(ctx, d, cur, "", offReason, false)
	}

	mapped, err := d.Map(u)
	if err != nil {
		return ory.Identity{}, err
	}

	meta, err := withRecord(cur.MetadataAdmin, record{Directory: d.ID, User: u})
	if err != nil {
		return ory.Identity{}, fmt.Errorf("scim: metadata: %w", err)
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

	return s.announce(ctx, d, updated, kind, offReason, moved)
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

// identityPayload is what an identity event's message keeps.
type identityPayload struct {
	IdentityID string `json:"identity_id"`
}

// statePayload is what an IdentityStateChanged message keeps.
type statePayload struct {
	IdentityID string `json:"identity_id"`
	Directory  string `json:"directory"`
	State      string `json:"state"`
	Reason     string `json:"reason"`
}

// reactivatedAfter is how long after its creation a state change of an
// active identity is a reactivation, not the creation itself.
const reactivatedAfter = time.Second

// announce enqueues what the directory did to id, as Kratos holds it now:
// kind (IdentityCreated or IdentityUpdated, none when nothing was written),
// and its state — a deactivation (for offReason) once its sessions are
// deleted, or a reactivation (this request moved it, or one before did). The ids come from the identity's versions, so
// the IdP's retry after a failure enqueues the same messages again, which
// are no second event; a failure is errUnavailable, for the IdP to retry.
func (s Service) announce(ctx context.Context, d Directory, id ory.Identity, kind, offReason string, moved bool) (
	ory.Identity, error,
) {
	var msgs []outbox.Message

	switch kind {
	case eventCreated:
		msgs = append(msgs, message(eventCreated, "created-"+id.ID, identityPayload{IdentityID: id.ID}, id.ID))
	case eventUpdated:
		msgs = append(msgs, message(eventUpdated, "updated-"+id.ID+"-"+stamp(id.UpdatedAt),
			identityPayload{IdentityID: id.ID}, id.ID))
	}

	switch {
	case id.State == inactive:
		// Kratos's state alone keeps the sessions: they end before the
		// deactivation is announced, on every request (deleting none is
		// harmless).
		if err := s.kratos.DeleteIdentitySessions(ctx, id.ID); err != nil && !ory.IsNotFound(err) {
			return ory.Identity{}, fmt.Errorf("%w: sessions: %w", errUnavailable, err)
		}

		msgs = append(msgs, s.stateMessage(d, id, offReason))
	case moved || reactivated(id):
		msgs = append(msgs, s.stateMessage(d, id, ReasonReactivated))
	}

	for i := range msgs {
		if err := s.outbox.Enqueue(ctx, msgs[i]); err != nil {
			return ory.Identity{}, fmt.Errorf("%w: %w", errUnavailable, err)
		}
	}

	return id, nil
}

// reactivated: an active identity whose state changed after its creation —
// how a retry, which moves nothing itself, tells a reactivation.
func reactivated(id ory.Identity) bool {
	return id.State != inactive && id.StateChangedAt != nil && id.CreatedAt != nil &&
		id.StateChangedAt.Sub(*id.CreatedAt) > reactivatedAfter
}

func (s Service) stateMessage(d Directory, id ory.Identity, reason string) outbox.Message {
	return message(eventState, "state-"+id.ID+"-"+id.State+"-"+stamp(id.StateChangedAt),
		statePayload{IdentityID: id.ID, Directory: d.ID, State: id.State, Reason: reason}, id.ID)
}

// message is an outbox message of topic, its id named by key, ordered by the
// identity.
func message(topic, key string, payload any, identityID string) outbox.Message {
	raw, err := json.Marshal(payload)
	if err != nil {
		raw = []byte("{}")
	}

	return outbox.Message{
		ID: outbox.ID("scim-" + key), Topic: topic, PartitionKey: identityID, Payload: raw,
		ContentType: "application/json",
	}
}

// stamp is a version time as part of a message key.
func stamp(t *time.Time) string {
	if t == nil {
		return "0"
	}

	return t.UTC().Format(time.RFC3339Nano)
}

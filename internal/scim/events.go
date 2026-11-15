package scim

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/outbox"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// ByDirectory is the `by` of the events a directory causes.
const ByDirectory = "directory"

// IdentityEvent is kratos.IdentityCreated/Updated/Deleted.
type IdentityEvent = *kratoseventsv1.IdentityEvent

// StateChanged is kratos.IdentityStateChanged.
type StateChanged = *kratoseventsv1.IdentityStateChanged

// Directories are the corporate directories the configuration lists: their
// SCIM endpoints over Kratos, and the events they cause. Created, updated and
// deleted are the identity events the activities declare; the state change
// is declared here.
type Directories struct {
	deps.Component

	dirs   config.Live[[]Directory]
	tokens config.Live[map[string]config.Secret]
	kratos Kratos
	svc    Service

	created, updated, deleted event.Ref[IdentityEvent]
	state                     event.Ref[StateChanged]
}

// New declares kratos.IdentityStateChanged under parent; the directories
// dirs, authenticated by tokens (by directory id), provision through kratos,
// keep their events in box and publish them on created, updated, deleted
// and the state change.
func New(
	parent deps.Scope, dirs config.Live[[]Directory], tokens config.Live[map[string]config.Secret], kratos Kratos,
	box Outbox, created, updated, deleted event.Ref[IdentityEvent],
) *Directories {
	e := &Directories{
		Component: deps.NewComponent(parent, "directories"), dirs: dirs, tokens: tokens, kratos: kratos,
		created: created, updated: updated, deleted: deleted,
	}
	e.svc = NewService(kratos, box)
	e.register(box)
	e.state = event.Declare[StateChanged](e, "IdentityStateChanged",
		event.Describe("a corporate directory (SCIM) deactivated, reactivated or deleted an identity; "+
			"a deactivation has ended every session"))

	return e
}

// StateEvent is the declared kratos.IdentityStateChanged.
func (e *Directories) StateEvent() event.Ref[StateChanged] { return e.state }

// Topics of a directory's events.
const (
	eventCreated = "IdentityCreated"
	eventUpdated = "IdentityUpdated"
	eventDeleted = "IdentityDeleted"
	eventState   = "IdentityStateChanged"
)

// register makes box publish the directories' events.
func (e *Directories) register(box Outbox) {
	box.Register(eventCreated, func(ctx context.Context, m outbox.Message) error {
		return e.publishIdentity(ctx, e.created, m)
	})
	box.Register(eventUpdated, func(ctx context.Context, m outbox.Message) error {
		return e.publishIdentity(ctx, e.updated, m)
	})
	box.Register(eventDeleted, e.publishDeleted)
	box.Register(eventState, e.publishState)
}

// publishIdentity publishes the identity of m as Kratos holds it now; one
// deleted since is published with its id only.
func (e *Directories) publishIdentity(ctx context.Context, ref event.Ref[IdentityEvent], m outbox.Message) error {
	var p identityPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return outbox.Permanent(fmt.Errorf("scim: %s payload: %w", m.Topic, err))
	}

	payload := &kratoseventsv1.IdentityEvent{IdentityId: p.IdentityID, By: ByDirectory}

	id, err := e.kratos.GetIdentity(ctx, p.IdentityID)

	switch {
	case err == nil:
		payload = identityEvent(id)
	case !ory.IsNotFound(err):
		return fmt.Errorf("scim: read identity: %w", err)
	}

	return e.wrap(ref.Publish(ctx, payload, event.Key(p.IdentityID), event.ID(m.ID)))
}

// publishState publishes a state change; every session of a deactivated
// identity is deleted again first (the request deleted them already).
func (e *Directories) publishState(ctx context.Context, m outbox.Message) error {
	var p statePayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return outbox.Permanent(fmt.Errorf("scim: state payload: %w", err))
	}

	if p.State == inactive {
		if err := e.kratos.DeleteIdentitySessions(ctx, p.IdentityID); err != nil && !ory.IsNotFound(err) {
			return fmt.Errorf("scim: sessions: %w", err)
		}
	}

	return e.wrap(e.state.Publish(ctx, &kratoseventsv1.IdentityStateChanged{
		IdentityId: p.IdentityID, State: p.State, By: ByDirectory, Directory: p.Directory, Reason: p.Reason,
	}, event.Key(p.IdentityID), event.ID(m.ID)))
}

// publishDeleted publishes a deletion once the identity is gone; one that
// never goes is discarded.
func (e *Directories) publishDeleted(ctx context.Context, m outbox.Message) error {
	var p identityPayload
	if err := json.Unmarshal(m.Payload, &p); err != nil {
		return outbox.Permanent(fmt.Errorf("scim: deleted payload: %w", err))
	}

	_, err := e.kratos.GetIdentity(ctx, p.IdentityID)

	switch {
	case err == nil:
		return outbox.Happened(m, time.Time{}, time.Now())
	case !ory.IsNotFound(err):
		return fmt.Errorf("scim: read identity: %w", err)
	}

	return e.wrap(e.deleted.Publish(ctx, &kratoseventsv1.IdentityEvent{IdentityId: p.IdentityID, By: ByDirectory},
		event.Key(p.IdentityID), event.ID(m.ID)))
}

func (e *Directories) wrap(err error) error {
	if err != nil {
		return fmt.Errorf("scim: publish: %w", err)
	}

	return nil
}

func identityEvent(id ory.Identity) IdentityEvent {
	return &kratoseventsv1.IdentityEvent{
		IdentityId: id.ID, SchemaId: id.SchemaID, Traits: events.Traits(id.Traits), By: ByDirectory,
	}
}

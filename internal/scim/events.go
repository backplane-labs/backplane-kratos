package scim

import (
	"context"
	"fmt"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
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
	svc    Service

	created, updated, deleted event.Ref[IdentityEvent]
	state                     event.Ref[StateChanged]
}

// New declares kratos.IdentityStateChanged under parent; the directories
// dirs, authenticated by tokens (by directory id), provision through kratos
// and publish the identity events on created, updated and deleted.
func New(
	parent deps.Scope, dirs config.Live[[]Directory], tokens config.Live[map[string]config.Secret], kratos Kratos,
	created, updated, deleted event.Ref[IdentityEvent],
) *Directories {
	e := &Directories{
		Component: deps.NewComponent(parent, "directories"), dirs: dirs, tokens: tokens,
		created: created, updated: updated, deleted: deleted,
	}
	e.svc = NewService(kratos, e)
	e.state = event.Declare[StateChanged](e, "IdentityStateChanged",
		event.Describe("a corporate directory (SCIM) deactivated, reactivated or deleted an identity; "+
			"a deactivation has ended every session"))

	return e
}

// StateEvent is the declared kratos.IdentityStateChanged.
func (e *Directories) StateEvent() event.Ref[StateChanged] { return e.state }

// Publish publishes p about id for directory dir.
func (e *Directories) Publish(ctx context.Context, id ory.Identity, dir string, p Pending) error {
	opts := []event.PublishOption{event.Key(id.ID), event.ID(p.ID)}

	var err error

	switch p.Kind {
	case kindCreated:
		err = e.created.Publish(ctx, identityEvent(id), opts...)
	case kindUpdated:
		err = e.updated.Publish(ctx, identityEvent(id), opts...)
	default:
		err = e.state.Publish(ctx, &kratoseventsv1.IdentityStateChanged{
			IdentityId: id.ID, State: id.State, By: ByDirectory, Directory: dir, Reason: p.Reason,
		}, opts...)
	}

	if err != nil {
		return fmt.Errorf("scim: publish %s: %w", p.Kind, err)
	}

	return nil
}

// PublishDeleted publishes kratos.IdentityDeleted for an identity about to be
// deleted.
func (e *Directories) PublishDeleted(ctx context.Context, id ory.Identity) error {
	err := e.deleted.Publish(ctx, &kratoseventsv1.IdentityEvent{IdentityId: id.ID, By: ByDirectory},
		event.Key(id.ID), event.ID("scim-deleted-"+id.ID))
	if err != nil {
		return fmt.Errorf("scim: publish deleted: %w", err)
	}

	return nil
}

func identityEvent(id ory.Identity) IdentityEvent {
	return &kratoseventsv1.IdentityEvent{
		IdentityId: id.ID, SchemaId: id.SchemaID, Traits: events.Traits(id.Traits), By: ByDirectory,
	}
}

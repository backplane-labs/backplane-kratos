package flows

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/event"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/outbox"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// Outbox keeps the security events until the broker took them (README,
// Security events).
type Outbox interface {
	Register(topic string, p outbox.Publisher)
	Enqueue(ctx context.Context, m outbox.Message) error
}

// settingsEntry is a pending SettingsChanged: the event as it is known
// before the change, and the identity's version, credentials and addresses
// it is compared with once Kratos stored it.
type settingsEntry struct {
	Event json.RawMessage `json:"event"`
	// Version is the identity's updated_at before the change: Kratos
	// stored the change once its updated_at moved past it.
	Version     time.Time   `json:"version"`
	Credentials credentials `json:"credentials"`
	Addresses   []address   `json:"addresses"`
}

// RecordMessage is shown when a change is refused because its security
// event cannot be recorded.
const RecordMessage = 5000002

// register makes the outbox publish the security events.
func (f *Flows) register() {
	for _, flow := range []string{overlay.FlowLogin, overlay.FlowRegistration, overlay.FlowRecovery} {
		ref := f.events[flow]
		f.box.Register(eventName(flow), func(ctx context.Context, m outbox.Message) error {
			var flowEvent kratoseventsv1.FlowEvent
			if err := protojson.Unmarshal(m.Payload, &flowEvent); err != nil {
				return outbox.Permanent(fmt.Errorf("flows: %s payload: %w", m.Topic, err))
			}

			return wrapPublish(ref.Publish(ctx, &flowEvent, event.Key(flowEvent.GetIdentityId()), event.ID(m.ID)))
		})
	}

	f.box.Register(eventName(overlay.FlowSettings), f.publishSettings)
}

func wrapPublish(err error) error {
	if err != nil {
		return fmt.Errorf("flows: publish: %w", err)
	}

	return nil
}

// publishSettings publishes a SettingsChanged once Kratos stored its change
// (the identity's updated_at moved past the one before it; one it never
// stored is discarded), completed with what the change did: the credentials
// and addresses now against the ones before.
func (f *Flows) publishSettings(ctx context.Context, m outbox.Message) error {
	var entry settingsEntry
	if err := json.Unmarshal(m.Payload, &entry); err != nil {
		return outbox.Permanent(fmt.Errorf("flows: settings payload: %w", err))
	}

	var flowEvent kratoseventsv1.FlowEvent
	if err := protojson.Unmarshal(entry.Event, &flowEvent); err != nil {
		return outbox.Permanent(fmt.Errorf("flows: settings event: %w", err))
	}

	now, err := f.sessions.GetIdentity(ctx, flowEvent.GetIdentityId(), CredentialTypes()...)
	if err != nil {
		return fmt.Errorf("flows: read identity: %w", err)
	}

	stored := now.UpdatedAt != nil && now.UpdatedAt.After(entry.Version)
	if err := outbox.Happened(m, stored, time.Now()); err != nil {
		return err
	}

	after := credentialsOf(now)
	flowEvent.Traits = events.Traits(now.Traits)
	flowEvent.Changes = diffCredentials(entry.Credentials, after)
	flowEvent.Credentials = after.types()
	flowEvent.Addresses = diffAddresses(entry.Addresses, addressesOf(now))

	return wrapPublish(f.events[overlay.FlowSettings].Publish(ctx, &flowEvent,
		event.Key(flowEvent.GetIdentityId()), event.ID(m.ID)))
}

// security is the settings hook Kratos waits for before it stores a change:
// it reads the identity as it is and enqueues SettingsChanged, so the change
// is never stored without its event; one that cannot be enqueued is refused.
func (f *Flows) security(w http.ResponseWriter, r *http.Request) {
	start, point, method := time.Now(), "security/settings", r.PathValue("method")

	c, _, err := decode(r)
	if err != nil {
		f.record(point, start, "bad_request", err)
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	var id struct {
		ID       string          `json:"id"`
		SchemaID string          `json:"schema_id"`
		Traits   json.RawMessage `json:"traits"`
	}

	if json.Unmarshal(c.Identity, &id) != nil || id.ID == "" {
		f.record(point, start, "no_identity", nil)
		writeJSON(w, http.StatusOK, map[string]any{})

		return
	}

	if err := f.enqueueSettings(r.Context(), c, id.ID, id.SchemaID, method); err != nil {
		f.Log().Ctx().Warn(r.Context(), "settings change refused: its event cannot be recorded",
			xlog.String("identity", id.ID), xlog.Err(err))
		f.record(point, start, "refused", err)

		writeJSON(w, http.StatusBadRequest,
			(&Deny{Messages: []Message{{ID: RecordMessage, Text: unavailableText}}}).kratos())

		return
	}

	f.record(point, start, "enqueued", nil)
	writeJSON(w, http.StatusOK, map[string]any{})
}

// enqueueSettings enqueues SettingsChanged of this flow and method, with the
// identity's credentials and addresses before the change.
func (f *Flows) enqueueSettings(ctx context.Context, c kratosCtx, identityID, schemaID, method string) error {
	cur, err := f.sessions.GetIdentity(ctx, identityID, CredentialTypes()...)
	if err != nil {
		return fmt.Errorf("flows: read identity: %w", err)
	}

	flowEvent := &kratoseventsv1.FlowEvent{
		IdentityId: identityID, SchemaId: schemaID, Method: method, FlowId: c.Flow.ID,
		TransientPayload: events.Traits(c.Flow.TransientPayload),
	}

	if c.Session != nil {
		flowEvent.Session = sessionEvent(*c.Session)
		if c.Session.Identity != nil {
			flowEvent.PreviousTraits = events.Traits(c.Session.Identity.Traits)
		}
	}

	raw, err := protojson.Marshal(flowEvent)
	if err != nil {
		return fmt.Errorf("flows: settings event: %w", err)
	}

	entry := settingsEntry{Event: raw, Credentials: credentialsOf(cur), Addresses: addressesOf(cur)}
	if cur.UpdatedAt != nil {
		entry.Version = *cur.UpdatedAt
	}

	payload, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("flows: settings entry: %w", err)
	}

	return f.box.Enqueue(ctx, outbox.Message{
		ID: outbox.ID("settings-" + c.Flow.ID + "-" + method), Topic: eventName(overlay.FlowSettings),
		PartitionKey: identityID, Payload: payload, ContentType: contentJSON,
	})
}

// enqueueSession enqueues flowEvent, the event of a stored session: its id is
// the session's, so the front and the flow's callback enqueue one message.
func (f *Flows) enqueueSession(ctx context.Context, name string, flowEvent FlowEvent) error {
	payload, err := protojson.Marshal(flowEvent)
	if err != nil {
		return fmt.Errorf("flows: %s event: %w", name, err)
	}

	return f.box.Enqueue(ctx, outbox.Message{
		ID: outbox.ID(name + "-" + flowEvent.GetSession().GetId()), Topic: name,
		PartitionKey: flowEvent.GetIdentityId(), Payload: payload, ContentType: contentJSON,
	})
}

// recordIssued writes the event of a session the answer issues (LoggedIn,
// Registered, Recovered) into the identity's outbox before its credential
// leaves; one that cannot be written refuses the client and revokes the
// session.
func (f *Flows) recordIssued(ctx context.Context, a *answerOf, iss issuance, session ory.Session, errorURL string) {
	if session.Identity == nil {
		return
	}

	flowEvent := &kratoseventsv1.FlowEvent{
		IdentityId: session.Identity.ID, SchemaId: session.Identity.SchemaID, Method: lastMethod(session),
		FlowId: iss.flowID, Traits: events.Traits(session.Identity.Traits), TransientPayload: events.Traits(iss.transient),
		Session: sessionEvent(session),
	}

	if err := f.enqueueSession(ctx, eventName(iss.kind), flowEvent); err != nil {
		f.Log().Ctx().Warn(ctx, "new session refused: its event cannot be recorded", xlog.String("session", session.ID),
			xlog.Err(err))
		f.refuse(ctx, a, session.ID, errorURL, refusal{
			id: errUnavailable, status: http.StatusServiceUnavailable, reason: "unavailable",
			messages: []Message{{ID: UnavailableMessage, Text: unavailableText}},
		})

		return
	}
}

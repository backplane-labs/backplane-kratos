// Package outbox keeps the events that must not be lost in PostgreSQL
// (gopherex/pg-outbox) until the broker took them: an event is enqueued
// before the change it reports is done, and the publisher of its topic
// checks in Kratos that the change happened before it publishes — an event
// of a change that never happened is discarded, never published.
package outbox

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/postgres"
	"github.com/google/uuid"

	pgoutbox "github.com/gopherex/pg-outbox"
	"github.com/gopherex/xlog"
)

// Schema is the PostgreSQL schema of the outbox's tables.
const Schema = "backplane_kratos"

// maxAttempts is never reached in practice: an event waits as long as the
// broker is down (the backoff is capped at 30s), it is not dead-lettered.
const maxAttempts = 1 << 30

// retention is how long a published message's row is kept.
const retention = 24 * time.Hour

// Message is an event waiting for the broker.
type Message = pgoutbox.Message

// Publisher publishes the message of its topic; it returns an outcome of
// Happened when the change it reports is not (yet) in Kratos.
type Publisher func(ctx context.Context, m Message) error

// ID is the message id of an event named by key: the same key is the same
// message, so enqueueing it again is no second event.
func ID(key string) string {
	return uuid.NewSHA1(uuid.NewSHA1(uuid.NameSpaceURL, []byte("backplane-kratos/outbox")), []byte(key)).String()
}

// Migrations are the outbox's tables, applied by the postgres dependency in
// Schema.
func Migrations() fs.FS { return pgoutbox.MigrationsFS() }

// Outbox enqueues messages and relays them to their topic's publisher.
type Outbox struct {
	deps.Component

	// off: a service without events; nothing is enqueued or relayed.
	off        bool
	db         deps.Dependency[*postgres.DB]
	schema     string
	publishers map[string]Publisher
	instance   string

	once  sync.Once
	relay *pgoutbox.Outbox
	err   error
}

// New is the outbox under parent in db, its tables in schema (Schema; the
// tests give each run its own).
func New(parent deps.Scope, db deps.Dependency[*postgres.DB], schema string) *Outbox {
	host, _ := os.Hostname()

	return &Outbox{
		Component: deps.NewComponent(parent, "outbox"), db: db, schema: schema, publishers: map[string]Publisher{},
		instance: host + "-" + uuid.NewString(),
	}
}

// Off is the outbox of a service without events: nothing is enqueued.
func Off() *Outbox { return &Outbox{off: true, publishers: map[string]Publisher{}} }

// Register makes p publish the messages of topic; it is called while the
// service is assembled, before it starts.
func (o *Outbox) Register(topic string, p Publisher) { o.publishers[topic] = p }

// ErrUnknownTopic: no publisher is registered for a message's topic.
var ErrUnknownTopic = errors.New("outbox: no publisher for the topic")

// Enqueue writes m; it is published once its publisher accepts it.
func (o *Outbox) Enqueue(ctx context.Context, m Message) error {
	if o.off {
		return nil
	}

	relay, err := o.get()
	if err != nil {
		return err
	}

	if err := relay.Enqueue(ctx, m); err != nil {
		return fmt.Errorf("outbox: enqueue %s: %w", m.Topic, err)
	}

	return nil
}

// Run relays the messages until ctx ends.
func (o *Outbox) Run(ctx context.Context) error {
	if o.off {
		return nil
	}

	relay, err := o.get()
	if err != nil {
		return err
	}

	if err := relay.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("outbox: relay: %w", err)
	}

	return nil
}

// get builds the relay on first use: the database is a dependency, ready
// only once the service runs.
func (o *Outbox) get() (*pgoutbox.Outbox, error) {
	o.once.Do(func() {
		db := o.db.Get()

		relay, err := pgoutbox.New(db.Pool, db.Pool, o,
			pgoutbox.WithSchema(o.schema), pgoutbox.WithInstanceID(o.instance),
			pgoutbox.WithListenPool(db.ListenPool()), pgoutbox.WithMaxAttempts(maxAttempts),
			pgoutbox.WithLogger(slog.New(xlog.NewSlogHandler(o.Log()))),
			pgoutbox.WithClearPayloadOnComplete(true), pgoutbox.WithRetention(retention),
		)
		if err != nil {
			o.err = fmt.Errorf("outbox: %w", err)

			return
		}

		o.relay = relay
	})

	return o.relay, o.err
}

// Publish publishes each message through its topic's publisher, settling
// each on its own outcome.
func (o *Outbox) Publish(ctx context.Context, msgs []Message) error {
	outcomes := make(map[string]error, len(msgs))

	for i := range msgs {
		publish, ok := o.publishers[msgs[i].Topic]
		if !ok {
			outcomes[msgs[i].ID] = Permanent(fmt.Errorf("%w: %s", ErrUnknownTopic, msgs[i].Topic))

			continue
		}

		outcomes[msgs[i].ID] = publish(pgoutbox.MessageContext(ctx, msgs[i]), msgs[i])
	}

	if err := pgoutbox.PerMessage(outcomes, nil); err != nil {
		return fmt.Errorf("outbox: %w", err)
	}

	return nil
}

// Permanent is a message that can never be published (its payload does not
// read): it goes to the dead letters at once.
func Permanent(err error) error { return fmt.Errorf("outbox: %w", pgoutbox.Permanent(err)) }

const (
	// verifyWindow is how long a message waits for the change it reports to
	// appear in Kratos before it is discarded as one that never happened.
	verifyWindow = 2 * time.Minute
	// recheck is how soon a message is tried again while its change is not
	// in Kratos yet.
	recheck = 2 * time.Second
)

var (
	// ErrNotYet: the change a message reports is not in Kratos (yet).
	ErrNotYet = errors.New("outbox: the change is not in Kratos yet")
	// ErrNeverStored: the change a message reports never appeared in Kratos.
	ErrNeverStored = errors.New("outbox: the change was never stored in Kratos")
)

// Happened decides a message from whether Kratos holds the change it
// reports (read by its publisher from Kratos's own versions, never from
// clocks): published when it does, else tried again while the message is
// young and discarded once it is old — a change that was never stored.
func Happened(m Message, happened bool, now time.Time) error {
	if happened {
		return nil
	}

	if now.Sub(m.CreatedAt) < verifyWindow {
		return fmt.Errorf("outbox: %w", pgoutbox.RetryAfter(ErrNotYet, recheck))
	}

	return fmt.Errorf("outbox: %w", pgoutbox.Discard(ErrNeverStored))
}

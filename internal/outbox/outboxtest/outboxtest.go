// Package outboxtest is an outbox in memory for the tests of the outbox's
// users: messages are enqueued (once per id, as pg-outbox dedupes) and
// published when the test says so, with pg-outbox's outcomes.
package outboxtest

import (
	"context"
	"errors"
	"sync"
	"time"

	pgoutbox "github.com/gopherex/pg-outbox"

	"github.com/backplane-labs/backplane-kratos/internal/outbox"
)

// Memory is an outbox in memory.
type Memory struct {
	mu         sync.Mutex
	publishers map[string]outbox.Publisher
	pending    []outbox.Message
	seen       map[string]bool
	fail       error
}

// New is an empty outbox.
func New() *Memory {
	return &Memory{publishers: map[string]outbox.Publisher{}, seen: map[string]bool{}}
}

// Register makes p publish the messages of topic.
func (m *Memory) Register(topic string, p outbox.Publisher) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.publishers[topic] = p
}

// Fail makes Enqueue fail with err (nil: succeed again).
func (m *Memory) Fail(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.fail = err
}

// Enqueue keeps msg, stamped now; an id enqueued before is no new message.
func (m *Memory) Enqueue(_ context.Context, msg outbox.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.fail != nil {
		return m.fail
	}

	if m.seen[msg.ID] {
		return nil
	}

	m.seen[msg.ID] = true
	msg.CreatedAt = time.Now()
	m.pending = append(m.pending, msg)

	return nil
}

// Pending are the messages not published yet, in order.
func (m *Memory) Pending() []outbox.Message {
	m.mu.Lock()
	defer m.mu.Unlock()

	return append([]outbox.Message(nil), m.pending...)
}

// Publish publishes every pending message in order: a published or
// discarded one goes, one to retry stays; the first failure is returned.
func (m *Memory) Publish(ctx context.Context) error {
	m.mu.Lock()
	msgs := append([]outbox.Message(nil), m.pending...)
	publishers := m.publishers
	m.mu.Unlock()

	var (
		kept  []outbox.Message
		first error
	)

	for i := range msgs {
		publish, ok := publishers[msgs[i].Topic]
		if !ok {
			return outbox.ErrUnknownTopic
		}

		err := publish(ctx, msgs[i])

		var discarded *pgoutbox.DiscardError

		switch {
		case err == nil, errors.As(err, &discarded):
		default:
			kept = append(kept, msgs[i])

			if first == nil {
				first = err
			}
		}
	}

	m.mu.Lock()
	m.pending = kept
	m.mu.Unlock()

	return first
}

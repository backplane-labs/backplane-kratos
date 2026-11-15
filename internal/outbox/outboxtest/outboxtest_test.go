package outboxtest_test

import (
	"context"
	"errors"
	"testing"
	"time"

	pgoutbox "github.com/gopherex/pg-outbox"

	"github.com/backplane-labs/backplane-kratos/internal/outbox"
	"github.com/backplane-labs/backplane-kratos/internal/outbox/outboxtest"
)

func TestMemory(t *testing.T) {
	t.Parallel()

	m := outboxtest.New()
	outcome := map[string]error{
		"done": nil, "later": pgoutbox.RetryAfter(errors.New("not yet"), time.Second),
		"never": pgoutbox.Discard(errors.New("no")),
	}
	m.Register("T", func(_ context.Context, msg outbox.Message) error { return outcome[msg.ID] })

	for _, id := range []string{"done", "later", "never", "done"} {
		if err := m.Enqueue(t.Context(), outbox.Message{ID: id, Topic: "T"}); err != nil {
			t.Fatal(err)
		}
	}

	if len(m.Pending()) != 3 {
		t.Fatalf("an id enqueued twice is one message: %d", len(m.Pending()))
	}

	if err := m.Publish(t.Context()); err == nil || len(m.Pending()) != 1 || m.Pending()[0].ID != "later" {
		t.Fatalf("Publish: %v, pending %+v", err, m.Pending())
	}

	m.Fail(errors.New("database down"))

	if err := m.Enqueue(t.Context(), outbox.Message{ID: "x", Topic: "T"}); err == nil {
		t.Fatal("a failing outbox enqueues nothing")
	}
}

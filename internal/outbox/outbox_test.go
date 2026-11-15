package outbox_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/postgres"

	pgoutbox "github.com/gopherex/pg-outbox"

	"github.com/backplane-labs/backplane-kratos/internal/outbox"
)

func TestID(t *testing.T) {
	t.Parallel()

	first, again := outbox.ID("LoggedIn-s1"), outbox.ID("LoggedIn-s1")
	if first != again || outbox.ID("a") == outbox.ID("b") {
		t.Fatal("ids must be the same for one key and differ for two")
	}
}

func TestHappened(t *testing.T) {
	t.Parallel()

	created := time.Unix(1_800_000_000, 0)
	m := outbox.Message{CreatedAt: created}

	tests := []struct {
		name     string
		happened bool
		now      time.Time
		want     string // published, retry, discard
	}{
		{name: "happened", happened: true, now: created, want: "published"},
		{name: "happened, old", happened: true, now: created.Add(time.Hour), want: "published"},
		{name: "not yet, young", now: created.Add(time.Second), want: "retry"},
		{name: "never, old", now: created.Add(time.Hour), want: "discard"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := outbox.Happened(m, tc.happened, tc.now)

			var (
				retry   *pgoutbox.RetryAfterError
				discard *pgoutbox.DiscardError
			)

			got := "published"

			switch {
			case errors.As(err, &retry):
				got = "retry"
			case errors.As(err, &discard):
				got = "discard"
			case err != nil:
				got = err.Error()
			}

			if got != tc.want {
				t.Fatalf("Happened = %s, want %s", got, tc.want)
			}
		})
	}
}

func TestPublishRoutesByTopic(t *testing.T) {
	t.Parallel()

	h := backplanetest.New(t)
	box := outbox.New(h.Root(), deps.Dependency[*postgres.DB]{}, outbox.Schema)

	var got []string

	box.Register("A", func(_ context.Context, m outbox.Message) error {
		got = append(got, m.ID)

		return nil
	})

	err := box.Publish(t.Context(), []outbox.Message{{ID: "1", Topic: "A"}, {ID: "2", Topic: "Unknown"}})

	var batch *pgoutbox.BatchError
	if !errors.As(err, &batch) || len(got) != 1 || got[0] != "1" {
		t.Fatalf("Publish: %v, published %v", err, got)
	}

	var permanent *pgoutbox.PermanentError
	if !errors.As(batch.Outcomes["2"], &permanent) || batch.Outcomes["1"] != nil {
		t.Fatalf("outcomes %+v", batch.Outcomes)
	}
}

func TestOff(t *testing.T) {
	t.Parallel()

	off := outbox.Off()
	off.Register("A", nil)

	if err := off.Enqueue(t.Context(), outbox.Message{}); err != nil || off.Run(t.Context()) != nil {
		t.Fatal("an outbox that is off enqueues and relays nothing")
	}
}

func BenchmarkID(b *testing.B) {
	for b.Loop() {
		_ = outbox.ID("LoggedIn-7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d")
	}
}

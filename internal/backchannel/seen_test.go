package backchannel_test

import (
	"strconv"
	"testing"
	"time"

	"github.com/backplane-labs/backplane-kratos/internal/backchannel"
)

func TestSeen(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	s := backchannel.NewSeen()

	tests := []struct {
		name string
		id   string
		at   time.Time
		want bool
	}{
		{name: "unknown", id: "b", at: now, want: false},
		{name: "recorded", id: "a", at: now, want: true},
		{name: "until its token expires", id: "a", at: now.Add(time.Minute - time.Second), want: true},
		{name: "forgotten after", id: "a", at: now.Add(time.Minute), want: false},
	}

	s.Add("a", now.Add(time.Minute), now)

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := s.Has(tc.id, tc.at); got != tc.want {
				t.Fatalf("has(%s) = %v", tc.id, got)
			}
		})
	}
}

func TestSeenBounded(t *testing.T) {
	t.Parallel()

	now := time.Unix(1_800_000_000, 0)
	s := backchannel.NewSeen()

	for i := range backchannel.MaxSeen + 10 {
		s.Add(strconv.Itoa(i), now.Add(time.Hour+time.Duration(i)*time.Second), now)
	}

	if s.Len() > backchannel.MaxSeen || s.Has("0", now) || !s.Has(strconv.Itoa(backchannel.MaxSeen+9), now) {
		t.Fatalf("%d ids kept; the soonest to expire must go first", s.Len())
	}
}

func BenchmarkSeen(b *testing.B) {
	now := time.Unix(1_800_000_000, 0)
	s := backchannel.NewSeen()

	for i := 0; b.Loop(); i++ {
		id := strconv.Itoa(i % backchannel.MaxSeen)
		if !s.Has(id, now) {
			s.Add(id, now.Add(time.Minute), now)
		}
	}
}

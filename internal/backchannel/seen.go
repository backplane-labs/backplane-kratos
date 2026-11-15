package backchannel

import (
	"sync"
	"time"
)

// maxSeen bounds the token ids remembered; past it the expired ones go,
// then the oldest.
const maxSeen = 10_000

// seen remembers token ids until their tokens expire, so a replica ignores
// a repeat.
type seen struct {
	mu  sync.Mutex
	ids map[string]time.Time // id -> expiry
}

func newSeen() *seen { return &seen{ids: map[string]time.Time{}} }

// has reports whether id was recorded and its token has not expired at now.
func (s *seen) has(id string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	until, ok := s.ids[id]

	return ok && now.Before(until)
}

// add records id until exp.
func (s *seen) add(id string, exp, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.ids) >= maxSeen {
		s.prune(now)
	}

	s.ids[id] = exp
}

// prune drops expired ids, and the soonest to expire while still full.
func (s *seen) prune(now time.Time) {
	for id, until := range s.ids {
		if !now.Before(until) {
			delete(s.ids, id)
		}
	}

	for len(s.ids) >= maxSeen {
		var (
			oldest string
			at     time.Time
		)

		for id, until := range s.ids {
			if oldest == "" || until.Before(at) {
				oldest, at = id, until
			}
		}

		delete(s.ids, oldest)
	}
}

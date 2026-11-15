package backchannel

import (
	"context"
	"net/http"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// MaxSeen is maxSeen.
const MaxSeen = maxSeen

// Seen is seen.
type Seen struct{ s *seen }

// NewSeen is newSeen.
func NewSeen() Seen { return Seen{s: newSeen()} }

// Has is seen.has.
func (s Seen) Has(id string, now time.Time) bool { return s.s.has(id, now) }

// Add is seen.add.
func (s Seen) Add(id string, exp, now time.Time) { s.s.add(id, exp, now) }

// Len is the number of ids remembered.
func (s Seen) Len() int {
	s.s.mu.Lock()
	defer s.s.mu.Unlock()

	return len(s.s.ids)
}

// Keys is keys.
type Keys struct{ k *keys }

// NewKeys is newKeys.
func NewKeys(client *http.Client) Keys { return Keys{k: newKeys(client)} }

// Get is keys.get.
func (k Keys) Get(ctx context.Context, url, kid string, now time.Time) (jose.JSONWebKeySet, error) {
	return k.k.get(ctx, url, kid, now)
}

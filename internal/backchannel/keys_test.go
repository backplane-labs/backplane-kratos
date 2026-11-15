package backchannel_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"

	"github.com/backplane-labs/backplane-kratos/internal/backchannel"
)

func TestKeys(t *testing.T) {
	t.Parallel()

	var (
		fetches atomic.Int32
		down    atomic.Bool
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)

		if down.Load() {
			w.WriteHeader(http.StatusBadGateway)

			return
		}

		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{KeyID: "k1", Key: []byte("x")}}})
	}))
	t.Cleanup(srv.Close)

	k := backchannel.NewKeys(srv.Client())
	now := time.Unix(1_800_000_000, 0)

	steps := []struct {
		name    string
		kid     string
		at      time.Time
		down    bool
		fetches int32
		err     bool
	}{
		{name: "first use fetches", kid: "k1", at: now, fetches: 1},
		{name: "cached", kid: "k1", at: now.Add(time.Minute), fetches: 1},
		{name: "unknown kid soon after: not again", kid: "k2", at: now.Add(10 * time.Second), fetches: 1},
		{name: "unknown kid later: fetched", kid: "k2", at: now.Add(time.Minute), fetches: 2},
		{name: "stale: fetched", kid: "k1", at: now.Add(20 * time.Minute), fetches: 3},
		{name: "IdP down: the cached set", kid: "k1", at: now.Add(40 * time.Minute), down: true, fetches: 4},
	}

	for _, s := range steps {
		down.Store(s.down)

		_, err := k.Get(t.Context(), srv.URL, s.kid, s.at)
		if (err != nil) != s.err || fetches.Load() != s.fetches {
			t.Fatalf("%s: err %v, fetches %d, want %d", s.name, err, fetches.Load(), s.fetches)
		}
	}

	down.Store(true)

	if _, err := backchannel.NewKeys(srv.Client()).Get(t.Context(), srv.URL, "k1", now); err == nil {
		t.Fatal("no keys and the IdP down must fail")
	}
}

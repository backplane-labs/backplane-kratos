package backchannel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

const (
	// keysFresh is how long a fetched key set is used as it is.
	keysFresh = 10 * time.Minute
	// refetchGap bounds how often a token with an unknown key fetches the set.
	refetchGap = 30 * time.Second
	// maxKeys bounds a key set's body.
	maxKeys = 1 << 20
)

// ErrKeys: the provider's key set cannot be fetched.
var ErrKeys = errors.New("backchannel: the provider's keys are unavailable")

// keys caches the providers' key sets by URL.
type keys struct {
	client *http.Client

	mu   sync.Mutex
	sets map[string]keySet
}

type keySet struct {
	set     jose.JSONWebKeySet
	fetched time.Time
}

func newKeys(client *http.Client) *keys { return &keys{client: client, sets: map[string]keySet{}} }

// get is the set at url holding kid: the cached one while fresh and holding
// it, else fetched again (at most every refetchGap for an unknown kid). The
// fetch runs outside the lock; a failed one keeps the cached set.
func (k *keys) get(ctx context.Context, url, kid string, now time.Time) (jose.JSONWebKeySet, error) {
	k.mu.Lock()
	cached, ok := k.sets[url]
	k.mu.Unlock()

	known := kid == "" || len(cached.set.Key(kid)) > 0
	if ok && now.Sub(cached.fetched) < keysFresh && (known || now.Sub(cached.fetched) < refetchGap) {
		return cached.set, nil
	}

	set, err := k.fetch(ctx, url)
	if err != nil {
		if ok {
			return cached.set, nil
		}

		return jose.JSONWebKeySet{}, err
	}

	k.mu.Lock()
	k.sets[url] = keySet{set: set, fetched: now}
	k.mu.Unlock()

	return set, nil
}

func (k *keys) fetch(ctx context.Context, url string) (jose.JSONWebKeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("%w: %w", ErrKeys, err)
	}

	res, err := k.client.Do(req)
	if err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("%w: %w", ErrKeys, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return jose.JSONWebKeySet{}, fmt.Errorf("%w: %s", ErrKeys, res.Status)
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(res.Body, maxKeys)).Decode(&set); err != nil {
		return jose.JSONWebKeySet{}, fmt.Errorf("%w: %w", ErrKeys, err)
	}

	return set, nil
}

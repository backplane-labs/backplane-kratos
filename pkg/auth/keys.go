package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/singleflight"
)

// keys caches a JWK set: the only cache of the package, of public keys, not
// of users. A verification never waits for the network but on the first
// use and on a kid it has not seen; a set older than maxAge is refetched in
// the background while the old one keeps verifying. A fetch that fails
// keeps the last good set.
type keys struct {
	url        string
	client     *http.Client
	maxAge     time.Duration
	minRefresh time.Duration
	now        func() time.Time

	group singleflight.Group

	mu        sync.RWMutex
	byKid     map[string]jose.JSONWebKey
	fetchedAt time.Time // the last good fetch
	triedAt   time.Time // the last attempt, good or not
	lastErr   error     // the last attempt's failure
}

func newKeys(url string, client *http.Client, maxAge, minRefresh time.Duration, now func() time.Time) *keys {
	return &keys{url: url, client: client, maxAge: maxAge, minRefresh: minRefresh, now: now}
}

// key returns the key named kid, fetching the set when it does not know
// it (at most once per minRefresh: tokens with a made-up kid do not drive
// the issuer).
func (k *keys) key(ctx context.Context, kid string) (jose.JSONWebKey, error) {
	k.mu.RLock()
	key, ok := k.byKid[kid]
	stale := k.now().Sub(k.fetchedAt) > k.maxAge
	k.mu.RUnlock()

	if ok {
		if stale {
			k.refreshInBackground(ctx)
		}

		return key, nil
	}

	if err := k.refresh(ctx); err != nil {
		return jose.JSONWebKey{}, err
	}

	k.mu.RLock()
	key, ok = k.byKid[kid]
	k.mu.RUnlock()

	if !ok {
		return jose.JSONWebKey{}, fmt.Errorf("%w: kid %q", ErrUnknownKey, kid)
	}

	return key, nil
}

// refresh fetches the set unless an attempt was made within minRefresh;
// concurrent callers share one fetch.
func (k *keys) refresh(ctx context.Context) error {
	if recent, err := k.tried(); recent {
		// Within minRefresh nothing is fetched again: a known set answers
		// as is, an unknown one with the failure that left it unknown.
		return err
	}

	// One fetch for every caller, not bound to the first caller's cancel.
	_, err, _ := k.group.Do("fetch", func() (any, error) {
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), fetchTimeout)
		defer cancel()

		return nil, k.fetch(fetchCtx)
	})

	return err //nolint:wrapcheck // fetch's own error
}

// tried reports whether an attempt was made within minRefresh and, when
// no set was ever fetched, why.
func (k *keys) tried() (bool, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if k.triedAt.IsZero() || k.now().Sub(k.triedAt) >= k.minRefresh {
		return false, nil
	}

	if k.byKid == nil {
		return true, k.lastErr
	}

	return true, nil
}

// refreshInBackground refetches without holding up the verification that
// noticed the set is old: the fetch outlives ctx's cancel.
func (k *keys) refreshInBackground(ctx context.Context) {
	if recent, _ := k.tried(); recent {
		return
	}

	go func() { _ = k.refresh(context.WithoutCancel(ctx)) }()
}

// fetchTimeout bounds a background fetch.
const fetchTimeout = 10 * time.Second

// maxSet bounds the set's size.
const maxSet = 1 << 20

func (k *keys) fetch(ctx context.Context) error {
	err := k.load(ctx)

	k.mu.Lock()
	k.triedAt, k.lastErr = k.now(), err
	k.mu.Unlock()

	return err
}

func (k *keys) load(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, http.NoBody)
	if err != nil {
		return fmt.Errorf("%w: keys: %w", ErrUnavailable, err)
	}

	res, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: keys: %w", ErrUnavailable, err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: keys: %s answered %s", ErrUnavailable, k.url, res.Status)
	}

	var set jose.JSONWebKeySet
	if err := json.NewDecoder(io.LimitReader(res.Body, maxSet)).Decode(&set); err != nil {
		return fmt.Errorf("%w: keys: %w", ErrUnavailable, err)
	}

	byKid := make(map[string]jose.JSONWebKey, len(set.Keys))

	for i := range set.Keys {
		key := &set.Keys[i]
		if key.KeyID == "" || !key.IsPublic() || (key.Use != "" && key.Use != "sig") {
			continue
		}

		byKid[key.KeyID] = *key
	}

	k.mu.Lock()
	k.byKid, k.fetchedAt = byKid, k.now()
	k.mu.Unlock()

	return nil
}

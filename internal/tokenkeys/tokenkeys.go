// Package tokenkeys is the session tokens' signing keys: the ones the
// configuration gives (token_key and settings.tokens.keys), or the ones
// backplane-kratos mints, keeps in NATS KV and rotates itself.
package tokenkeys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/go-jose/go-jose/v4"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// Set is the keys Kratos signs with and services verify with.
type Set struct {
	// Private is the private JWK tokens are signed with now; empty: no
	// tokens.
	Private string
	// Public are the public JWKs services verify with: the signing key's
	// first, then the next one and the earlier ones still verifying.
	Public []string
}

// Enabled reports whether tokens are signed.
func (s Set) Enabled() bool { return s.Private != "" }

// Source gives the current set and tells when it changes: the
// configured keys or the minted ones.
type Source struct {
	get   func() Set
	watch func(fn func())
}

// Get is the current set.
func (s Source) Get() Set { return s.get() }

// Watch calls fn when the set changes.
func (s Source) Watch(fn func()) { s.watch(fn) }

// NewConfigured is the configuration's set: token_key signs; Public is
// nil, the settings' tokens.keys verify as they render.
func NewConfigured(key config.Live[config.Secret], settings config.Live[overlay.Settings]) Source {
	return Source{
		get: func() Set { return Set{Private: key.Get().Reveal()} },
		watch: func(fn func()) {
			key.Watch(func(config.Secret) { fn() })
			settings.Watch(func(overlay.Settings) { fn() })
		},
	}
}

// key is one minted key as the store keeps it.
type key struct {
	Private json.RawMessage `json:"private"`
	Public  json.RawMessage `json:"public"`
	// Active is when it starts signing: a minted key is published first,
	// so every replica's JWKS holds it before a token carries it.
	Active time.Time `json:"active"`
}

// state is the minted keys, newest first.
type state struct {
	Keys []key `json:"keys"`
}

// signing is the index of the key signing at now: the newest active one.
func (s state) signing(now time.Time) int {
	for i, k := range s.Keys {
		if !k.Active.After(now) {
			return i
		}
	}

	return -1
}

// set is what the state signs and publishes at now.
func (s state) set(now time.Time) Set {
	i := s.signing(now)
	if i < 0 {
		return Set{}
	}

	out := Set{Private: string(s.Keys[i].Private), Public: make([]string, 0, len(s.Keys))}

	out.Public = append(out.Public, string(s.Keys[i].Public))
	for j, k := range s.Keys {
		if j != i {
			out.Public = append(out.Public, string(k.Public))
		}
	}

	return out
}

// Schedule is when keys rotate.
type Schedule struct {
	// Every is how long a key signs before the next one takes over.
	Every time.Duration
	// Propagation is how long a new key is published before it signs.
	Propagation time.Duration
	// TokenTTL is the longest a token lives: a key that stopped signing
	// is published that long after.
	TokenTTL time.Duration
}

// next is the state at now under s: a key minted when none signs or the
// signing one is due, keys whose tokens all expired dropped. changed is
// false when nothing is to do.
func (s state) next(now time.Time, schedule Schedule, mint func(active time.Time) (key, error)) (state, bool, error) {
	out := state{Keys: append([]key(nil), s.Keys...)}
	changed := false

	i := out.signing(now)
	due := i < 0 || i == 0 && !now.Before(out.Keys[0].Active.Add(schedule.Every))

	if due {
		active := now
		if i >= 0 {
			active = now.Add(schedule.Propagation)
		}

		k, err := mint(active)
		if err != nil {
			return state{}, false, err
		}

		out.Keys = append([]key{k}, out.Keys...)
		changed = true
		i = out.signing(now)
	}

	// A key older than the signing one stopped signing when its successor
	// became active; its tokens are gone a token lifetime later.
	keep := out.Keys[:0]

	for j, k := range out.Keys {
		if j > i && i >= 0 && !now.Before(out.Keys[j-1].Active.Add(schedule.TokenTTL)) {
			changed = true

			continue
		}

		keep = append(keep, k)
	}

	out.Keys = keep

	return out, changed, nil
}

// kidBytes is the random length of a minted key's id.
const kidBytes = 8

// mintKey is a fresh ES256 key signing from active.
func mintKey(active time.Time) (key, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return key{}, fmt.Errorf("tokenkeys: mint: %w", err)
	}

	id := make([]byte, kidBytes)
	if _, err := rand.Read(id); err != nil {
		return key{}, fmt.Errorf("tokenkeys: mint: %w", err)
	}

	jwk := jose.JSONWebKey{Key: private, KeyID: hex.EncodeToString(id), Algorithm: string(jose.ES256), Use: "sig"}

	priv, err := jwk.MarshalJSON()
	if err != nil {
		return key{}, fmt.Errorf("tokenkeys: mint: %w", err)
	}

	pub, err := jwk.Public().MarshalJSON()
	if err != nil {
		return key{}, fmt.Errorf("tokenkeys: mint: %w", err)
	}

	return key{Private: priv, Public: pub, Active: active}, nil
}

// watchers keeps the callbacks of a source.
type watchers struct {
	mu  sync.Mutex
	fns []func()
}

func (w *watchers) add(fn func()) {
	w.mu.Lock()
	defer w.mu.Unlock()

	w.fns = append(w.fns, fn)
}

func (w *watchers) notify() {
	w.mu.Lock()
	fns := append([]func(){}, w.fns...)
	w.mu.Unlock()

	for _, fn := range fns {
		fn()
	}
}

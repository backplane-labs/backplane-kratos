package tokenkeys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	infranats "github.com/backplane-labs/backplane/pkg/backplane/infra/nats"
	natsgo "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"

	"github.com/gopherex/xlog"
)

// Bucket keeps the minted keys. It holds private keys: only
// backplane-kratos's NATS identity may use $KV.kratos_token_keys.>.
const Bucket = "kratos_token_keys"

// entry is the bucket's one key: the whole state, updated by revision.
const entry = "set"

// check is how often a replica reads the state and rotates when due.
const check = 30 * time.Second

// Minted mints, keeps and rotates the keys in Bucket. Every replica runs
// it: a change is an update at the read revision, so of replicas racing
// one wins and the others read its state.
type Minted struct {
	deps.Component

	conn     deps.Dependency[*natsgo.Conn]
	cfg      infranats.Config
	replicas int
	schedule func() Schedule
	now      func() time.Time

	kv jetstream.KeyValue

	mu       sync.Mutex
	current  Set
	watchers watchers
}

// Source is the minted keys as the overlay, JWKS and console read them.
func (m *Minted) Source() Source { return Source{get: m.Get, watch: m.Watch} }

// NewMinted is the minted keys under parent, on conn (cfg its section),
// the bucket replicated replicas times, rotating as schedule says.
func NewMinted(
	parent deps.Scope, conn deps.Dependency[*natsgo.Conn], cfg infranats.Config, replicas int, schedule func() Schedule,
) *Minted {
	m := &Minted{
		Component: deps.NewComponent(parent, "token keys"), conn: conn, cfg: cfg, replicas: max(replicas, 1),
		schedule: schedule, now: time.Now,
	}
	m.OnStart(m.start)

	return m
}

// Get is the current set.
func (m *Minted) Get() Set {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.current
}

// Watch calls fn when the set changes.
func (m *Minted) Watch(fn func()) { m.watchers.add(fn) }

// start makes sure a key signs before the service serves, then keeps
// rotating.
func (m *Minted) start(ctx context.Context) error {
	if err := m.open(ctx); err != nil {
		return err
	}

	if err := m.tick(ctx); err != nil {
		return err
	}

	m.Go(func(ctx context.Context) error {
		ticker := time.NewTicker(check)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return nil
			case <-ticker.C:
				if err := m.tick(ctx); err != nil {
					m.Log().Ctx().Warn(ctx, "token keys: rotation check failed", xlog.Err(err))
				}
			}
		}
	})

	return nil
}

// open binds the bucket, creating it on the first start.
func (m *Minted) open(ctx context.Context) error {
	js, err := m.cfg.JetStream(m.conn.Get())
	if err != nil {
		return fmt.Errorf("tokenkeys: %w", err)
	}

	m.kv, err = js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: Bucket, Description: "Signing keys of backplane-kratos's session tokens", History: 1, Replicas: m.replicas,
	})
	if err != nil {
		return fmt.Errorf("tokenkeys: bucket: %w", err)
	}

	return nil
}

// tick reads the state, rotates it when due (one replica's update wins)
// and publishes the set.
func (m *Minted) tick(ctx context.Context) error {
	now := m.now()

	st, revision, err := read(ctx, m.kv)
	if err != nil {
		return err
	}

	next, changed, err := st.next(now, m.schedule(), mintKey)
	if err != nil {
		return err
	}

	if changed {
		if next, err = m.save(ctx, next, revision); err != nil {
			return err
		}
	}

	m.publish(next.set(now))

	return nil
}

// save writes next over revision; when another replica changed the state
// first, its state is the one taken.
func (m *Minted) save(ctx context.Context, next state, revision uint64) (state, error) {
	raw, err := json.Marshal(next)
	if err != nil {
		return state{}, fmt.Errorf("tokenkeys: %w", err)
	}

	if revision == 0 {
		_, err = m.kv.Create(ctx, entry, raw)
	} else {
		_, err = m.kv.Update(ctx, entry, raw, revision)
	}

	if err == nil {
		return next, nil
	}

	theirs, _, err := read(ctx, m.kv)

	return theirs, err
}

func read(ctx context.Context, kv jetstream.KeyValue) (state, uint64, error) {
	got, err := kv.Get(ctx, entry)

	switch {
	case errors.Is(err, jetstream.ErrKeyNotFound):
		return state{}, 0, nil
	case err != nil:
		return state{}, 0, fmt.Errorf("tokenkeys: read: %w", err)
	}

	var st state
	if err := json.Unmarshal(got.Value(), &st); err != nil {
		return state{}, 0, fmt.Errorf("tokenkeys: stored state: %w", err)
	}

	return st, got.Revision(), nil
}

func (m *Minted) publish(set Set) {
	m.mu.Lock()
	same := set.Private == m.current.Private && slices.Equal(set.Public, m.current.Public)
	m.current = set
	m.mu.Unlock()

	if !same {
		m.watchers.notify()
	}
}

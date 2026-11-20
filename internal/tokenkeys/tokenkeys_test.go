package tokenkeys_test

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	infranats "github.com/backplane-labs/backplane/pkg/backplane/infra/nats"
	"github.com/nats-io/nats-server/v2/server"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	"github.com/backplane-labs/backplane-kratos/internal/tokenkeys"
)

func jetStream(t *testing.T) string {
	t.Helper()

	srv, err := server.NewServer(&server.Options{
		Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), NoLog: true, NoSigs: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	go srv.Start()
	t.Cleanup(srv.Shutdown)

	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("nats server not ready")
	}

	return srv.ClientURL()
}

// clock is a settable time shared by the replicas.
type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) get() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *clock) add(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.now = c.now.Add(d) }

var schedule = tokenkeys.Schedule{Every: time.Hour, Propagation: 2 * time.Minute, TokenTTL: 5 * time.Minute}

func replica(t *testing.T, url string, c *clock) *tokenkeys.Minted {
	t.Helper()

	h := backplanetest.New(t)
	section := infranats.Config{URL: config.Secret(url)}
	conn := deps.NewDependency(h.Root(), infranats.New(section))
	m := tokenkeys.NewMinted(h.Root(), conn, section, 1, func() tokenkeys.Schedule { return schedule })
	m.SetClock(c.get)
	h.Start()

	return m
}

func kid(t *testing.T, jwk string) string {
	t.Helper()

	var k struct {
		Kid string `json:"kid"`
		D   string `json:"d"`
	}

	if err := json.Unmarshal([]byte(jwk), &k); err != nil {
		t.Fatal(err)
	}

	return k.Kid
}

func kids(t *testing.T, set tokenkeys.Set) []string {
	t.Helper()

	out := make([]string, 0, len(set.Public))
	for _, p := range set.Public {
		out = append(out, kid(t, p))
	}

	return out
}

// Replicas starting together sign with one key; on schedule a new key is
// published first, signs after the propagation, and the old one leaves the
// published set a token lifetime after it stopped signing.
func TestMintedKeysRotate(t *testing.T) {
	t.Parallel()

	url := jetStream(t)
	c := &clock{now: time.Date(2026, 11, 19, 0, 0, 0, 0, time.UTC)}

	a, b := replica(t, url, c), replica(t, url, c)
	first := a.Get()

	if !first.Enabled() || first.Private != b.Get().Private || len(first.Public) != 1 {
		t.Fatalf("replicas disagree or no key: %+v %+v", first, b.Get())
	}

	if _, err := overlay.PublicKeys(first.Public); err != nil {
		t.Fatalf("published keys: %v", err)
	}

	original := kid(t, first.Private)

	// The console reads where the key comes from, its id and when it hands over.
	if !first.Minted || first.Kid() != original || !first.RotatesAt.Equal(c.get().Add(schedule.Every)) {
		t.Fatalf("minted set = minted %v kid %q rotates %v", first.Minted, first.Kid(), first.RotatesAt)
	}

	// Due: a new key is published, the old one still signs.
	c.add(time.Hour)

	if err := a.Check(t.Context()); err != nil {
		t.Fatal(err)
	}

	if err := b.Check(t.Context()); err != nil {
		t.Fatal(err)
	}

	published := a.Get()
	if kid(t, published.Private) != original || len(published.Public) != 2 || published.Private != b.Get().Private {
		t.Fatalf("before propagation: signing %s, published %v", kid(t, published.Private), kids(t, published))
	}

	// After the propagation the new key signs; the old one still verifies.
	c.add(schedule.Propagation)

	if err := a.Check(t.Context()); err != nil {
		t.Fatal(err)
	}

	rotated := a.Get()
	if next := kid(t, rotated.Private); next == original || kids(t, rotated)[0] != next || len(rotated.Public) != 2 {
		t.Fatalf("after propagation: signing %s, published %v", next, kids(t, rotated))
	}

	// A token lifetime later the old key is gone.
	c.add(schedule.TokenTTL)

	if err := b.Check(t.Context()); err != nil {
		t.Fatal(err)
	}

	if got := kids(t, b.Get()); len(got) != 1 || got[0] == original {
		t.Fatalf("old key still published: %v", got)
	}
}

// A configured key is the set; its public keys are the settings'.
func TestConfigured(t *testing.T) {
	t.Parallel()

	src := tokenkeys.NewConfigured(config.LiveOf(config.Secret("private")), config.LiveOf(overlay.Settings{}))
	if set := src.Get(); set.Private != "private" || set.Public != nil || !set.Enabled() || set.Minted {
		t.Fatalf("set %+v", set)
	}

	if tokenkeys.NewConfigured(config.LiveOf(config.Secret("")), config.LiveOf(overlay.Settings{})).Get().Enabled() {
		t.Fatal("no key must mean no tokens")
	}
}

func TestSetKid(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name, private, want string
	}{
		{"jwk with kid", `{"kty":"EC","kid":"2026-11-20-ab"}`, "2026-11-20-ab"},
		{"jwk without kid", `{"kty":"EC"}`, ""},
		{"no key", "", ""},
		{"not json", "private", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := (tokenkeys.Set{Private: tc.private}).Kid(); got != tc.want {
				t.Fatalf("Kid = %q, want %q", got, tc.want)
			}
		})
	}
}

package backchannel_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/backplane-labs/backplane-kratos/internal/backchannel"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

// kratos plays the admin API: one identity per credential, the sessions
// deleted, and a failure on demand.
type kratos struct {
	mu       sync.Mutex
	byCred   map[string]string
	deleted  map[string]int
	failList atomic.Bool
}

func (k *kratos) ListIdentities(_ context.Context, f ory.IdentityFilter) (ory.Page[ory.Identity], error) {
	if k.failList.Load() {
		return ory.Page[ory.Identity]{}, &ory.Error{Status: http.StatusServiceUnavailable}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if id, ok := k.byCred[f.CredentialsIdentifier]; ok {
		return ory.Page[ory.Identity]{Items: []ory.Identity{{ID: id}}}, nil
	}

	return ory.Page[ory.Identity]{}, nil
}

func (k *kratos) DeleteIdentitySessions(_ context.Context, id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.deleted[id]++

	return nil
}

func (k *kratos) deletions(id string) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.deleted[id]
}

type receiver struct {
	h       *backplanetest.Harness
	k       *kratos
	revoked event.Ref[backchannel.SessionsRevoked]
	srv     *httptest.Server
	issuer  idp
	now     time.Time
	fetches *atomic.Int32
}

func setupReceiver(t *testing.T) *receiver {
	t.Helper()

	r := &receiver{
		h: backplanetest.New(t), issuer: newIdP(t), now: time.Unix(1_800_000_000, 0), fetches: &atomic.Int32{},
		k: &kratos{byCred: map[string]string{"corp:person-1": "identity-1"}, deleted: map[string]int{}},
	}

	jwks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		r.fetches.Add(1)
		_ = json.NewEncoder(w).Encode(r.issuer.set)
	}))
	t.Cleanup(jwks.Close)

	p := provider
	p.JWKSURL = jwks.URL

	r.revoked = event.Declare[backchannel.SessionsRevoked](r.h.Root(), "SessionsRevoked")
	rec := backchannel.New(r.h.Root(), config.LiveOf([]backchannel.Provider{p}), r.k, r.revoked, jwks.Client(),
		func() time.Time { return r.now })
	r.srv = httptest.NewServer(rec.Handler())
	t.Cleanup(r.srv.Close)
	r.h.Start()

	return r
}

func (r *receiver) post(t *testing.T, path, token string) (int, string) {
	t.Helper()

	form := url.Values{"logout_token": {token}}.Encode()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, r.srv.URL+path, strings.NewReader(form))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var body struct {
		Error string `json:"error"`
	}

	_ = json.NewDecoder(res.Body).Decode(&body)

	if res.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control %q", res.Header.Get("Cache-Control"))
	}

	return res.StatusCode, body.Error
}

func TestLogout(t *testing.T) {
	t.Parallel()

	r := setupReceiver(t)
	token := r.issuer.sign(t, "k1", claims(r.now, nil))

	if code, _ := r.post(t, backchannel.Path+"corp", token); code != http.StatusOK {
		t.Fatalf("logout: %d", code)
	}

	published := backplanetest.EventsWithMeta(r.h, r.revoked)
	if r.k.deletions("identity-1") != 1 || len(published) != 1 ||
		published[0].Value.GetBy() != backchannel.ByBackchannel || published[0].Key != "identity-1" {
		t.Fatalf("deletions %d, events %+v", r.k.deletions("identity-1"), published)
	}

	// A repeat on this replica is acknowledged and does nothing.
	if code, _ := r.post(t, backchannel.Path+"corp", token); code != http.StatusOK || r.k.deletions("identity-1") != 1 {
		t.Fatalf("repeat: %d, deletions %d", code, r.k.deletions("identity-1"))
	}

	// A person Kratos does not know is already signed out.
	stranger := r.issuer.sign(t, "k1", claims(r.now, map[string]any{"sub": "nobody", "jti": "jti-2"}))
	if code, _ := r.post(t, backchannel.Path+"corp", stranger); code != http.StatusOK {
		t.Fatalf("unknown person: %d", code)
	}

	if r.fetches.Load() != 1 {
		t.Fatalf("keys fetched %d times, want once", r.fetches.Load())
	}
}

func TestLogoutRefusals(t *testing.T) {
	t.Parallel()

	r := setupReceiver(t)

	tests := []struct {
		name, path, token string
		want              int
	}{
		{name: "no token", path: "corp", want: http.StatusBadRequest},
		{name: "forged", path: "corp", token: newIdP(t).sign(t, "k1", claims(r.now, nil)), want: http.StatusBadRequest},
		{
			name: "a login token", path: "corp",
			token: r.issuer.sign(t, "k1", claims(r.now, map[string]any{"events": nil, "nonce": "n"})),
			want:  http.StatusBadRequest,
		},
		{name: "unknown provider", path: "nope", token: r.issuer.sign(t, "k1", claims(r.now, nil)), want: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			code, errCode := r.post(t, backchannel.Path+tc.path, tc.token)
			if code != tc.want || (code == http.StatusBadRequest && errCode != "invalid_request") {
				t.Fatalf("%d %q, want %d", code, errCode, tc.want)
			}
		})
	}

	if r.k.deletions("identity-1") != 0 {
		t.Fatal("a refused token ended sessions")
	}
}

func TestLogoutRetriedAfterAFailure(t *testing.T) {
	t.Parallel()

	r := setupReceiver(t)
	token := r.issuer.sign(t, "k1", claims(r.now, nil))

	r.k.failList.Store(true)

	if code, _ := r.post(t, backchannel.Path+"corp", token); code != http.StatusServiceUnavailable {
		t.Fatalf("Kratos failing: %d", code)
	}

	r.k.failList.Store(false)
	backplanetest.FailPublish(r.h, errors.New("broker down"))

	if code, _ := r.post(t, backchannel.Path+"corp", token); code != http.StatusServiceUnavailable {
		t.Fatalf("broker failing: %d", code)
	}

	backplanetest.FailPublish(r.h, nil)

	if code, _ := r.post(t, backchannel.Path+"corp", token); code != http.StatusOK ||
		len(backplanetest.Events(r.h, r.revoked)) != 1 {
		t.Fatalf("retry: %d", code)
	}
}

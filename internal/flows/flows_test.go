package flows_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

const key = "test-key"

// harness serves the callbacks of a fresh Flows; failOpen names
// fail-open hooks.
func harness(t *testing.T, failOpen ...string) (*backplanetest.Harness, *flows.Flows, *httptest.Server) {
	t.Helper()

	return harnessWith(t, &sessions{}, failOpen...)
}

func harnessWith(
	t *testing.T, kratos *sessions, failOpen ...string,
) (*backplanetest.Harness, *flows.Flows, *httptest.Server) {
	t.Helper()

	h := backplanetest.New(t, backplanetest.Name("kratos"))
	f := flows.New(h.Root(), key, config.LiveOf(failOpen), kratos)
	h.Start()

	srv := httptest.NewServer(f.Handler())
	t.Cleanup(srv.Close)

	return h, f, srv
}

// sessions is Kratos's session store: it holds stored once asked after
// more than hidden times.
type sessions struct {
	mu     sync.Mutex
	hidden int
	asked  int
	stored []ory.Session

	// who answers WhoAmI (none: 401), after GetSession; seen are the
	// tokens and cookies WhoAmI was asked about.
	who   *ory.Session
	after ory.Session
	seen  []string

	// whoErr, when set, is WhoAmI's error; disabled are the revoked ids;
	// the first busy revokes fail as Kratos's concurrent update does.
	whoErr   error
	disabled []string
	busy     int
}

func (s *sessions) DisableSession(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.busy > 0 {
		s.busy--

		return &ory.Error{Status: http.StatusBadRequest}
	}

	s.disabled = append(s.disabled, id)

	return nil
}

func (s *sessions) revoked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	return append([]string(nil), s.disabled...)
}

func (s *sessions) WhoAmI(_ context.Context, token, cookie string) (ory.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.seen = append(s.seen, token+cookie)
	if s.whoErr != nil {
		return ory.Session{}, s.whoErr
	}

	if s.who == nil {
		return ory.Session{}, errNoSession
	}

	return *s.who, nil
}

func (s *sessions) GetSession(context.Context, string) (ory.Session, error) { return s.after, nil }

var errNoSession = &ory.Error{Status: http.StatusUnauthorized}

func (s *sessions) ListIdentitySessions(context.Context, string, ory.SessionFilter) (ory.Page[ory.Session], error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.asked++
	if s.asked <= s.hidden {
		return ory.Page[ory.Session]{}, nil
	}

	return ory.Page[ory.Session]{Items: s.stored}, nil
}

func post(t *testing.T, srv *httptest.Server, path, fixture string) (int, map[string]any) {
	t.Helper()

	body, err := os.ReadFile("testdata/" + fixture)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	req.SetBasicAuth(overlay.KeyUser, key)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var out map[string]any

	_ = json.NewDecoder(res.Body).Decode(&out)

	return res.StatusCode, out
}

// The courier's message reaches Deliver with the code and link split out
// of Kratos's template data.
func TestDeliver(t *testing.T) {
	t.Parallel()

	h, f, srv := harness(t)

	var got flows.DeliverIn

	backplanetest.Answer(h, f.DeliverRef(), func(_ context.Context, in flows.DeliverIn) (flows.DeliverOut, error) {
		got = in

		return flows.DeliverOut{}, nil
	})

	if code, _ := post(t, srv, "/courier/email", "courier_verification.json"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	if got.Channel != "email" || got.Recipient != "a@example.com" || got.TemplateType != "verification_code_valid" ||
		got.Code != "998072" || !strings.Contains(got.Link, "code=998072") || got.ExpiresInMinutes != 60 ||
		len(got.Identity) == 0 || !strings.Contains(got.Rendered.Subject, "998072") {
		t.Fatalf("deliver input: %+v", got)
	}

	if bytes.Contains(got.Data, []byte("998072")) {
		t.Fatalf("the code leaked into data: %s", got.Data)
	}
}

// A failed delivery answers 502: Kratos keeps the message and retries it.
func TestDeliverFailure(t *testing.T) {
	t.Parallel()

	h, f, srv := harness(t)

	backplanetest.Answer(h, f.DeliverRef(), func(context.Context, flows.DeliverIn) (flows.DeliverOut, error) {
		return flows.DeliverOut{}, errors.New("smtp down")
	})

	if code, _ := post(t, srv, "/courier/email", "courier_verification.json"); code != http.StatusBadGateway {
		t.Fatalf("status %d", code)
	}

	if stats := f.Stats(); len(stats) != 1 || stats[0].Failures != 1 || stats[0].LastError == "" {
		t.Fatalf("stats: %+v", stats)
	}
}

func TestFlowVerdicts(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		failOpen []string
		answer   func(flows.FlowIn) (flows.FlowOut, error)
		status   int
		check    func(t *testing.T, body map[string]any)
	}{
		{
			name: "continue", status: http.StatusOK,
			answer: func(flows.FlowIn) (flows.FlowOut, error) { return flows.FlowOut{}, nil },
			check: func(t *testing.T, body map[string]any) {
				t.Helper()

				if len(body) != 0 {
					t.Fatalf("body %v", body)
				}
			},
		},
		{
			name: "deny", status: http.StatusBadRequest,
			answer: func(flows.FlowIn) (flows.FlowOut, error) {
				return flows.FlowOut{Deny: &flows.Deny{Messages: []flows.Message{
					{Field: "traits.email", ID: 4000100, Text: "no"}, {Text: "whole form"},
				}}}, nil
			},
			check: func(t *testing.T, body map[string]any) {
				t.Helper()

				msgs, _ := body["messages"].([]any)
				first, _ := msgs[0].(map[string]any)
				second, _ := msgs[1].(map[string]any)

				if len(msgs) != 2 || first["instance_ptr"] != "#/traits/email" || second["instance_ptr"] != "#/" {
					t.Fatalf("messages %v", body)
				}
			},
		},
		{
			name: "change", status: http.StatusOK,
			answer: func(flows.FlowIn) (flows.FlowOut, error) {
				return flows.FlowOut{
					Identity: &flows.IdentityPatch{MetadataPublic: json.RawMessage(`{"tier":"gold"}`)},
				}, nil
			},
			check: func(t *testing.T, body map[string]any) {
				t.Helper()

				if _, ok := body["identity"]; !ok {
					t.Fatalf("body %v", body)
				}
			},
		},
		{
			name: "fail closed", status: http.StatusBadRequest,
			answer: func(flows.FlowIn) (flows.FlowOut, error) { return flows.FlowOut{}, errors.New("down") },
			check: func(t *testing.T, body map[string]any) {
				t.Helper()

				if !strings.Contains(mustJSON(t, body), "unavailable") {
					t.Fatalf("body %v", body)
				}
			},
		},
		{
			name: "fail open", status: http.StatusOK, failOpen: []string{"AfterRegistration"},
			answer: func(flows.FlowIn) (flows.FlowOut, error) { return flows.FlowOut{}, errors.New("down") },
			check:  func(*testing.T, map[string]any) {},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, f, srv := harness(t, tc.failOpen...)

			var got flows.FlowIn

			backplanetest.Answer(h, f.Point("AfterRegistration"),
				func(_ context.Context, in flows.FlowIn) (flows.FlowOut, error) {
					got = in

					return tc.answer(in)
				})

			code, body := post(t, srv, "/hooks/after/registration/password", "after_registration.json")
			if code != tc.status {
				t.Fatalf("status %d, want %d: %v", code, tc.status, body)
			}

			tc.check(t, body)

			if got.Flow != "registration" || got.Method != "password" || got.FlowID == "" || len(got.Identity) == 0 {
				t.Fatalf("flow input: %+v", got)
			}

			for k := range got.RequestHeaders {
				if strings.EqualFold(k, "cookie") {
					t.Fatal("cookies reached the hook")
				}
			}
		})
	}
}

// The acting session reaches the hook whole; one Kratos has not stored yet
// (after login) carries no id.
func TestFlowSession(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, point, path, fixture string
		check                      func(t *testing.T, s ory.Session)
	}{
		{
			name: "settings: the stored session", point: "BeforeSettings",
			path: "/hooks/before/settings/" + overlay.GenericMethod, fixture: "before_settings.json",
			check: func(t *testing.T, s ory.Session) {
				t.Helper()

				if s.ID != "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d" || !s.Active || s.AuthenticatorAssuranceLevel != "aal2" ||
					s.AuthenticatedAt == nil || s.ExpiresAt == nil || len(s.AuthenticationMethods) != 2 ||
					s.AuthenticationMethods[1].Method != "totp" || s.AuthenticationMethods[1].CompletedAt == nil ||
					len(s.Devices) != 1 || s.Devices[0].IPAddress != "203.0.113.9" {
					t.Fatalf("session %+v", s)
				}
			},
		},
		{
			name: "login: not stored yet, no id", point: "AfterLogin",
			path: "/hooks/after/login/password", fixture: "after_login.json",
			check: func(t *testing.T, s ory.Session) {
				t.Helper()

				if s.ID != "" || s.AuthenticatorAssuranceLevel != "aal1" || len(s.Devices) != 1 || s.Devices[0].ID != "" ||
					s.Devices[0].IPAddress != "203.0.113.7" {
					t.Fatalf("session %+v", s)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h, f, srv := harness(t)

			var got flows.FlowIn

			backplanetest.Answer(h, f.Point(tc.point), func(_ context.Context, in flows.FlowIn) (flows.FlowOut, error) {
				got = in

				return flows.FlowOut{}, nil
			})

			if code, body := post(t, srv, tc.path, tc.fixture); code != http.StatusOK {
				t.Fatalf("status %d: %v", code, body)
			}

			if got.Session.IsZero() {
				t.Fatal("no session")
			}

			tc.check(t, got.Session)

			if raw := mustJSON(t, got); strings.Contains(raw, "ory_kratos_session") {
				t.Fatal("the session cookie reached the hook")
			}
		})
	}
}

// An unbound point lets the flow continue without calling backplane.
func TestFlowUnbound(t *testing.T) {
	t.Parallel()

	_, f, srv := harness(t)

	code, body := post(t, srv, "/hooks/after/login/password", "after_registration.json")
	if code != http.StatusOK || len(body) != 0 {
		t.Fatalf("unbound: %d %v", code, body)
	}

	if f.Bound("AfterLogin") {
		t.Fatal("AfterLogin is bound")
	}
}

// Completed flows publish their event.
func TestFlowEvent(t *testing.T) {
	t.Parallel()

	h, f, srv := harness(t)

	if code, _ := post(t, srv, "/events/registration/password", "after_registration.json"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	events := backplanetest.Events(h, f.Event("registration"))
	if len(events) != 1 || events[0].GetIdentityId() == "" || events[0].GetMethod() != "password" ||
		events[0].GetPreviousTraits() != nil {
		t.Fatalf("events: %+v", events)
	}
}

// SettingsChanged carries the traits before the change, from the
// signed-in session.
func TestSettingsChangedPrevious(t *testing.T) {
	t.Parallel()

	h, f, srv := harness(t)

	if code, _ := post(t, srv, "/events/settings/profile", "after_settings.json"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	events := backplanetest.Events(h, f.Event("settings"))
	if len(events) != 1 {
		t.Fatalf("events: %+v", events)
	}

	if was, is := events[0].GetPreviousTraits().GetFields()["email"].GetStringValue(),
		events[0].GetTraits().GetFields()["email"].GetStringValue(); was != "old@example.com" || is != "new@example.com" {
		t.Fatalf("previous %q, traits %q", was, is)
	}
}

// LoggedIn waits for Kratos to store the login's session and carries it.
func TestLoggedInAfterSessionStored(t *testing.T) {
	t.Parallel()

	authenticated := time.Date(2026, 10, 24, 3, 35, 4, 320712000, time.UTC)
	other := authenticated.Add(-time.Hour)
	kratos := &sessions{hidden: 2, stored: []ory.Session{
		{ID: "older", AuthenticatedAt: &other},
		{ID: "stored", AuthenticatedAt: &authenticated},
	}}

	h, f, srv := harnessWith(t, kratos)

	if code, _ := post(t, srv, "/events/login/password", "after_login.json"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	var events []flows.FlowEvent

	for deadline := time.Now().Add(5 * time.Second); len(events) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)

		events = backplanetest.Events(h, f.Event("login"))
	}

	if len(events) != 1 {
		t.Fatalf("events: %+v", events)
	}

	s := events[0].GetSession()
	if s.GetId() != "stored" || !s.GetAuthenticatedAt().AsTime().Equal(authenticated) || s.GetAal() != "aal1" ||
		s.GetIpAddress() != "203.0.113.7" || s.GetUserAgent() != "test-agent" {
		t.Fatalf("session: %+v", s)
	}

	if qr := events[0].GetTransientPayload().GetFields()["qr"].GetStringValue(); qr != "q-1" {
		t.Fatalf("transient payload: %+v", events[0].GetTransientPayload())
	}
}

// Recovered waits for the session the recovery signed in with, stored
// after the hooks: one authenticated by a recovery method since the flow
// began, not an older recovery's nor a password login's.
func TestRecoveredAfterSessionStored(t *testing.T) {
	t.Parallel()

	issued := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	before, after := issued.Add(-time.Hour), issued.Add(3*time.Second)
	recovery := []ory.AuthenticationMethod{{Method: "code_recovery", AAL: "aal1"}}
	kratos := &sessions{hidden: 2, stored: []ory.Session{
		{ID: "older recovery", AuthenticatedAt: &before, AuthenticationMethods: recovery},
		{ID: "password", AuthenticatedAt: &after, AuthenticationMethods: []ory.AuthenticationMethod{{Method: "password"}}},
		{ID: "recovered", AuthenticatedAt: &after, AuthenticationMethods: recovery, AuthenticatorAssuranceLevel: "aal1"},
	}}

	h, f, srv := harnessWith(t, kratos)

	if code, _ := post(t, srv, "/events/recovery/any", "after_recovery.json"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}

	var events []flows.FlowEvent

	for deadline := time.Now().Add(5 * time.Second); len(events) == 0 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)

		events = backplanetest.Events(h, f.Event("recovery"))
	}

	if len(events) != 1 || events[0].GetSession().GetId() != "recovered" || events[0].GetSession().GetAal() != "aal1" {
		t.Fatalf("events: %+v", events)
	}
}

// Without Basic kratos:<key> nothing is served.
func TestKeyRequired(t *testing.T) {
	t.Parallel()

	_, _, srv := harness(t)

	tests := []struct {
		name           string
		user, password string
		basic          bool
	}{
		{name: "no credentials"},
		{name: "wrong key", user: overlay.KeyUser, password: "not-the-key", basic: true},
		{name: "wrong user", user: "admin", password: key, basic: true},
		{name: "empty key", user: overlay.KeyUser, basic: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			req, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL+"/courier/email",
				strings.NewReader("{}"))
			if tc.basic {
				req.SetBasicAuth(tc.user, tc.password)
			}

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}

			_ = res.Body.Close()

			if res.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status %d", res.StatusCode)
			}
		})
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return string(b)
}

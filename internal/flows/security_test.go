package flows_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/outbox"
	"github.com/backplane-labs/backplane-kratos/internal/outbox/outboxtest"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

const settingsIdentity = "0c1d2e3f-4a5b-4c6d-8e7f-901a2b3c4d5e"

func credential(kind, config string, identifiers ...string) ory.Credentials {
	return ory.Credentials{Type: kind, Identifiers: identifiers, Config: json.RawMessage(config)}
}

func address(via, value string) ory.VerifiableAddress {
	return ory.VerifiableAddress{Via: via, Value: value, Status: "sent"}
}

// A settings change stages SettingsChanged into the change Kratos stores;
// once stored, it is published with what the change did.
func TestSettingsChangedStaged(t *testing.T) {
	t.Parallel()

	// The identity changed a moment ago (the login): a recent updated_at is
	// not this change.
	signedIn := time.Now()
	kratos := &sessions{}
	kratos.setIdentity(ory.Identity{
		ID: settingsIdentity, MetadataAdmin: json.RawMessage(`{"crm":7}`), UpdatedAt: &signedIn,
		Credentials: map[string]ory.Credentials{
			"password": credential("password", `{"hashed_password":"h1"}`, "old@example.com"),
			"oidc":     credential("oidc", `{"providers":[]}`, "google:1"),
		},
		VerifiableAddresses: []ory.VerifiableAddress{address("email", "old@example.com")},
	})

	b := outboxtest.New()
	h, f, srv := harnessBox(t, kratos, b)

	code, answer := post(t, srv, "/security/settings/password", "after_settings.json")
	if code != http.StatusOK || len(answer) != 0 {
		t.Fatalf("enqueue: %d %v", code, answer)
	}

	if e := b.Pending(); len(e) != 1 || e[0].Topic != "SettingsChanged" ||
		e[0].ID != outbox.ID("settings-6c8d2f3b-4e5a-4b7c-9d0e-1f2a3b4c5d6e-password") {
		t.Fatalf("enqueued %+v", e)
	}

	if err := b.Publish(t.Context()); !errors.Is(err, outbox.ErrNotYet) {
		t.Fatalf("publish before the change is stored: %v", err)
	}

	if got := backplanetest.Events(h, f.Event("settings")); len(got) != 0 || len(b.Pending()) != 1 {
		t.Fatalf("published before Kratos stored the change: %+v", got)
	}

	// Kratos stored the change: a new password, TOTP on, Google unlinked,
	// GitHub linked, the email changed.
	stored := signedIn.Add(time.Millisecond)
	after := ory.Identity{
		ID: settingsIdentity, SchemaID: "default", Traits: json.RawMessage(`{"email":"new@example.com"}`),
		UpdatedAt: &stored,
		Credentials: map[string]ory.Credentials{
			"password": credential("password", `{"hashed_password":"h2"}`, "new@example.com"),
			"totp":     credential("totp", `{"totp_url":"otpauth://x"}`),
			"oidc":     credential("oidc", `{"providers":[]}`, "github:9"),
		},
		VerifiableAddresses: []ory.VerifiableAddress{address("email", "new@example.com")},
	}
	kratos.setIdentity(after)

	if err := b.Publish(t.Context()); err != nil {
		t.Fatal(err)
	}

	got := backplanetest.Events(h, f.Event("settings"))
	if len(got) != 1 {
		t.Fatalf("events %+v", got)
	}

	ev := got[0]
	if ev.GetPreviousTraits().GetFields()["email"].GetStringValue() != "old@example.com" ||
		ev.GetTraits().GetFields()["email"].GetStringValue() != "new@example.com" ||
		ev.GetSession().GetId() != "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d" || ev.GetMethod() != "password" {
		t.Fatalf("event %+v", ev)
	}

	changes := make([]string, 0, len(ev.GetChanges()))
	for _, c := range ev.GetChanges() {
		changes = append(changes, c.GetType()+":"+c.GetChange()+":"+c.GetProvider())
	}

	want := []string{"oidc:added:github", "oidc:removed:google", "password:replaced:", "totp:added:"}
	if !slices.Equal(changes, want) {
		t.Fatalf("changes %v, want %v", changes, want)
	}

	if !slices.Equal(ev.GetCredentials(), []string{"oidc", "password", "totp"}) {
		t.Fatalf("credentials %v", ev.GetCredentials())
	}

	if a := ev.GetAddresses(); len(a) != 1 || a[0].GetPrevious() != "old@example.com" || a[0].GetCurrent() != "new@example.com" {
		t.Fatalf("addresses %+v", a)
	}
}

// A change whose event cannot be enqueued is refused, so it is never silent.
func TestSettingsChangeRefusedWhenItsEventCannotBeKept(t *testing.T) {
	t.Parallel()

	for _, fail := range []error{errors.New("database down")} {
		b := outboxtest.New()
		b.Fail(fail)
		_, _, srv := harnessBox(t, &sessions{}, b)

		if code, body := post(t, srv, "/security/settings/password", "after_settings.json"); code != http.StatusBadRequest ||
			!deniedWith(body, flows.RecordMessage) {
			t.Fatalf("%v: %d %s", fail, code, body)
		}
	}
}

// An issued session's event is in the outbox before its credential leaves,
// one per authentication step (a second factor on the same session is an
// event of its own); one that cannot be written refuses the client and
// revokes the session.
func TestIssuedSessionRecorded(t *testing.T) {
	t.Parallel()

	stepUp := stored()
	stepUp.AuthenticatorAssuranceLevel = "aal2"
	stepUp.AuthenticationMethods = append(stepUp.AuthenticationMethods,
		ory.AuthenticationMethod{Method: "lookup_secret", AAL: "aal2"})

	tests := []struct {
		name, kind, event, wantKey string
		session                    ory.Session
		fail                       error
		wantStatus                 int
	}{
		{
			name: "login", kind: "login", event: "LoggedIn", session: stored(), wantKey: "LoggedIn-s-1-1",
			wantStatus: http.StatusOK,
		},
		{
			name: "step-up", kind: "login", event: "LoggedIn", session: stepUp, wantKey: "LoggedIn-s-1-2",
			wantStatus: http.StatusOK,
		},
		{
			name: "registration", kind: "registration", event: "Registered", session: stored(),
			wantKey: "Registered-s-1-1", wantStatus: http.StatusOK,
		},
		{
			name: "not recorded", kind: "login", session: stored(), fail: errors.New("kratos down"),
			wantStatus: http.StatusServiceUnavailable,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kratos := &sessions{after: tc.session}
			b := outboxtest.New()
			b.Fail(tc.fail)
			_, f, _ := harnessBox(t, kratos, b)

			k := newKratos(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"session_token":"tok-1","session":{"id":"s-1","active":true}}`))
			})
			srv := public(t, f, k, "")

			r := do(t, http.MethodPost, srv.URL+"/self-service/"+tc.kind+"?flow=f-1", "application/json",
				`{"method":"password","transient_payload":{"qr":"q-1"}}`, nil)
			if r.status != tc.wantStatus {
				t.Fatalf("status %d %s", r.status, r.body)
			}

			if tc.fail != nil {
				if !slices.Contains(kratos.revoked(), "s-1") {
					t.Fatal("an unrecorded session must be revoked")
				}

				return
			}

			e := b.Pending()
			if len(e) != 1 || e[0].Topic != tc.event || e[0].ID != outbox.ID(tc.wantKey) {
				t.Fatalf("messages %+v", e)
			}

			var ev kratoseventsv1.FlowEvent
			if err := protojson.Unmarshal(e[0].Payload, &ev); err != nil {
				t.Fatal(err)
			}

			methods := ev.GetSession().GetAuthenticationMethods()
			if len(methods) != len(tc.session.AuthenticationMethods) || methods[0].GetMethod() != "password" ||
				ev.GetSession().GetAal() != tc.session.AuthenticatorAssuranceLevel ||
				ev.GetTransientPayload().GetFields()["qr"].GetStringValue() != "q-1" {
				t.Fatalf("event %+v", &ev)
			}
		})
	}
}

// deniedWith reports whether Kratos's deny answer carries a message with id.
func deniedWith(body map[string]any, id int64) bool {
	raw, err := json.Marshal(body)
	if err != nil {
		return false
	}

	return strings.Contains(string(raw), fmt.Sprintf(`"id":%d`, id))
}

// A session issued past the front is recorded once Kratos stored it: the
// login's, and a recovery's (authenticated by a recovery method since the
// flow began, not an older recovery's nor a password login's).
func TestStoredSessionRecorded(t *testing.T) {
	t.Parallel()

	authenticated := time.Date(2026, 10, 24, 3, 35, 4, 320712000, time.UTC)
	issued := time.Date(2026, 11, 10, 9, 0, 0, 0, time.UTC)
	before, after := issued.Add(-time.Hour), issued.Add(3*time.Second)
	older := authenticated.Add(-time.Hour)
	recovery := []ory.AuthenticationMethod{{Method: "code_recovery", AAL: "aal1"}}

	tests := []struct {
		name, path, fixture, event, wantKey string
		stored                              []ory.Session
	}{
		{
			name: "login", path: "/events/login/password", fixture: "after_login.json", event: "LoggedIn", wantKey: "LoggedIn-stored-0",
			stored: []ory.Session{{ID: "older", AuthenticatedAt: &older}, {ID: "stored", AuthenticatedAt: &authenticated}},
		},
		{
			name: "recovery", path: "/events/recovery/any", fixture: "after_recovery.json", event: "Recovered",
			wantKey: "Recovered-recovered-1",
			stored: []ory.Session{
				{ID: "older recovery", AuthenticatedAt: &before, AuthenticationMethods: recovery},
				{ID: "password", AuthenticatedAt: &after, AuthenticationMethods: []ory.AuthenticationMethod{{Method: "password"}}},
				{ID: "recovered", AuthenticatedAt: &after, AuthenticationMethods: recovery, AuthenticatorAssuranceLevel: "aal1"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			b := outboxtest.New()
			_, _, srv := harnessBox(t, &sessions{hidden: 2, stored: tc.stored}, b)

			if code, _ := post(t, srv, tc.path, tc.fixture); code != http.StatusOK {
				t.Fatalf("status %d", code)
			}

			var e []outbox.Message
			for deadline := time.Now().Add(5 * time.Second); len(e) == 0 && time.Now().Before(deadline); {
				time.Sleep(10 * time.Millisecond)

				e = b.Pending()
			}

			if len(e) != 1 || e[0].Topic != tc.event || e[0].ID != outbox.ID(tc.wantKey) {
				t.Fatalf("entries %+v", e)
			}
		})
	}
}

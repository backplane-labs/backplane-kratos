package it_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// passwordLogin is a password login's session token.
func passwordLogin(t *testing.T, email string) string {
	t.Helper()

	_, flow := call(t, http.MethodGet, "/self-service/login/api", nil)

	status, body := call(t, http.MethodPost, fmt.Sprintf("/self-service/login?flow=%v", flow["id"]),
		map[string]any{"method": "password", "identifier": email, "password": password})
	if status != http.StatusOK {
		t.Fatalf("login: %d %v", status, body)
	}

	token, _ := body["session_token"].(string)

	return token
}

// changePassword runs a settings flow with the session token.
func changePassword(t *testing.T, e env, token, next string) int {
	t.Helper()

	auth := http.Header{"X-Session-Token": {token}}

	_, settings := e.callAt(t, http.MethodGet, publicURL+"/self-service/settings/api", nil, auth)
	status, _ := e.callAt(t, http.MethodPost, fmt.Sprintf("%s/self-service/settings?flow=%v", publicURL, settings["id"]),
		map[string]any{"method": "password", "password": next}, auth)

	return status
}

func settingsEvents(e env, id string) []*kratoseventsv1.FlowEvent {
	var out []*kratoseventsv1.FlowEvent

	for _, ev := range backplanetest.Events(e.h, e.flows.Event(overlay.FlowSettings)) {
		if ev.GetIdentityId() == id {
			out = append(out, ev)
		}
	}

	return out
}

// TestSettingsSecurityEvent: a password change is reported as one, with
// the session that made it.
func TestSettingsSecurityEvent(t *testing.T) {
	t.Parallel()

	e := start(t, nil)
	email := unique("secure")
	id := e.newUser(t, email)
	token := passwordLogin(t, email)

	if status := changePassword(t, e, token, "Another-Long-Pass-456!y"); status != http.StatusOK {
		t.Fatalf("settings: %d", status)
	}

	waitFor(t, "SettingsChanged published", func() bool { return len(settingsEvents(e, id)) == 1 })

	ev := settingsEvents(e, id)[0]
	if len(ev.GetChanges()) != 1 || ev.GetChanges()[0].GetType() != "password" ||
		ev.GetChanges()[0].GetChange() != "replaced" || !slices.Contains(ev.GetCredentials(), "password") ||
		ev.GetSession().GetId() == "" || ev.GetSession().GetAuthenticationMethods()[0].GetMethod() != "password" ||
		ev.GetPreviousTraits().GetFields()["email"].GetStringValue() != email {
		t.Fatalf("event %+v", ev)
	}
}

// TestSecurityEventSurvivesBrokerDown: the broker down does not stop a
// change, and its event waits in Kratos until it can be published.
func TestSecurityEventSurvivesBrokerDown(t *testing.T) {
	t.Parallel()

	e := start(t, nil)
	email := unique("down")
	id := e.newUser(t, email)
	token := passwordLogin(t, email)

	backplanetest.FailPublish(e.h, errors.New("broker down"))

	if status := changePassword(t, e, token, "Another-Long-Pass-456!y"); status != http.StatusOK {
		t.Fatalf("settings with the broker down: %d", status)
	}

	if events := settingsEvents(e, id); len(events) != 0 {
		t.Fatalf("published with the broker down: %+v", events)
	}

	backplanetest.FailPublish(e.h, nil)

	// The relay retries with a backoff capped at 30s.
	waitLong(t, "SettingsChanged published once the broker is back", func() bool { return len(settingsEvents(e, id)) == 1 })

	if events := settingsEvents(e, id); events[0].GetChanges()[0].GetType() != "password" {
		t.Fatalf("events %+v", events)
	}
}

// waitLong is waitFor across the relay's longest backoff.
func waitLong(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(90 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not reached: %s", what)
		}

		time.Sleep(500 * time.Millisecond)
	}
}

// TestStepUpSecurityEvent: a backup code that steps a password session up to
// AAL2 is a LoggedIn of its own, with both methods and the new AAL.
func TestStepUpSecurityEvent(t *testing.T) {
	t.Parallel()

	e := startWith(t, func(s *overlay.Settings) { s.Methods.LookupSecret.Enabled = true }, nil)
	email := unique("stepup")
	id := e.newUser(t, email)
	token := passwordLogin(t, email)
	auth := http.Header{"X-Session-Token": {token}}

	_, settings := e.callAt(t, http.MethodGet, publicURL+"/self-service/settings/api", nil, auth)
	settingsURL := fmt.Sprintf("%s/self-service/settings?flow=%v", publicURL, settings["id"])

	status, generated := e.callAt(t, http.MethodPost, settingsURL,
		map[string]any{"method": "lookup_secret", "lookup_secret_regenerate": true}, auth)
	codes := lookupCodes(generated)

	if status != http.StatusOK || len(codes) == 0 {
		t.Fatalf("regenerate: %d %v", status, generated)
	}

	if confirmed, body := e.callAt(t, http.MethodPost, settingsURL,
		map[string]any{"method": "lookup_secret", "lookup_secret_confirm": true}, auth); confirmed != http.StatusOK {
		t.Fatalf("confirm: %d %v", confirmed, body)
	}

	_, login := e.callAt(t, http.MethodGet, publicURL+"/self-service/login/api?aal=aal2&refresh=true", nil, auth)
	if stepped, body := e.callAt(t, http.MethodPost, fmt.Sprintf("%s/self-service/login?flow=%v", publicURL, login["id"]),
		map[string]any{"method": "lookup_secret", "lookup_secret": codes[0]}, auth); stepped != http.StatusOK {
		t.Fatalf("step-up: %d %v", stepped, body)
	}

	logins := func() []*kratoseventsv1.FlowEvent {
		var out []*kratoseventsv1.FlowEvent

		for _, ev := range backplanetest.Events(e.h, e.flows.Event(overlay.FlowLogin)) {
			if ev.GetIdentityId() == id {
				out = append(out, ev)
			}
		}

		return out
	}

	waitFor(t, "both LoggedIn published", func() bool { return len(logins()) == 2 })

	// Kratos may list the second factor more than once; the step is one
	// event all the same (the front and the callback agree on it).
	first, second := logins()[0], logins()[1]
	methods := second.GetSession().GetAuthenticationMethods()

	if first.GetSession().GetId() != second.GetSession().GetId() || second.GetSession().GetAal() != "aal2" ||
		len(methods) < 2 || methods[0].GetMethod() != "password" || methods[len(methods)-1].GetMethod() != "lookup_secret" {
		t.Fatalf("step-up event %+v", second)
	}

	time.Sleep(3 * time.Second)

	if n := len(logins()); n != 2 {
		t.Fatalf("%d LoggedIn events, want 2", n)
	}
}

// lookupCodes are the backup codes a lookup_secret_regenerate answer shows.
func lookupCodes(flow map[string]any) []string {
	var parsed struct {
		UI struct {
			Nodes []struct {
				Attributes struct {
					Text struct {
						Context struct {
							Secrets []struct {
								Text string `json:"text"`
							} `json:"secrets"`
						} `json:"context"`
					} `json:"text"`
				} `json:"attributes"`
			} `json:"nodes"`
		} `json:"ui"`
	}

	raw, err := json.Marshal(flow)
	if err != nil || json.Unmarshal(raw, &parsed) != nil {
		return nil
	}

	var out []string

	for _, n := range parsed.UI.Nodes {
		for _, secret := range n.Attributes.Text.Context.Secrets {
			out = append(out, secret.Text)
		}
	}

	return out
}

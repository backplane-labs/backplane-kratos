package it_test

import (
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

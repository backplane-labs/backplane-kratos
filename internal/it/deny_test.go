package it_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// denyText is the message every denying hook of these tests sends.
const denyText = "Confirm this session first"

// denying binds the after hooks of flows to deny with denyText for the
// whole form.
func denying(kinds ...string) func(*backplanetest.Harness, *flows.Flows) {
	return func(h *backplanetest.Harness, f *flows.Flows) {
		for _, flow := range kinds {
			backplanetest.Answer(h, f.Point(overlay.HookName(overlay.After, flow)),
				func(context.Context, flows.FlowIn) (flows.FlowOut, error) {
					return flows.FlowOut{Deny: &flows.Deny{Messages: []flows.Message{{ID: 4000099, Text: denyText}}}}, nil
				})
		}
	}
}

// shows reports whether a flow's ui shows denyText among the form's own
// messages (ui.messages), where a client looks for a denial of the form.
func shows(ui any) bool {
	m, _ := ui.(map[string]any)
	raw, err := json.Marshal(m["messages"])

	return err == nil && strings.Contains(string(raw), denyText)
}

// A denying AfterLogin and AfterRegistration show the hook's message in
// ui.messages, directly at Kratos and through the front.
func TestAfterHooksDenyTheForm(t *testing.T) {
	t.Parallel()

	e := start(t, denying(overlay.FlowLogin, overlay.FlowRegistration))

	for _, base := range []string{frontURL, publicURL} {
		email := unique("deny-form")
		e.newUser(t, email)

		_, flow := call(t, http.MethodGet, "/self-service/login/api", nil)

		status, body := e.callAt(t, http.MethodPost, fmt.Sprintf("%s/self-service/login?flow=%v", base, flow["id"]),
			map[string]any{"method": "password", "identifier": email, "password": password}, nil)
		if status != http.StatusBadRequest || !shows(body["ui"]) {
			t.Fatalf("denied login at %s: %d, ui %v", base, status, body["ui"])
		}

		_, flow = call(t, http.MethodGet, "/self-service/registration/api", nil)

		status, body = e.callAt(t, http.MethodPost, fmt.Sprintf("%s/self-service/registration?flow=%v", base, flow["id"]),
			map[string]any{"method": "password", "traits": map[string]any{"email": unique("deny-reg")}, "password": password}, nil)
		if status != http.StatusBadRequest || !shows(body["ui"]) {
			t.Fatalf("denied registration at %s: %d, ui %v", base, status, body["ui"])
		}
	}
}

// A denying AfterSettings (profile, password) shows the hook's message in
// ui.messages; a denying AfterRecovery does in the new recovery flow Kratos
// answers with (continue_with show_recovery_ui: Kratos v26 restarts a
// recovery its hook refused). Directly at Kratos and through the front.
func TestAfterSettingsAndRecoveryDeny(t *testing.T) {
	t.Parallel()

	e := start(t, denying(overlay.FlowSettings, overlay.FlowRecovery))

	for _, base := range []string{frontURL, publicURL} {
		email := unique("deny")
		id := e.newUser(t, email)

		_, flow := call(t, http.MethodGet, "/self-service/login/api", nil)

		status, body := call(t, http.MethodPost, fmt.Sprintf("/self-service/login?flow=%v", flow["id"]),
			map[string]any{"method": "password", "identifier": email, "password": password})
		if status != http.StatusOK {
			t.Fatalf("login: %d %v", status, body)
		}

		token, _ := body["session_token"].(string)
		auth := http.Header{"X-Session-Token": {token}}

		for _, submit := range []map[string]any{
			{"method": "profile", "traits": map[string]any{"email": unique("deny-new")}},
			{"method": "password", "password": "Another-Long-Pass-456!y"},
		} {
			started, settings := e.callAt(t, http.MethodGet, base+"/self-service/settings/api", nil, auth)
			if started != http.StatusOK {
				t.Fatalf("settings flow at %s: %d %v", base, started, settings)
			}

			denied, answer := e.callAt(t, http.MethodPost, fmt.Sprintf("%s/self-service/settings?flow=%v", base, settings["id"]),
				submit, auth)
			if denied != http.StatusBadRequest || !shows(answer["ui"]) {
				t.Fatalf("denied settings %v at %s: %d, ui %v", submit["method"], base, denied, answer["ui"])
			}
		}

		recovery, err := e.kratos.CreateRecoveryCode(t.Context(), id, "", "api")
		if err != nil {
			t.Fatal(err)
		}

		link, err := url.Parse(recovery.Link)
		if err != nil {
			t.Fatal(err)
		}

		_, body = e.callAt(t, http.MethodPost, base+"/self-service/recovery?flow="+link.Query().Get("flow"),
			map[string]any{"method": "code", "code": recovery.Code}, nil)

		next := restartedRecovery(body)
		if next == "" {
			t.Fatalf("denied recovery at %s: no continue_with show_recovery_ui in %v", base, body)
		}

		if _, retry := e.callAt(t, http.MethodGet, base+"/self-service/recovery/flows?id="+next, nil, nil); !shows(retry["ui"]) {
			t.Fatalf("restarted recovery at %s: ui %v", base, retry["ui"])
		}
	}
}

// restartedRecovery is the flow of an error's continue_with
// show_recovery_ui.
func restartedRecovery(body map[string]any) string {
	errBody, _ := body["error"].(map[string]any)
	details, _ := errBody["details"].(map[string]any)
	steps, _ := details["continue_with"].([]any)

	for _, s := range steps {
		step, _ := s.(map[string]any)
		flow, _ := step["flow"].(map[string]any)

		if id, _ := flow["id"].(string); step["action"] == "show_recovery_ui" && id != "" {
			return id
		}
	}

	return ""
}

// A denying AfterSettings shows the hook's message in ui.messages of a
// browser settings flow, as a form (303 back to the flow) and as JSON (an
// SPA), directly at Kratos and through the front.
func TestAfterSettingsDeniesBrowser(t *testing.T) {
	t.Parallel()

	e := start(t, denying(overlay.FlowSettings))

	for _, base := range []string{frontURL, publicURL} {
		for _, asJSON := range []bool{false, true} {
			email := unique("deny-browser")
			e.newUser(t, email)

			b := e.browser(t)
			flowID, csrf := browserFlow(t, b, overlay.FlowLogin)

			if status, _, cookies := submitForm(t, b, frontURL+"/self-service/login?flow="+flowID, url.Values{
				"csrf_token": {csrf}, "method": {"password"}, "identifier": {email}, "password": {password},
			}); status != http.StatusSeeOther || sessionCookie(cookies) == "" {
				t.Fatalf("browser login: %d", status)
			}

			settingsID, csrf := browserFlowAt(t, b, base, overlay.FlowSettings)
			form := url.Values{"csrf_token": {csrf}, "method": {"profile"}, "traits.email": {unique("deny-browser-new")}}
			target := fmt.Sprintf("%s/self-service/settings?flow=%s", base, settingsID)

			var ui any

			if asJSON {
				status, body := postJSONIn(t, b, target, form)
				if status != http.StatusBadRequest {
					t.Fatalf("json settings at %s: %d %v", base, status, body)
				}

				ui = body["ui"]
			} else {
				status, location, _ := submitForm(t, b, target, form)
				if status != http.StatusSeeOther {
					t.Fatalf("form settings at %s: %d %s", base, status, location)
				}

				ui = getFlow(t, b, base, overlay.FlowSettings, settingsID)["ui"]
			}

			if !shows(ui) {
				t.Fatalf("browser settings (json %v) at %s: ui %v", asJSON, base, ui)
			}
		}
	}
}

// browserFlowAt is browserFlow with the flow started at base.
func browserFlowAt(t *testing.T, b *http.Client, base, kind string) (string, string) {
	t.Helper()

	body := getJSONIn(t, b, base+"/self-service/"+kind+"/browser")

	id, _ := body["id"].(string)
	ui, _ := body["ui"].(map[string]any)
	nodes, _ := ui["nodes"].([]any)

	for _, n := range nodes {
		node, _ := n.(map[string]any)
		attrs, _ := node["attributes"].(map[string]any)

		if attrs["name"] == "csrf_token" {
			return id, fmt.Sprint(attrs["value"])
		}
	}

	t.Fatalf("browser %s flow at %s without a CSRF token: %v", kind, base, body)

	return "", ""
}

// getFlow is a browser flow of kind as b sees it.
func getFlow(t *testing.T, b *http.Client, base, kind, id string) map[string]any {
	t.Helper()

	return getJSONIn(t, b, base+"/self-service/"+kind+"/flows?id="+id)
}

func getJSONIn(t *testing.T, b *http.Client, target string) map[string]any {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Accept", "application/json")

	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var out map[string]any

	_ = json.NewDecoder(res.Body).Decode(&out)

	return out
}

// postJSONIn posts form as JSON in b, as an SPA does.
func postJSONIn(t *testing.T, b *http.Client, target string, form url.Values) (int, map[string]any) {
	t.Helper()

	fields := map[string]any{}
	for k := range form {
		fields[k] = form.Get(k)
	}

	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var out map[string]any

	_ = json.NewDecoder(res.Body).Decode(&out)

	return res.StatusCode, out
}

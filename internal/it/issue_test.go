package it_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// errorUI is the error page of the SessionIssued tests.
const errorUI = "https://ui.example/error"

// Verdicts of the product's SessionIssued.
const (
	allow = "allow"
	deny  = "deny"
	down  = "down"
)

var errProductDown = errors.New("product down")

// admission is the product's side: SessionIssued answers the verdict set
// for the client's flow (allow when none), and what it and the after
// hooks got is kept by the client's flow.
type admission struct {
	mu       sync.Mutex
	verdicts map[string]string
	issued   map[string][]flows.SessionIssuedIn
	after    map[string][]flows.FlowIn
}

// expect sets the verdict for the client's flow flowID.
func (a *admission) expect(flowID, verdict string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.verdicts[flowID] = verdict
}

// last is the one SessionIssued call of the client's flow flowID.
func (a *admission) last(t *testing.T, flowID string) flows.SessionIssuedIn {
	t.Helper()

	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.issued[flowID]) != 1 {
		t.Fatalf("SessionIssued calls of flow %s: %+v, want one", flowID, a.issued[flowID])
	}

	return a.issued[flowID][0]
}

// completed is the after hook call of flow for the client's flow flowID.
func (a *admission) completed(t *testing.T, flow, flowID string) flows.FlowIn {
	t.Helper()

	a.mu.Lock()
	defer a.mu.Unlock()

	for _, in := range a.after[flowID] {
		if in.Flow == flow {
			return in
		}
	}

	t.Fatalf("no After%s with client flow %s; got %+v", flow, flowID, a.after[flowID])

	return flows.FlowIn{}
}

func (a *admission) bind(h *backplanetest.Harness, f *flows.Flows) {
	backplanetest.Answer(h, f.SessionIssued(), func(_ context.Context, in flows.SessionIssuedIn) (flows.SessionIssuedOut, error) {
		a.mu.Lock()
		defer a.mu.Unlock()

		a.issued[in.FlowID] = append(a.issued[in.FlowID], in)

		switch a.verdicts[in.FlowID] {
		case deny:
			return flows.SessionIssuedOut{Deny: &flows.SessionDeny{
				Code: "DEVICE_LIMIT", Messages: []flows.Message{{ID: 4000001, Text: "Too many devices"}},
			}}, nil
		case down:
			return flows.SessionIssuedOut{}, errProductDown
		default:
			return flows.SessionIssuedOut{}, nil
		}
	})

	for _, flow := range []string{overlay.FlowLogin, overlay.FlowRegistration, overlay.FlowRecovery} {
		backplanetest.Answer(h, f.Point(overlay.HookName(overlay.After, flow)),
			func(_ context.Context, in flows.FlowIn) (flows.FlowOut, error) {
				a.mu.Lock()
				defer a.mu.Unlock()

				a.after[in.ClientFlowID] = append(a.after[in.ClientFlowID], in)

				return flows.FlowOut{}, nil
			})
	}
}

// The cases of a test run one after another: the stand's Kratos keeps its
// data in memory (SQLite) and refuses concurrent writes ("Unable to
// serialize access").

// startAdmission starts the service with SessionIssued bound and the
// OIDC providers and error page set.
func startAdmission(t *testing.T) (env, *admission) {
	t.Helper()

	a := &admission{
		verdicts: map[string]string{}, issued: map[string][]flows.SessionIssuedIn{}, after: map[string][]flows.FlowIn{},
	}
	e := startWith(t, func(s *overlay.Settings) {
		nativeSettings(s)
		s.ErrorUIURL = errorUI
	}, a.bind)

	return e, a
}

// refused checks the client got verdict's refusal and no credential, and
// Kratos ended the session sid.
func (e env) refused(t *testing.T, verdict string, status int, body map[string]any, sid string) {
	t.Helper()

	want := map[string]struct {
		status int
		id     string
	}{deny: {http.StatusForbidden, "session_refused"}, down: {http.StatusServiceUnavailable, "session_unavailable"}}[verdict]

	errBody, _ := body["error"].(map[string]any)
	if status != want.status || errBody["id"] != want.id || body["session_token"] != nil || body["session"] != nil {
		t.Fatalf("%s: %d %v, want %d %s and no credential", verdict, status, body, want.status, want.id)
	}

	if verdict == deny && errBody["reason"] != "DEVICE_LIMIT" {
		t.Fatalf("reason %v", errBody["reason"])
	}

	e.ended(t, sid)
}

// ended checks Kratos ended the session sid.
func (e env) ended(t *testing.T, sid string) {
	t.Helper()

	s, err := e.kratos.GetSession(t.Context(), sid)
	if err != nil || s.Active {
		t.Fatalf("session %s after a refusal: active %v, %v", sid, s.Active, err)
	}
}

// Sessions issued by API flows through the front (password login,
// registration, a recovery code) reach SessionIssued with the client's
// flow and payload; admitted, the client gets the token; denied or with
// the product down, the client gets no token and Kratos ends the session.
func TestSessionIssuedAPI(t *testing.T) {
	t.Parallel()

	e, a := startAdmission(t)

	for _, verdict := range []string{allow, deny, down} {
		t.Logf("case %s", "login "+verdict)
		func() {
			email := unique("issued-login-" + verdict)
			e.newUser(t, email)

			_, flow := call(t, http.MethodGet, "/self-service/login/api", nil)
			flowID := fmt.Sprint(flow["id"])
			a.expect(flowID, verdict)

			status, body := e.callAt(t, http.MethodPost, frontURL+"/self-service/login?flow="+flowID, map[string]any{
				"method": "password", "identifier": email, "password": password, "transient_payload": map[string]any{"m": verdict},
			}, nil)

			in := a.last(t, flowID)
			if in.Flow != overlay.FlowLogin || in.Channel != flows.ChannelAPI || in.Method != "password" || in.Session.ID == "" || in.Identity.ID == "" ||
				string(in.TransientPayload) != `{"m":"`+verdict+`"}` {
				t.Fatalf("SessionIssued got %+v", in)
			}

			if verdict != allow {
				e.refused(t, verdict, status, body, in.Session.ID)

				return
			}

			token, _ := body["session_token"].(string)
			if code, who := callAs(t, token, http.MethodGet, "/sessions/whoami", nil); status != http.StatusOK ||
				code != http.StatusOK || who["id"] != in.Session.ID {
				t.Fatalf("admitted login: %d %v, whoami %d %v", status, body, code, who)
			}
		}()
	}

	for _, verdict := range []string{allow, deny} {
		t.Logf("case %s", "registration "+verdict)
		func() {
			_, flow := call(t, http.MethodGet, "/self-service/registration/api", nil)
			flowID := fmt.Sprint(flow["id"])
			a.expect(flowID, verdict)

			status, body := e.callAt(t, http.MethodPost, frontURL+"/self-service/registration?flow="+flowID, map[string]any{
				"method": "password", "traits": map[string]any{"email": unique("issued-reg")}, "password": password,
			}, nil)

			in := a.last(t, flowID)
			if in.Flow != overlay.FlowRegistration || in.Channel != flows.ChannelAPI {
				t.Fatalf("SessionIssued got %+v", in)
			}

			if after := a.completed(t, overlay.FlowRegistration, flowID); after.FlowID != flowID {
				t.Fatalf("AfterRegistration flow %s, client flow %s, want %s", after.FlowID, after.ClientFlowID, flowID)
			}

			if verdict == deny {
				e.refused(t, verdict, status, body, in.Session.ID)
			} else if status != http.StatusOK || body["session_token"] == nil {
				t.Fatalf("admitted registration: %d %v", status, body)
			}
		}()
	}

	for _, verdict := range []string{allow, deny} {
		t.Logf("case %s", "recovery "+verdict)
		func() {
			id := e.newUser(t, unique("issued-recovery"))

			recovery, err := e.kratos.CreateRecoveryCode(t.Context(), id, "", "api")
			if err != nil {
				t.Fatal(err)
			}

			link, err := url.Parse(recovery.Link)
			if err != nil {
				t.Fatal(err)
			}

			flowID := link.Query().Get("flow")
			a.expect(flowID, verdict)
			status, body := e.callAt(t, http.MethodPost, frontURL+"/self-service/recovery?flow="+flowID,
				map[string]any{"method": "code", "code": recovery.Code}, nil)

			in := a.last(t, flowID)
			if in.Flow != overlay.FlowRecovery || in.Channel != flows.ChannelAPI ||
				in.Method != "code_recovery" {
				t.Fatalf("SessionIssued got %+v", in)
			}

			raw, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}

			if verdict == deny {
				if status != http.StatusForbidden || strings.Contains(string(raw), "ory_session_token") {
					t.Fatalf("denied recovery: %d %s", status, raw)
				}

				e.ended(t, in.Session.ID)
			} else if status != http.StatusOK || !strings.Contains(string(raw), "ory_session_token") {
				t.Fatalf("admitted recovery: %d %s", status, raw)
			}
		}()
	}
}

// browserFlow starts a browser flow of kind in b: its id and CSRF token.
func browserFlow(t *testing.T, b *http.Client, kind string) (string, string) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, frontURL+"/self-service/"+kind+"/browser", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Accept", "application/json")

	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var flow struct {
		ID string `json:"id"`
		UI struct {
			Nodes []struct {
				Attributes struct {
					Name  string `json:"name"`
					Value any    `json:"value"`
				} `json:"attributes"`
			} `json:"nodes"`
		} `json:"ui"`
	}

	if err := json.NewDecoder(res.Body).Decode(&flow); err != nil || flow.ID == "" {
		t.Fatalf("browser %s flow: %d %v", kind, res.StatusCode, err)
	}

	for _, n := range flow.UI.Nodes {
		if n.Attributes.Name == "csrf_token" {
			return flow.ID, fmt.Sprint(n.Attributes.Value)
		}
	}

	t.Fatalf("browser %s flow without a CSRF token", kind)

	return "", ""
}

// submitForm posts a browser form to target in b: the status, Location
// and the cookies the answer sets.
func submitForm(t *testing.T, b *http.Client, target string, form url.Values) (int, string, []*http.Cookie) {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, target, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	_, _ = io.Copy(io.Discard, res.Body)

	return res.StatusCode, res.Header.Get("Location"), res.Cookies()
}

// sessionCookie is Kratos's session cookie among cookies.
func sessionCookie(cookies []*http.Cookie) string {
	for _, c := range cookies {
		if c.Name == "ory_kratos_session" && c.Value != "" {
			return c.Value
		}
	}

	return ""
}

// errorPage is where a refused browser form flow is sent.
func errorPage(verdict string) string {
	if verdict == deny {
		return errorUI + "?id=session_refused&reason=DEVICE_LIMIT"
	}

	return errorUI + "?id=session_unavailable&reason=unavailable"
}

// A browser form login through the front: admitted, the browser gets the
// session cookie; refused, it is sent to the error page with no cookie and
// Kratos ends the session.
func TestSessionIssuedBrowserForm(t *testing.T) {
	t.Parallel()

	e, a := startAdmission(t)

	for _, verdict := range []string{allow, deny, down} {
		t.Logf("case %s", verdict)
		func() {
			email := unique("issued-browser-" + verdict)
			e.newUser(t, email)

			b := e.browser(t)
			flowID, csrf := browserFlow(t, b, overlay.FlowLogin)
			a.expect(flowID, verdict)

			status, location, cookies := submitForm(t, b, frontURL+"/self-service/login?flow="+flowID, url.Values{
				"csrf_token": {csrf}, "method": {"password"}, "identifier": {email}, "password": {password},
				"transient_payload": {`{"m":"form"}`},
			})

			in := a.last(t, flowID)
			if in.Channel != flows.ChannelBrowser || string(in.TransientPayload) != `{"m":"form"}` {
				t.Fatalf("SessionIssued got %+v", in)
			}

			if verdict == allow {
				if status != http.StatusSeeOther || sessionCookie(cookies) == "" {
					t.Fatalf("admitted: %d %s %v", status, location, cookies)
				}

				return
			}

			if status != http.StatusSeeOther || location != errorPage(verdict) || sessionCookie(cookies) != "" {
				t.Fatalf("refused: %d %s %v", status, location, cookies)
			}

			e.ended(t, in.Session.ID)
		}()
	}
}

// follow follows b's redirects from next until the answer is no
// redirect or leaves for the app: the last status, Location and cookies.
func follow(t *testing.T, b *http.Client, next string) (int, string, []*http.Cookie) {
	t.Helper()

	var trace []string

	for range 10 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, next, http.NoBody)
		if err != nil {
			t.Fatal(err)
		}

		res, err := b.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()

		trace = append(trace, fmt.Sprintf("%d %s", res.StatusCode, next))
		location := res.Header.Get("Location")

		if strings.HasPrefix(next, frontURL+"/self-service/methods/oidc/callback/") || location == "" {
			return res.StatusCode, location, res.Cookies()
		}

		next = location
	}

	t.Fatalf("no callback after %v", trace)

	return 0, "", nil
}

// A browser OIDC login of a new subject: the start goes through the hop,
// Kratos completes the login as a new registration flow, whose after hook
// still gets the client's login flow as ClientFlowID, as SessionIssued
// does; refused, the browser goes to the error page with no cookie.
func TestSessionIssuedBrowserOIDC(t *testing.T) {
	t.Parallel()

	e, a := startAdmission(t)

	for _, verdict := range []string{allow, deny} {
		t.Logf("case %s", verdict)
		func() {
			b := e.browser(t)
			flowID, csrf := browserFlow(t, b, overlay.FlowLogin)
			a.expect(flowID, verdict)

			status, location, _ := submitForm(t, b, frontURL+"/self-service/login?flow="+flowID, url.Values{
				"csrf_token": {csrf}, "method": {"oidc"}, "provider": {"mock"},
			})
			if status != http.StatusSeeOther || !strings.HasPrefix(location, frontURL+flows.OIDCStartPath+"?t=") {
				t.Fatalf("oidc start: %d %s, want the hop", status, location)
			}

			status, location, cookies := follow(t, b, location)

			if after := a.completed(t, overlay.FlowRegistration, flowID); after.FlowID == flowID {
				t.Fatalf("registration not converted: flow %s", after.FlowID)
			}

			in := a.last(t, flowID)
			if in.Flow != overlay.FlowLogin || in.Channel != flows.ChannelBrowser || in.Method != "oidc" {
				t.Fatalf("SessionIssued got %+v", in)
			}

			if verdict == allow {
				if status != http.StatusSeeOther || sessionCookie(cookies) == "" {
					t.Fatalf("admitted: %d %s %v", status, location, cookies)
				}

				return
			}

			if status != http.StatusSeeOther || location != errorPage(verdict) || sessionCookie(cookies) != "" {
				t.Fatalf("refused: %d %s %v", status, location, cookies)
			}

			e.ended(t, in.Session.ID)
		}()
	}
}

// A native OIDC login of a new subject through the front: the system
// browser takes the hop, the converted registration's after hook gets the
// app's flow as ClientFlowID; the exchange reaches SessionIssued with the
// app's X-Kratos-Flow-Id, and a refusal answers 403 without the token.
func TestSessionIssuedNative(t *testing.T) {
	t.Parallel()

	e, a := startAdmission(t)

	for _, verdict := range []string{allow, deny, down} {
		t.Logf("case %s", verdict)
		func() {
			n := nativeSignInVia(t, e, frontURL, overlay.FlowLogin, "mock", map[string]any{"m": "native"})
			a.expect(n.flow, verdict)

			if after := a.completed(t, overlay.FlowRegistration, n.flow); after.FlowID == n.flow {
				t.Fatalf("registration not converted: flow %s (trace %v)", after.FlowID, n.trace)
			}

			q := url.Values{"init_code": {n.initCode}, "return_to_code": {n.returnToCode}}
			status, body := e.callAt(t, http.MethodGet, frontURL+flows.TokenExchangePath+"?"+q.Encode(), nil,
				http.Header{flows.NativeFlowHeader: {n.flow}})

			in := a.last(t, n.flow)
			if in.Channel != flows.ChannelNativeExchange || in.Method != "oidc" {
				t.Fatalf("SessionIssued got %+v", in)
			}

			if verdict != allow {
				e.refused(t, verdict, status, body, in.Session.ID)

				return
			}

			if status != http.StatusOK || body["session_token"] == nil {
				t.Fatalf("admitted exchange: %d %v", status, body)
			}
		}()
	}
}

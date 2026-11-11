package it_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// nativeCallback is the app's private-use callback (RFC 8252 7.1).
const nativeCallback = "ru.komeet://auth/callback"

// oidcIssuer is the test OIDC provider (make it-up): issuer default signs
// in a new subject every time, returning always the same one.
const oidcIssuer = "http://127.0.0.1:34480/"

// oidcMapper makes the subject an email address.
const oidcMapper = `local claims = std.extVar('claims');
{ identity: { traits: { email: claims.sub + '@oidc.test' } } }`

// nativeSettings allow the native callback and the two OIDC providers.
func nativeSettings(s *overlay.Settings) {
	s.AllowedReturnURLs = []string{nativeCallback}
	s.Methods.OIDC = overlay.OIDC{Enabled: true, Providers: []overlay.OIDCProvider{
		{
			ID: "mock", Provider: "generic", ClientID: "kratos", IssuerURL: oidcIssuer + "default",
			Scope: []string{"openid", "email"}, Mapper: oidcMapper,
		},
		{
			ID: "returning", Provider: "generic", ClientID: "kratos", IssuerURL: oidcIssuer + "returning",
			Scope: []string{"openid", "email"}, Mapper: oidcMapper,
		},
	}}
}

// browser is the system browser: it keeps cookies and does not follow
// redirects, so the test sees every hop.
func browser(t *testing.T) *http.Client {
	t.Helper()

	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

// hop requests url in b; the answer's status and Location.
func hop(t *testing.T, b *http.Client, method, target string, body any) (int, string) {
	t.Helper()

	var in io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}

		in = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, target, in)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := b.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	_, _ = io.Copy(io.Discard, res.Body)

	return res.StatusCode, res.Header.Get("Location")
}

// native is one native sign-in through the system browser.
type native struct {
	flow, initCode, returnToCode string
	trace                        []string
}

// nativeSignIn runs a native OIDC flow of kind (login or registration)
// with provider, as the app does: an API flow asking for a session token
// exchange code, the browser through the provider back to the app's
// callback, whose code completes the pair.
func nativeSignIn(t *testing.T, kind, provider string, transient map[string]any) native {
	t.Helper()

	q := url.Values{"return_session_token_exchange_code": {"true"}, "return_to": {nativeCallback}}

	status, flow := call(t, http.MethodGet, "/self-service/"+kind+"/api?"+q.Encode(), nil)
	if status != http.StatusOK {
		t.Fatalf("%s flow: %d %v", kind, status, flow)
	}

	n := native{flow: fmt.Sprint(flow["id"])}
	n.initCode, _ = flow["session_token_exchange_code"].(string)

	submit := map[string]any{"method": "oidc", "provider": provider}
	if transient != nil {
		submit["transient_payload"] = transient
	}

	status, body := call(t, http.MethodPost, "/self-service/"+kind+"?flow="+n.flow, submit)
	n.trace = append(n.trace, fmt.Sprintf("submit %d", status))

	next, _ := body["redirect_browser_to"].(string)
	if next == "" {
		t.Fatalf("submit: %d %v", status, body)
	}

	b := browser(t)

	for range 10 {
		if strings.HasPrefix(next, nativeCallback) {
			callback, err := url.Parse(next)
			if err != nil {
				t.Fatal(err)
			}

			n.returnToCode = callback.Query().Get("code")

			return n
		}

		code, location := hop(t, b, http.MethodGet, next, nil)
		n.trace = append(n.trace, fmt.Sprintf("%d %s", code, next))

		if location == "" {
			t.Fatalf("no redirect after %v", n.trace)
		}

		next = location
	}

	t.Fatalf("no callback after %v", n.trace)

	return n
}

// exchange trades the pair for the session token at Kratos.
func exchange(t *testing.T, n native) (int, map[string]any) {
	t.Helper()

	q := url.Values{"init_code": {n.initCode}, "return_to_code": {n.returnToCode}}

	return call(t, http.MethodGet, "/sessions/token-exchange?"+q.Encode(), nil)
}

// exchangeVia trades the pair through the service's exchange at base.
func exchangeVia(t *testing.T, base string, n native) int {
	t.Helper()

	q := url.Values{"init_code": {n.initCode}, "return_to_code": {n.returnToCode}}
	status, _ := hop(t, http.DefaultClient, http.MethodGet, base+flows.TokenExchangePath+"?"+q.Encode(), nil)

	return status
}

// exchanged is the session token and session id an exchange answered.
func exchanged(t *testing.T, n native) (string, string) {
	t.Helper()

	status, body := exchange(t, n)
	if status != http.StatusOK {
		t.Fatalf("exchange: %d %v (trace %v)", status, body, n.trace)
	}

	session, _ := body["session"].(map[string]any)
	token, _ := body["session_token"].(string)

	return token, fmt.Sprint(session["id"])
}

// flowSession waits for the flow event of flow whose flow id is flowID
// and returns it.
func flowSession(t *testing.T, e env, flow, flowID string) *kratoseventsv1.FlowEvent {
	t.Helper()

	var got *kratoseventsv1.FlowEvent

	waitFor(t, flow+" event of flow "+flowID, func() bool {
		for _, ev := range backplanetest.Events(e.h, e.flows.Event(flow)) {
			if ev.GetFlowId() == flowID && ev.GetSession().GetId() != "" {
				got = ev

				return true
			}
		}

		return false
	})

	return got
}

// The native OIDC sign-in of a mobile app against real Kratos: API flows
// asking for a session token exchange code, the system browser through
// the provider to the app's callback, the exchange, then the session
// token; its events carry the final session; a foreign return_to is
// refused; API logout publishes LoggedOut.
func TestNativeOIDC(t *testing.T) {
	t.Parallel()

	e := startWith(t, nativeSettings, nil)

	public, err := url.Parse(publicURL)
	if err != nil {
		t.Fatal(err)
	}

	front := httptest.NewServer(flows.TokenExchange(public, nil, 5*time.Minute))
	t.Cleanup(front.Close)

	// return_to must be an allowed URL. A private-use URI without a host
	// (RFC 8252 7.1, ru.komeet:/auth/callback) is refused even when listed:
	// Kratos puts the default return URL's host into it first.
	for _, returnTo := range []string{"https://evil.example/cb", "ru.komeet:/auth/callback"} {
		q := url.Values{"return_session_token_exchange_code": {"true"}, "return_to": {returnTo}}
		if status, body := call(t, http.MethodGet, "/self-service/login/api?"+q.Encode(), nil); status != http.StatusBadRequest {
			t.Fatalf("return_to %s: %d %v", returnTo, status, body)
		}
	}

	// A new subject registers; Registered carries the session the app
	// holds, and the client's transient payload.
	registered := nativeSignIn(t, "registration", "mock", map[string]any{"qr": "n-1"})
	token, sid := exchanged(t, registered)

	if code, who := callAs(t, token, http.MethodGet, "/sessions/whoami", nil); code != http.StatusOK || who["id"] != sid {
		t.Fatalf("whoami with the exchanged token: %d %v, want %s", code, who, sid)
	}

	reg := flowSession(t, e, overlay.FlowRegistration, registered.flow)
	if reg.GetSession().GetId() != sid {
		t.Fatalf("Registered session %s, want %s", reg.GetSession().GetId(), sid)
	}

	if qr := reg.GetTransientPayload().GetFields()["qr"].GetStringValue(); qr != "n-1" {
		t.Fatalf("Registered transient payload %v", reg.GetTransientPayload())
	}

	// Kratos itself answers the same pair again, with the same token, and
	// even after the session ended: it consumes no code and checks no age
	// (why the service fronts the exchange, TestTokenExchangeProxy). Should
	// Kratos fix it, this fails and the proxy can go.
	if again, body := exchange(t, registered); again != http.StatusOK || body["session_token"] != token {
		t.Fatalf("second exchange: %d %v", again, body)
	}

	if err := e.kratos.DisableSession(t.Context(), sid); err != nil {
		t.Fatal(err)
	}

	revoked, body := exchange(t, registered)
	if session, _ := body["session"].(map[string]any); revoked != http.StatusOK || session["active"] != false {
		t.Fatalf("exchange after revoke: %d %v", revoked, body)
	}

	// Through the service, the ended session's pair answers 404.
	if status := exchangeVia(t, front.URL, registered); status != http.StatusNotFound {
		t.Fatalf("exchange of an ended session through the service: %d", status)
	}

	// The same subject signs in again: LoggedIn carries the new session.
	nativeSignIn(t, "login", "returning", nil)
	returning := nativeSignIn(t, "login", "returning", map[string]any{"qr": "n-2"})

	// A fresh active session's pair passes through the service.
	if status := exchangeVia(t, front.URL, returning); status != http.StatusOK {
		t.Fatalf("exchange through the service: %d", status)
	}

	token, sid = exchanged(t, returning)

	if login := flowSession(t, e, overlay.FlowLogin, returning.flow); login.GetSession().GetId() != sid ||
		login.GetTransientPayload().GetFields()["qr"].GetStringValue() != "n-2" {
		t.Fatalf("LoggedIn %v, want session %s and qr n-2", login, sid)
	}

	// API logout through the service publishes LoggedOut.
	proxy := httptest.NewServer(e.flows.Logout(public, nil))
	t.Cleanup(proxy.Close)

	if status, _ := hop(t, http.DefaultClient, http.MethodDelete, proxy.URL+"/self-service/logout/api",
		map[string]string{"session_token": token}); status != http.StatusNoContent {
		t.Fatalf("logout: %d", status)
	}

	waitFor(t, "LoggedOut", func() bool {
		for _, out := range backplanetest.Events(e.h, e.flows.LoggedOut()) {
			if out.GetSession().GetId() == sid {
				return true
			}
		}

		return false
	})
}

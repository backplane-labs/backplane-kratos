package flows_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

const errorUI = "https://ui.example/error"

// kratosFake answers every request with answer and keeps the FlowHeader
// each request carried.
type kratosFake struct {
	mu      sync.Mutex
	headers []string
	srv     *httptest.Server
}

func newKratos(t *testing.T, answer http.HandlerFunc) *kratosFake {
	t.Helper()

	k := &kratosFake{}
	k.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		k.mu.Lock()
		k.headers = append(k.headers, r.Header.Get(overlay.FlowHeader))
		k.mu.Unlock()

		answer(w, r)
	}))
	t.Cleanup(k.srv.Close)

	return k
}

func (k *kratosFake) flowHeaders() []string {
	k.mu.Lock()
	defer k.mu.Unlock()

	return append([]string(nil), k.headers...)
}

// public is Public of f in front of k, with the error page errorURL.
func public(t *testing.T, f *flows.Flows, k *kratosFake, errorURL string) *httptest.Server {
	t.Helper()

	u, err := url.Parse(k.srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	settings := overlay.Settings{
		ErrorUIURL: errorURL, Login: overlay.Login{Lifespan: time.Hour}, Registration: overlay.Registration{Lifespan: time.Hour},
	}

	srv := httptest.NewServer(f.Public(u, nil, 5*time.Minute, config.LiveOf(settings)))
	t.Cleanup(srv.Close)

	return srv
}

// noFollow sees every redirect.
var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

type reply struct {
	status int
	header http.Header
	body   string
}

func do(t *testing.T, method, target, contentType, body string, header http.Header) reply {
	t.Helper()

	req, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}

	for k, v := range header {
		req.Header[k] = v
	}

	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	res, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)

	return reply{status: res.StatusCode, header: res.Header, body: string(raw)}
}

// stored is the session Kratos stored for every test: s-1 of identity i-1.
func stored() ory.Session {
	at := time.Now().Add(-time.Second)

	return ory.Session{
		ID: "s-1", Active: true, AuthenticatedAt: &at, AuthenticatorAssuranceLevel: "aal1",
		AuthenticationMethods: []ory.AuthenticationMethod{{Method: "password", AAL: "aal1"}},
		Identity:              &ory.Identity{ID: "i-1", SchemaID: "default", Traits: json.RawMessage(`{"email":"a@b.c"}`)},
	}
}

// bindIssued answers SessionIssued with out (or err) and records what it got.
func bindIssued(h *backplanetest.Harness, f *flows.Flows, out flows.SessionIssuedOut, err error) *[]flows.SessionIssuedIn {
	var (
		mu  sync.Mutex
		got []flows.SessionIssuedIn
	)

	backplanetest.Answer(h, f.SessionIssued(), func(_ context.Context, in flows.SessionIssuedIn) (flows.SessionIssuedOut, error) {
		mu.Lock()
		defer mu.Unlock()

		got = append(got, in)

		return out, err
	})

	return &got
}

var errHookDown = errors.New("product down")

// Every session a submit issues is admitted by SessionIssued before its
// credential leaves; a denial or a failure revokes the session and the
// client gets no token and no cookie.
func TestSessionIssued(t *testing.T) {
	t.Parallel()

	const (
		apiLogin   = `{"session_token":"tok-1","session":{"id":"s-1","active":true}}`
		recovered  = `{"id":"f-r","continue_with":[{"action":"set_ory_session_token","ory_session_token":"tok-r"}]}`
		formCookie = "ory_kratos_session=sess-cookie; Path=/; HttpOnly"
		csrfCookie = "csrf_token_abc=x; Path=/; HttpOnly"
		allowed    = "allow"
		denied     = "deny"
		down       = "down"
		unbound    = "unbound"
		transient  = `{"device_admission":"proof-1"}`
	)

	type answer struct {
		status  int
		ctype   string
		body    string
		cookies []string
	}

	jsonAnswer := func(body string) answer {
		return answer{status: http.StatusOK, ctype: "application/json", body: body}
	}
	formAnswer := func(cookies ...string) answer {
		return answer{status: http.StatusSeeOther, cookies: cookies}
	}

	tests := []struct {
		name string
		kind string
		// get: a GET of path (default: a POST of the kind's submit).
		get      string
		answer   answer
		hook     string
		busy     int
		who      *ory.Session
		whoErr   error
		errorURL string

		wantStatus   int
		wantChannel  string
		wantLocation string
		wantRevoked  bool
		wantCalled   bool
		wantCookie   bool
		wantInBody   string
	}{
		{
			name: "api login admitted", kind: "login", answer: jsonAnswer(apiLogin), hook: allowed,
			wantStatus: http.StatusOK, wantChannel: flows.ChannelAPI, wantCalled: true, wantInBody: "tok-1",
		},
		{
			name: "api login denied", kind: "login", answer: jsonAnswer(apiLogin), hook: denied,
			wantStatus: http.StatusForbidden, wantChannel: flows.ChannelAPI, wantCalled: true, wantRevoked: true,
			wantInBody: `"reason":"DEVICE_LIMIT"`,
		},
		{
			name: "revoke racing kratos's own write is tried again", kind: "login", answer: jsonAnswer(apiLogin),
			hook: denied, busy: 3, wantStatus: http.StatusForbidden, wantChannel: flows.ChannelAPI, wantCalled: true,
			wantRevoked: true,
		},
		{
			name: "api login with the product down", kind: "login", answer: jsonAnswer(apiLogin), hook: down,
			wantStatus: http.StatusServiceUnavailable, wantChannel: flows.ChannelAPI, wantCalled: true, wantRevoked: true,
			wantInBody: `"id":"session_unavailable"`,
		},
		{
			name: "unbound passes", kind: "login", answer: jsonAnswer(apiLogin), hook: unbound,
			wantStatus: http.StatusOK, wantInBody: "tok-1",
		},
		{
			name: "registration denied", kind: "registration", answer: jsonAnswer(apiLogin), hook: denied,
			wantStatus: http.StatusForbidden, wantChannel: flows.ChannelAPI, wantCalled: true, wantRevoked: true,
		},
		{
			name: "api recovery token checked", kind: "recovery", answer: jsonAnswer(recovered), hook: denied,
			who: new(stored()), wantStatus: http.StatusForbidden, wantChannel: flows.ChannelAPI, wantCalled: true,
			wantRevoked: true,
		},
		{
			name: "browser form admitted", kind: "login", answer: formAnswer(formCookie, csrfCookie), hook: allowed,
			who: new(stored()), errorURL: errorUI, wantStatus: http.StatusSeeOther, wantChannel: flows.ChannelBrowser,
			wantCalled: true, wantCookie: true,
		},
		{
			name: "browser form denied goes to the error page", kind: "login", answer: formAnswer(formCookie), hook: denied,
			who: new(stored()), errorURL: errorUI, wantStatus: http.StatusSeeOther, wantChannel: flows.ChannelBrowser,
			wantCalled: true, wantRevoked: true, wantLocation: errorUI + "?id=session_refused&reason=DEVICE_LIMIT",
		},
		{
			name: "browser form denied without an error page", kind: "login", answer: formAnswer(formCookie), hook: denied,
			who: new(stored()), wantStatus: http.StatusForbidden, wantChannel: flows.ChannelBrowser, wantCalled: true,
			wantRevoked: true, wantInBody: `"id":"session_refused"`,
		},
		{
			name: "browser recovery down", kind: "recovery", answer: formAnswer(formCookie), hook: down, who: new(stored()),
			errorURL: errorUI, wantStatus: http.StatusSeeOther, wantChannel: flows.ChannelBrowser, wantCalled: true,
			wantRevoked: true, wantLocation: errorUI + "?id=session_unavailable&reason=unavailable",
		},
		{
			name: "csrf cookie alone issues nothing", kind: "login", answer: formAnswer(csrfCookie), hook: denied,
			wantStatus: http.StatusSeeOther, wantCookie: true,
		},
		{
			name: "awaiting a second factor issues nothing yet", kind: "login", answer: formAnswer(formCookie), hook: denied,
			whoErr: &ory.Error{Status: http.StatusForbidden}, wantStatus: http.StatusSeeOther, wantCookie: true,
		},
		{
			name: "kratos unreachable for whoami refuses", kind: "login", answer: formAnswer(formCookie), hook: allowed,
			whoErr: &ory.Error{Status: http.StatusBadGateway}, errorURL: errorUI, wantStatus: http.StatusSeeOther,
			wantLocation: errorUI + "?id=session_unavailable&reason=unavailable",
		},
		{
			name: "settings sets the signed-in session's cookie again", kind: "settings", answer: formAnswer(formCookie),
			hook: denied, who: new(stored()), errorURL: errorUI, wantStatus: http.StatusSeeOther, wantCookie: true,
		},
		{
			name: "recovery link redeemed by a GET", kind: "recovery", get: "/self-service/recovery?flow=f-1&token=t",
			answer: formAnswer(formCookie), hook: denied, who: new(stored()), errorURL: errorUI,
			wantStatus: http.StatusSeeOther, wantChannel: flows.ChannelBrowser, wantCalled: true, wantRevoked: true,
			wantLocation: errorUI + "?id=session_refused&reason=DEVICE_LIMIT",
		},
		{
			name: "verification sets an admitted session's cookie again", kind: "verification",
			get: "/self-service/verification?flow=f-1&code=c", answer: formAnswer(formCookie), hook: denied,
			who: new(stored()), wantStatus: http.StatusSeeOther, wantCookie: true,
		},
		{
			name: "a failed submit passes", kind: "login", hook: denied,
			answer:     answer{status: http.StatusBadRequest, ctype: "application/json", body: `{"id":"f-1","ui":{}}`},
			wantStatus: http.StatusBadRequest, wantInBody: `"ui"`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			kratos := &sessions{who: tc.who, whoErr: tc.whoErr, after: stored(), busy: tc.busy}
			h, f, _ := harnessWith(t, kratos)

			var got *[]flows.SessionIssuedIn

			switch tc.hook {
			case allowed:
				got = bindIssued(h, f, flows.SessionIssuedOut{}, nil)
			case denied:
				got = bindIssued(h, f, flows.SessionIssuedOut{Deny: &flows.SessionDeny{
					Code: "DEVICE_LIMIT", Messages: []flows.Message{{ID: 4000001, Text: "Too many devices"}},
				}}, nil)
			case down:
				got = bindIssued(h, f, flows.SessionIssuedOut{}, errHookDown)
			default:
				got = &[]flows.SessionIssuedIn{}
			}

			k := newKratos(t, func(w http.ResponseWriter, _ *http.Request) {
				for _, c := range tc.answer.cookies {
					w.Header().Add("Set-Cookie", c)
				}

				if tc.answer.ctype != "" {
					w.Header().Set("Content-Type", tc.answer.ctype)
				}

				if tc.answer.status == http.StatusSeeOther {
					w.Header().Set("Location", "https://app.example/home")
				}

				w.WriteHeader(tc.answer.status)
				_, _ = w.Write([]byte(tc.answer.body))
			})
			srv := public(t, f, k, tc.errorURL)

			var r reply

			wantTransient := transient
			if tc.get != "" {
				r, wantTransient = do(t, http.MethodGet, srv.URL+tc.get, "", "", nil), ""
			} else {
				r = do(t, http.MethodPost, srv.URL+"/self-service/"+tc.kind+"?flow=f-1", "application/json",
					`{"method":"password","transient_payload":`+transient+`}`, nil)
			}

			if r.status != tc.wantStatus {
				t.Fatalf("status %d %s, want %d", r.status, r.body, tc.wantStatus)
			}

			if tc.wantInBody != "" && !strings.Contains(r.body, tc.wantInBody) {
				t.Fatalf("body %s, want %s in it", r.body, tc.wantInBody)
			}

			if tc.wantLocation != "" && r.header.Get("Location") != tc.wantLocation {
				t.Fatalf("location %q, want %q", r.header.Get("Location"), tc.wantLocation)
			}

			if refused := tc.wantRevoked || tc.wantLocation != ""; refused && strings.Contains(r.body, "tok-") {
				t.Fatalf("a refused client got the token: %s", r.body)
			}

			if has := len(r.header.Values("Set-Cookie")) > 0; has != tc.wantCookie {
				t.Fatalf("Set-Cookie %v, want cookies %v", r.header.Values("Set-Cookie"), tc.wantCookie)
			}

			if revoked := kratos.revoked(); (len(revoked) == 1 && revoked[0] == "s-1") != tc.wantRevoked {
				t.Fatalf("revoked %v, want revoked %v", revoked, tc.wantRevoked)
			}

			if called := len(*got) == 1; called != tc.wantCalled {
				t.Fatalf("SessionIssued calls %v, want called %v", *got, tc.wantCalled)
			}

			if !tc.wantCalled {
				return
			}

			in := (*got)[0]
			if in.Flow != tc.kind || in.FlowID != "f-1" || in.Channel != tc.wantChannel || in.Method != "password" ||
				in.Identity.ID != "i-1" || in.Session.ID != "s-1" || in.Session.Identity != nil ||
				string(in.TransientPayload) != wantTransient {
				t.Fatalf("SessionIssued got %+v", in)
			}
		})
	}
}

// The client's flow reaches the after hooks as ClientFlowID through
// Kratos's forwarded headers, signed by the proxy; a header the client
// sends itself is dropped, and a forged one vouches for nothing.
func TestClientFlowID(t *testing.T) {
	t.Parallel()

	h, f, callbacks := harness(t)

	var got []string

	backplanetest.Answer(h, f.Point(overlay.HookName(overlay.After, overlay.FlowLogin)),
		func(_ context.Context, in flows.FlowIn) (flows.FlowOut, error) {
			got = append(got, in.ClientFlowID+"|"+in.RequestHeaders[overlay.FlowHeader])

			return flows.FlowOut{}, nil
		})

	k := newKratos(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadRequest) })
	srv := public(t, f, k, "")
	forged := http.Header{overlay.FlowHeader: {"forged"}}

	do(t, http.MethodPost, srv.URL+"/self-service/login?flow=f-1", "application/json", `{}`, forged)
	do(t, http.MethodGet, srv.URL+"/self-service/login/flows?id=f-1", "", "", forged)

	headers := k.flowHeaders()
	if len(headers) != 2 || headers[0] == "" || headers[0] == "forged" || headers[1] != "" {
		t.Fatalf("FlowHeader Kratos got %q: want the proxy's on the submit, none on the rest", headers)
	}

	for _, header := range []string{headers[0], "forged", ""} {
		body := `{"flow":{"id":"f-2"},"identity":{"id":"i-1"},"request_headers":{"` + overlay.FlowHeader + `":["` + header + `"]}}`

		req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, callbacks.URL+"/hooks/after/login/password",
			bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}

		req.SetBasicAuth(overlay.KeyUser, key)

		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}

		_ = res.Body.Close()
	}

	if want := []string{"f-1|", "|", "|"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("ClientFlowID %q, want %q", got, want)
	}
}

// An OIDC start goes through the hop: it sets the flow cookie for the
// state and sends the browser to exactly the provider URL Kratos gave; the
// callback carries the client's flow to Kratos and deletes the cookie. A
// link not signed by the service is refused.
func TestOIDCHop(t *testing.T) {
	t.Parallel()

	for _, asJSON := range []bool{false, true} {
		name := "browser form"
		if asJSON {
			name = "json (spa and native)"
		}

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, f, _ := harness(t)

			var provider string

			k := newKratos(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/self-service/methods/oidc/callback/") {
					w.WriteHeader(http.StatusSeeOther)

					return
				}

				if asJSON {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusUnprocessableEntity)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"error": map[string]any{"id": "browser_location_change_required"}, "redirect_browser_to": provider,
					})

					return
				}

				w.Header().Set("Location", provider)
				w.WriteHeader(http.StatusSeeOther)
			})
			srv := public(t, f, k, "")

			// Kratos's callback, as the provider will reach it: the
			// deployment's public host with the /auth prefix.
			callback := srv.URL + "/auth/self-service/methods/oidc/callback/mock"
			provider = "https://idp.example/authorize?" + url.Values{
				"client_id": {"kratos"}, "state": {"st-1"}, "redirect_uri": {callback},
			}.Encode()

			r := do(t, http.MethodPost, srv.URL+"/self-service/login?flow=f-1", "application/json",
				`{"method":"oidc","provider":"mock"}`, nil)

			next := r.header.Get("Location")
			if asJSON {
				var body struct {
					RedirectBrowserTo string `json:"redirect_browser_to"`
				}

				_ = json.Unmarshal([]byte(r.body), &body)
				next = body.RedirectBrowserTo
			}

			if !strings.HasPrefix(next, srv.URL+"/auth"+flows.OIDCStartPath+"?t=") {
				t.Fatalf("start sends the browser to %q, want the hop", next)
			}

			hop := do(t, http.MethodGet, strings.Replace(next, "/auth", "", 1), "", "", nil)
			if hop.status != http.StatusSeeOther || hop.header.Get("Location") != provider {
				t.Fatalf("hop: %d to %q, want 303 to %q", hop.status, hop.header.Get("Location"), provider)
			}

			cookies := (&http.Response{Header: hop.header}).Cookies()
			if len(cookies) != 1 || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
				t.Fatalf("hop cookies %v", hop.header.Values("Set-Cookie"))
			}

			tampered := do(t, http.MethodGet, strings.Replace(next, "/auth", "", 1)+"x", "", "", nil)
			if tampered.status != http.StatusBadRequest || tampered.header.Get("Location") != "" ||
				len(tampered.header.Values("Set-Cookie")) > 0 {
				t.Fatalf("tampered hop: %d %v", tampered.status, tampered.header)
			}

			cb := do(t, http.MethodGet, srv.URL+"/self-service/methods/oidc/callback/mock?state=st-1&code=c", "", "",
				http.Header{"Cookie": {cookies[0].Name + "=" + cookies[0].Value}})

			headers := k.flowHeaders()
			if len(headers) != 2 || headers[0] == "" || headers[1] == "" {
				t.Fatalf("FlowHeader Kratos got %q, want one on the start and the callback", headers)
			}

			deleted := (&http.Response{Header: cb.header}).Cookies()
			if len(deleted) != 1 || deleted[0].Name != cookies[0].Name || deleted[0].MaxAge >= 0 {
				t.Fatalf("callback cookies %v, want the flow cookie deleted", cb.header.Values("Set-Cookie"))
			}

			// Another state's cookie vouches for nothing.
			do(t, http.MethodGet, srv.URL+"/self-service/methods/oidc/callback/mock?state=st-2&code=c", "", "",
				http.Header{"Cookie": {flows.FlowCookieFor("st-2") + "=" + cookies[0].Value}})

			if moved := k.flowHeaders(); len(moved) != 3 || moved[2] != "" {
				t.Fatalf("FlowHeader for a moved cookie %q, want none", moved)
			}
		})
	}
}

// The native exchange admits the session with the app's flow header
// unverified, as channel native_exchange; a denial answers 403 without
// the token.
func TestExchangeSessionIssued(t *testing.T) {
	t.Parallel()

	kratos := &sessions{after: stored()}
	h, f, _ := harnessWith(t, kratos)
	got := bindIssued(h, f, flows.SessionIssuedOut{Deny: &flows.SessionDeny{Code: "DEVICE_LIMIT"}}, nil)

	k := newKratos(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_token":"tok-1","session":{"id":"s-1","active":true,"authenticated_at":"` +
			time.Now().UTC().Format(time.RFC3339Nano) + `"}}`))
	})
	srv := public(t, f, k, errorUI)

	r := do(t, http.MethodGet, srv.URL+flows.TokenExchangePath+"?init_code=i&return_to_code=r", "", "",
		http.Header{flows.NativeFlowHeader: {"f-1"}})

	if r.status != http.StatusForbidden || strings.Contains(r.body, "tok-1") || !strings.Contains(r.body, "DEVICE_LIMIT") {
		t.Fatalf("exchange %d %s", r.status, r.body)
	}

	if len(*got) != 1 || (*got)[0].FlowID != "f-1" || (*got)[0].Channel != flows.ChannelNativeExchange {
		t.Fatalf("SessionIssued got %+v", *got)
	}

	if revoked := kratos.revoked(); len(revoked) != 1 || revoked[0] != "s-1" {
		t.Fatalf("revoked %v", revoked)
	}
}

// An OIDC link from a settings flow ends in the same callback, where Kratos
// sets the signed-in session's cookie again: the hop's cookie says it is a
// settings flow, so no admission. A callback without the start cookie is
// admitted with no flow (fail-closed).
func TestOIDCLinkNotAdmitted(t *testing.T) {
	t.Parallel()

	kratos := &sessions{who: new(stored()), after: stored()}
	h, f, _ := harnessWith(t, kratos)
	got := bindIssued(h, f, flows.SessionIssuedOut{Deny: &flows.SessionDeny{Code: "DEVICE_LIMIT"}}, nil)

	var provider string

	k := newKratos(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/self-service/methods/oidc/callback/") {
			w.Header().Add("Set-Cookie", "ory_kratos_session=sess-cookie; Path=/; HttpOnly")
		} else {
			w.Header().Set("Location", provider)
		}

		w.WriteHeader(http.StatusSeeOther)
	})
	srv := public(t, f, k, errorUI)
	provider = "https://idp.example/authorize?" + url.Values{
		"state": {"st-1"}, "redirect_uri": {srv.URL + "/self-service/methods/oidc/callback/mock"},
	}.Encode()

	start := do(t, http.MethodPost, srv.URL+"/self-service/settings?flow=f-s", "application/x-www-form-urlencoded",
		"method=oidc&link=mock", nil)
	hop := do(t, http.MethodGet, start.header.Get("Location"), "", "", nil)
	cookies := (&http.Response{Header: hop.header}).Cookies()

	if len(cookies) != 1 {
		t.Fatalf("settings link start: %d %q, hop cookies %v", start.status, start.header.Get("Location"), cookies)
	}

	link := do(t, http.MethodGet, srv.URL+"/self-service/methods/oidc/callback/mock?state=st-1&code=c", "", "",
		http.Header{"Cookie": {cookies[0].Name + "=" + cookies[0].Value}})
	if !strings.Contains(strings.Join(link.header.Values("Set-Cookie"), ";"), "ory_kratos_session=sess-cookie") ||
		len(*got) != 0 || len(kratos.revoked()) != 0 {
		t.Fatalf("settings link callback: cookies %v, SessionIssued %v, revoked %v",
			link.header.Values("Set-Cookie"), *got, kratos.revoked())
	}

	unknown := do(t, http.MethodGet, srv.URL+"/self-service/methods/oidc/callback/mock?state=st-9&code=c", "", "", nil)
	if unknown.header.Get("Location") != errorUI+"?id=session_refused&reason=DEVICE_LIMIT" || len(*got) != 1 ||
		(*got)[0].FlowID != "" || (*got)[0].Flow != "" {
		t.Fatalf("callback without a start: %d %q, SessionIssued %+v", unknown.status, unknown.header.Get("Location"), *got)
	}
}

// FedCM's token endpoint signs in: the session it issues is admitted.
func TestFedCMAdmitted(t *testing.T) {
	t.Parallel()

	kratos := &sessions{after: stored()}
	h, f, _ := harnessWith(t, kratos)
	got := bindIssued(h, f, flows.SessionIssuedOut{Deny: &flows.SessionDeny{Code: "DEVICE_LIMIT"}}, nil)

	k := newKratos(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"session_token":"tok-1","session":{"id":"s-1","active":true}}`))
	})
	srv := public(t, f, k, errorUI)

	r := do(t, http.MethodPost, srv.URL+"/self-service/fed-cm/token", "application/json", `{"token":"jwt"}`, nil)
	if r.status != http.StatusForbidden || strings.Contains(r.body, "tok-1") || len(*got) != 1 ||
		(*got)[0].Flow != "login" || len(kratos.revoked()) != 1 {
		t.Fatalf("fed-cm: %d %s, SessionIssued %+v, revoked %v", r.status, r.body, *got, kratos.revoked())
	}
}

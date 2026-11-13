package flows

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/hook"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

const (
	// SelfServicePath is the prefix of Kratos's self-service endpoints the
	// deployment routes to Public, all of it: any answer under it may
	// carry a session, and every one is admitted.
	SelfServicePath = "/self-service/"
	// OIDCStartPath is the hop a sign-in with a provider takes on its way
	// there: it sets the cookie that carries the client's flow to the
	// callback. It sits under Kratos's OIDC prefix, routed here with it.
	OIDCStartPath = "/self-service/methods/oidc/backplane/start"
	// oidcPrefix is Kratos's OIDC routes, the callbacks among them.
	oidcPrefix = "/self-service/methods/oidc/"
	// flowCookie (with the OIDC state's hash) names the OIDC flow cookie.
	flowCookie = "backplane_kratos_flow_"

	// maxSubmit bounds a flow submit's body, read before Kratos gets it.
	maxSubmit = 1 << 20
	// maxAnswer bounds a JSON answer of Kratos's read here.
	maxAnswer = 1 << 20
	// revokeWait bounds revoking a refused session; revokePause is the
	// first pause between tries, doubling up to a second.
	revokeWait  = 5 * time.Second
	revokePause = 20 * time.Millisecond
	// issuedPoint is the stats point of SessionIssued.
	issuedPoint = "session_issued"
)

// Errors a refused client gets (error.id).
const (
	errRefused     = "session_refused"
	errUnavailable = "session_unavailable"
)

var (
	// errNoCheck: the issued session could not be checked; it is refused.
	errNoCheck = errors.New("issued session not checked")
	// errUnreadable: Kratos's answer is encoded, too long or not the JSON
	// it says; the client gets a 502 instead.
	errUnreadable = errors.New("kratos's answer cannot be read whole")
)

// issuance is what the proxy knows of a request that may issue a session.
type issuance struct {
	kind, flowID string
	// channel is set for the native exchange; else the answer decides.
	channel   string
	transient json.RawMessage
	// oidcStart: the answer may send the browser to a provider.
	oidcStart bool
	// state is the OIDC callback's state whose cookie came with the
	// request; the answer deletes it.
	state string
}

// front serves Kratos's public endpoints that issue sessions.
type front struct {
	f        *Flows
	public   *url.URL
	headers  map[string]string
	settings config.Live[overlay.Settings]
}

// Public serves Kratos's public API in front of Kratos at public: logout,
// the session token exchange, the OIDC callbacks and start hop, and every
// other request, passed on. Every request to Kratos with a client flow
// carries FlowHeader for it; every session an answer issues is admitted by
// SessionIssued before its credential leaves. Settings and verification
// issue none: Kratos sets the cookie of a session that exists already. headers go with every
// request to Kratos; settings give the flows' lifespans and error page.
func (f *Flows) Public(
	public *url.URL, headers map[string]string, exchangeMaxAge time.Duration, settings config.Live[overlay.Settings],
) http.Handler {
	p := front{f: f, public: public, headers: headers, settings: settings}
	logout := f.Logout(public, headers)

	mux := http.NewServeMux()
	mux.Handle(LogoutPath, logout)
	mux.Handle(LogoutPath+"/", logout)
	mux.Handle("GET "+TokenExchangePath, f.TokenExchange(public, headers, exchangeMaxAge))

	mux.HandleFunc("GET "+OIDCStartPath, p.hop)
	mux.HandleFunc(oidcPrefix+"callback", p.callback)
	mux.HandleFunc(oidcPrefix+"callback/{provider}", p.callback)
	mux.HandleFunc(oidcPrefix+"organization/{organization}/callback/{provider}", p.callback)
	mux.HandleFunc("/", p.pass)

	return mux
}

// ttl is how long the proxy vouches for a client's flow: the longest
// lifespan of a flow that signs in.
func (p front) ttl() time.Duration {
	s := p.settings.Get()

	return max(s.Login.Lifespan, s.Registration.Lifespan, s.Recovery.Lifespan, time.Minute)
}

func (p front) expiry() int64 { return time.Now().Add(p.ttl()).Unix() }

// pass serves every other request: whatever path answers with a session
// (a submit, a recovery link's GET, FedCM's token), it is admitted. The
// flow kind is the path's (/self-service/<kind>...), the flow ?flow=; a
// POST's body is read for its transient payload.
func (p front) pass(w http.ResponseWriter, r *http.Request) {
	iss := issuance{kind: flowKind(r.URL.Path), flowID: r.URL.Query().Get("flow")}

	if r.Method == http.MethodPost {
		raw, err := io.ReadAll(io.LimitReader(r.Body, maxSubmit+1))
		if err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)

			return
		}

		if len(raw) > maxSubmit {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)

			return
		}

		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(raw)), int64(len(raw))
		iss.transient = transientPayload(r.Header.Get("Content-Type"), raw)
		iss.oidcStart = iss.kind == overlay.FlowLogin || iss.kind == overlay.FlowRegistration ||
			iss.kind == overlay.FlowSettings
	}

	p.forward(w, r, iss)
}

// flowKind is the flow of a self-service path: /self-service/<kind>...;
// FedCM signs in.
func flowKind(path string) string {
	rest, ok := strings.CutPrefix(path, SelfServicePath)
	if !ok {
		return ""
	}

	kind, _, _ := strings.Cut(rest, "/")
	if kind == "fed-cm" {
		return overlay.FlowLogin
	}

	return kind
}

// reissues: the flow sets the cookie of a session that exists already (the
// signed-in one in settings, a registration's in verification), issuing
// none.
func reissues(kind string) bool {
	return kind == overlay.FlowSettings || kind == overlay.FlowVerification
}

// transientPayload is a submit's transient_payload: a JSON body's object,
// a form's JSON string.
func transientPayload(contentType string, raw []byte) json.RawMessage {
	media, _, _ := mime.ParseMediaType(contentType)

	switch media {
	case "application/json":
		var body struct {
			TransientPayload json.RawMessage `json:"transient_payload"`
		}

		if json.Unmarshal(raw, &body) == nil && len(body.TransientPayload) > 0 && string(body.TransientPayload) != "null" {
			return body.TransientPayload
		}
	case "application/x-www-form-urlencoded":
		form, err := url.ParseQuery(string(raw))
		if v := form.Get("transient_payload"); err == nil && json.Valid([]byte(v)) {
			return json.RawMessage(v)
		}
	}

	return nil
}

// callback serves an OIDC callback: the client's flow comes from the
// cookie the hop set for its state.
func (p front) callback(w http.ResponseWriter, r *http.Request) {
	var iss issuance

	// The cookie is deleted only by the answer to the request that brought
	// it: a form_post callback (POST, cross-site) brings none, and Kratos
	// sends it on to the GET that does.
	if state := r.URL.Query().Get("state"); state != "" {
		if c, err := r.Cookie(flowCookie + stateHash(state)); err == nil {
			if pr, ok := p.f.open(purposeCookie+stateHash(state), c.Value); ok {
				iss.kind, iss.flowID, iss.state = pr.Kind, pr.Flow, state
			}
		}
	}

	p.forward(w, r, iss)
}

// hop sets the OIDC flow cookie and sends the browser on to the provider
// URL its link was signed for; any other link is refused.
func (p front) hop(w http.ResponseWriter, r *http.Request) {
	link, ok := p.f.open(purposeHop, r.URL.Query().Get("t"))

	target, err := url.Parse(link.To)
	if !ok || err != nil || target.Query().Get("state") == "" {
		http.Error(w, "the sign-in link is invalid or has expired", http.StatusBadRequest)

		return
	}

	state := stateHash(target.Query().Get("state"))

	http.SetCookie(w, &http.Cookie{
		Name:     flowCookie + state,
		Value:    p.f.seal(purposeCookie+state, proof{Kind: link.Kind, Flow: link.Flow, Exp: link.Exp}),
		Path:     "/",
		MaxAge:   int(time.Until(time.Unix(link.Exp, 0)).Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, link.To, http.StatusSeeOther)
}

// forward passes r to Kratos with FlowHeader for iss's flow and admits the
// session its answer issues.
func (p front) forward(w http.ResponseWriter, r *http.Request, iss issuance) {
	proxy := kratosProxy(p.public, p.headers)
	rewrite := proxy.Rewrite
	proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		rewrite(pr)

		if iss.flowID != "" {
			pr.Out.Header.Set(overlay.FlowHeader,
				p.f.seal(purposeHeader, proof{Kind: iss.kind, Flow: iss.flowID, Exp: p.expiry()}))
		}
	}
	ctx := r.Context()
	proxy.ModifyResponse = func(res *http.Response) error { return p.answer(ctx, res, iss) }
	proxy.ServeHTTP(w, r)
}

// answer is Kratos's answer as the client gets it: an OIDC start goes
// through the hop, an issued session is admitted.
func (p front) answer(ctx context.Context, res *http.Response, iss issuance) error {
	a, err := readAnswer(res)
	if err != nil {
		return err
	}

	if iss.oidcStart {
		p.viaHop(&a, iss)
	}

	if !reissues(iss.kind) {
		p.f.admit(ctx, &a, iss, p.settings.Get().ErrorUIURL)
	}

	if iss.state != "" {
		a.header.Add("Set-Cookie", (&http.Cookie{
			Name: flowCookie + stateHash(iss.state), Value: "", Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
		}).String())
	}

	a.write(res)

	return nil
}

// viaHop sends a browser bound for an OIDC provider through the hop.
func (p front) viaHop(a *answerOf, iss issuance) {
	if iss.flowID == "" {
		return
	}

	if hop, ok := p.hopURL(a.header.Get("Location"), iss); ok {
		a.header.Set("Location", hop)
	}

	if hop, ok := p.hopURL(a.field("redirect_browser_to"), iss); ok {
		a.setField("redirect_browser_to", hop)
	}
}

// hopURL is the hop for a provider URL target, on the host of its
// redirect_uri (Kratos's callback); false when target is no OIDC start.
func (p front) hopURL(target string, iss issuance) (string, bool) {
	provider, err := url.Parse(target)
	if target == "" || err != nil || provider.Query().Get("state") == "" {
		return "", false
	}

	callback, err := url.Parse(provider.Query().Get("redirect_uri"))
	if err != nil {
		return "", false
	}

	base, _, found := strings.Cut(callback.Path, oidcPrefix)
	if !found {
		return "", false
	}

	hop := url.URL{Scheme: callback.Scheme, Host: callback.Host, Path: base + OIDCStartPath}
	hop.RawQuery = url.Values{"t": {p.f.seal(purposeHop, proof{
		Kind: iss.kind, Flow: iss.flowID, To: target, Exp: p.expiry(),
	})}}.Encode()

	return hop.String(), true
}

// answerOf is Kratos's answer being rewritten.
type answerOf struct {
	status int
	header http.Header
	// body is the JSON body; nil for any other.
	body map[string]json.RawMessage
	raw  []byte
	// replaced: raw is a new body.
	replaced bool
}

// readAnswer takes res's body when it is JSON.
func readAnswer(res *http.Response) (answerOf, error) {
	a := answerOf{status: res.StatusCode, header: res.Header}

	media, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if media != "application/json" {
		return a, nil
	}

	raw, err := readBody(res, maxAnswer)
	if err != nil {
		return a, err
	}

	if !json.Valid(raw) {
		return a, errUnreadable
	}

	a.raw, a.replaced = raw, true
	if json.Unmarshal(raw, &a.body) != nil {
		a.body = nil
	}

	return a, nil
}

// readBody is res's whole body, up to limit. A body this proxy cannot read
// whole (encoded, longer) is refused, never passed on: the session it may
// carry would leave unchecked.
func readBody(res *http.Response, limit int64) ([]byte, error) {
	defer func() { _ = res.Body.Close() }()

	if res.Header.Get("Content-Encoding") != "" {
		return nil, errUnreadable
	}

	raw, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read kratos's answer: %w", err)
	}

	if int64(len(raw)) > limit {
		return nil, errUnreadable
	}

	return raw, nil
}

// field is a string field of the JSON body; empty when there is none.
func (a *answerOf) field(name string) string {
	var s string

	_ = json.Unmarshal(a.body[name], &s)

	return s
}

func (a *answerOf) setField(name, value string) {
	v, err := json.Marshal(value)
	if err != nil {
		return
	}

	a.body[name] = v

	raw, err := json.Marshal(a.body)
	if err != nil {
		return
	}

	a.raw, a.replaced = raw, true
}

// replace makes the answer status with a JSON body.
func (a *answerOf) replace(status int, body any) {
	raw, err := json.Marshal(body)
	if err != nil {
		raw = []byte(`{}`)
	}

	a.status, a.raw, a.replaced = status, raw, true
	a.header.Set("Content-Type", "application/json")
	a.header.Del("Location")
}

// redirect makes the answer a 303 to location.
func (a *answerOf) redirect(location string) {
	a.status, a.raw, a.replaced = http.StatusSeeOther, nil, true
	a.header.Set("Location", location)
	a.header.Del("Content-Type")
}

func (a *answerOf) write(res *http.Response) {
	res.StatusCode, res.Status = a.status, strconv.Itoa(a.status)+" "+http.StatusText(a.status)

	if !a.replaced {
		return
	}

	res.Body = io.NopCloser(bytes.NewReader(a.raw))
	res.ContentLength = int64(len(a.raw))
	res.Header.Set("Content-Length", strconv.Itoa(len(a.raw)))
}

// issuedSession is the session an answer issues and the channel its credential
// leaves by; sid empty when it issues none. A session that cannot be used
// yet (a second factor is required) issues none: SessionIssued sees it
// once the step-up completes.
func (f *Flows) issuedSession(ctx context.Context, a *answerOf) (string, string, error) {
	var body struct {
		Session struct {
			ID string `json:"id"`
		} `json:"session"`
		SessionToken string `json:"session_token"`
		ContinueWith []struct {
			Action string `json:"action"`
			Token  string `json:"ory_session_token"`
		} `json:"continue_with"`
	}

	if a.raw != nil {
		_ = json.Unmarshal(a.raw, &body)
	}

	token := body.SessionToken
	for _, c := range body.ContinueWith {
		if c.Action == "set_ory_session_token" && token == "" {
			token = c.Token
		}
	}

	channel, cookie := ChannelBrowser, ""
	if token != "" {
		channel = ChannelAPI
	}

	if body.Session.ID != "" {
		return body.Session.ID, channel, nil
	}

	if token == "" {
		if cookie = sessionCookies(a.header); cookie == "" {
			return "", channel, nil
		}
	}

	s, err := f.sessions.WhoAmI(ctx, token, cookie)

	var e *ory.Error

	switch {
	case err == nil:
		return s.ID, channel, nil
	case errors.As(err, &e) && (e.Status == http.StatusUnauthorized || e.Status == http.StatusForbidden):
		// No session among the cookies, or one awaiting a second factor.
		return "", channel, nil
	default:
		return "", channel, errors.Join(errNoCheck, err)
	}
}

// sessionCookies is a Cookie header of the cookies an answer sets that may
// be a session's: not Kratos's CSRF or continuity cookies, not this
// service's, not deletions.
func sessionCookies(h http.Header) string {
	var out []string

	for _, c := range (&http.Response{Header: h}).Cookies() {
		if c.Value == "" || c.MaxAge < 0 || strings.HasPrefix(c.Name, "csrf_token") ||
			c.Name == "ory_kratos_continuity" || strings.HasPrefix(c.Name, flowCookie) {
			continue
		}

		out = append(out, c.Name+"="+c.Value)
	}

	return strings.Join(out, "; ")
}

// admit runs SessionIssued for the session the answer issues; refused,
// the session is revoked and the answer refuses the client.
func (f *Flows) admit(ctx context.Context, a *answerOf, iss issuance, errorURL string) {
	if !f.issued.Bound() {
		return
	}

	start := time.Now()

	sid, channel, err := f.issuedSession(ctx, a)
	if sid == "" && err == nil {
		return
	}

	if iss.channel != "" {
		channel = iss.channel
	}

	var session ory.Session

	if err == nil {
		session, err = f.sessions.GetSession(ctx, sid)
	}

	var out SessionIssuedOut

	if err == nil {
		in := SessionIssuedIn{
			Flow: iss.kind, Method: lastMethod(session), FlowID: iss.flowID, Channel: channel, Session: session,
			TransientPayload: iss.transient,
		}
		if session.Identity != nil {
			in.Identity = *session.Identity
		}

		in.Session.Identity = nil

		out, err = f.issued.Call(ctx, in)
	}

	switch {
	case errors.Is(err, hook.ErrNoBinding):
		f.record(issuedPoint, start, outcomeUnbound, nil)
	case err != nil:
		f.Log().Ctx().Warn(ctx, "new session refused: SessionIssued failed", xlog.String("session", sid), xlog.Err(err))
		f.record(issuedPoint, start, "failed", err)
		f.refuse(ctx, a, sid, errorURL, refusal{
			id: errUnavailable, status: http.StatusServiceUnavailable, reason: "unavailable",
			messages: []Message{{ID: UnavailableMessage, Text: "This is unavailable right now. Please try again later."}},
		})
	case out.Deny != nil:
		f.record(issuedPoint, start, "denied", nil)
		f.refuse(ctx, a, sid, errorURL, refusal{
			id: errRefused, status: http.StatusForbidden, reason: out.Deny.Code, messages: out.Deny.Messages,
		})
	default:
		f.record(issuedPoint, start, "admitted", nil)
	}
}

// revoke ends the session sid, trying again until revokeWait: Kratos
// refuses a revoke that races its own write to the session ("concurrent
// update", a 400). Revoking is idempotent; a session Kratos no longer
// knows is ended.
func (f *Flows) revoke(ctx context.Context, sid string) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeWait)
	defer cancel()

	for pause := revokePause; ; pause = min(pause<<1, time.Second) {
		err := f.sessions.DisableSession(ctx, sid)
		if err == nil || ory.IsNotFound(err) {
			return nil
		}

		select {
		case <-ctx.Done():
			return errors.Join(err, ctx.Err())
		case <-time.After(jitter(pause)):
		}
	}
}

// jitter is a random duration in [d/2, d).
func jitter(d time.Duration) time.Duration {
	half := d >> 1

	n, err := rand.Int(rand.Reader, big.NewInt(int64(half)))
	if err != nil {
		return d
	}

	return half + time.Duration(n.Int64())
}

// lastMethod is the method a session was last authenticated with.
func lastMethod(s ory.Session) string {
	if len(s.AuthenticationMethods) == 0 {
		return ""
	}

	return s.AuthenticationMethods[len(s.AuthenticationMethods)-1].Method
}

// refusal is what a refused client gets.
type refusal struct {
	id       string
	status   int
	reason   string
	messages []Message
}

// kratosError is Kratos's error body.
type kratosError struct {
	Error kratosErrorBody `json:"error"`
}

type kratosErrorBody struct {
	ID      string         `json:"id"`
	Code    int            `json:"code"`
	Status  string         `json:"status"`
	Reason  string         `json:"reason"`
	Message string         `json:"message"`
	Details refusalDetails `json:"details"`
}

type refusalDetails struct {
	Messages []Message `json:"messages"`
}

// refuse revokes the session sid and makes the answer refuse the client
// with no credential: no cookie, no token. A browser form flow is sent to
// errorURL (?id=&reason=); JSON clients get Kratos's error shape.
func (f *Flows) refuse(ctx context.Context, a *answerOf, sid, errorURL string, r refusal) {
	if sid != "" {
		if err := f.revoke(ctx, sid); err != nil {
			f.Log().Ctx().Error(ctx, "refused session not revoked: the client got no credential, end it in Kratos",
				xlog.String("session", sid), xlog.Err(err))
		}
	}

	a.header.Del("Set-Cookie")

	if a.raw == nil && errorURL != "" {
		u, err := url.Parse(errorURL)
		if err == nil {
			q := u.Query()
			q.Set("id", r.id)
			q.Set("reason", r.reason)
			u.RawQuery = q.Encode()
			a.redirect(u.String())

			return
		}
	}

	messages := r.messages
	if messages == nil {
		messages = []Message{}
	}

	a.replace(r.status, kratosError{Error: kratosErrorBody{
		ID: r.id, Code: r.status, Status: http.StatusText(r.status), Reason: r.reason,
		Message: "The session was refused", Details: refusalDetails{Messages: messages},
	}})
}

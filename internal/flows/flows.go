package flows

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/event"
	"github.com/backplane-labs/backplane/pkg/backplane/hook"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// Timeouts of the hooks: Kratos waits for flow hooks while a user waits.
const (
	flowTimeout    = 5 * time.Second
	deliverTimeout = 30 * time.Second
	maxCallback    = 4 << 20

	// storedWait bounds the wait for a login's session to be stored.
	storedWait = 30 * time.Second
	// storedPoll is the first pause between looks for it; it doubles.
	storedPoll = 10 * time.Millisecond
)

// errNotStored: the login's session never appeared in Kratos.
var errNotStored = errors.New("session of the login not stored")

// Sessions reads an identity's sessions from Kratos.
type Sessions interface {
	ListIdentitySessions(ctx context.Context, id string, f ory.SessionFilter) (ory.Page[ory.Session], error)
}

// outcomeUnbound: the hook had no binding; the flow continued.
const outcomeUnbound = "unbound"

// UnavailableMessage is shown when a flow hook fails and is not fail-open.
const UnavailableMessage = 5000001

// Flows declares the hooks and events and serves Kratos's callbacks.
type Flows struct {
	deps.Component

	key      string
	failOpen config.Live[[]string]
	sessions Sessions

	deliver hook.Ref[DeliverIn, DeliverOut]
	points  map[string]hook.Ref[FlowIn, FlowOut] // by hook name
	events  map[string]event.Ref[FlowEvent]      // by flow

	mu    sync.Mutex
	stats map[string]*Stat
}

// Stat is how one callback point has been doing since start.
type Stat struct {
	Point       string
	Calls       uint64
	Failures    uint64
	LastAt      time.Time
	LastOutcome string
	LastError   string
	LastLatency time.Duration
}

// eventName is the event of a completed flow.
func eventName(flow string) string {
	switch flow {
	case overlay.FlowRegistration:
		return "Registered"
	case overlay.FlowLogin:
		return "LoggedIn"
	case overlay.FlowSettings:
		return "SettingsChanged"
	case overlay.FlowRecovery:
		return "Recovered"
	default:
		return "Verified"
	}
}

// New declares the hooks and events under parent; key authenticates
// Kratos; hooks named in failOpen let the flow continue when they fail;
// sessions confirms a login's session is stored before LoggedIn.
func New(parent deps.Scope, key string, failOpen config.Live[[]string], sessions Sessions) *Flows {
	f := &Flows{
		Component: deps.NewComponent(parent, "flows"), key: key, failOpen: failOpen, sessions: sessions,
		points: map[string]hook.Ref[FlowIn, FlowOut]{}, events: map[string]event.Ref[FlowEvent]{},
		stats: map[string]*Stat{},
	}

	f.deliver = hook.Declare[DeliverIn, DeliverOut](f, overlay.DeliverHook, hook.DefaultTimeout(deliverTimeout),
		hook.Describe("Deliver a message of Kratos's courier (codes, links); an error makes Kratos retry it"))

	for _, flow := range overlay.Flows() {
		for _, when := range []string{"before", "after"} {
			name := overlay.HookName(when, flow)
			f.points[name] = hook.Declare[FlowIn, FlowOut](f, name, hook.DefaultTimeout(flowTimeout),
				hook.Describe(describePoint(when, flow)))
		}

		f.events[flow] = event.Declare[FlowEvent](f, eventName(flow),
			event.Describe("an identity completed the "+flow+" flow"))
	}

	return f
}

func describePoint(when, flow string) string {
	if when == "before" {
		return "Kratos is starting a " + flow + " flow: deny it or let it continue"
	}

	switch flow {
	case overlay.FlowRegistration, overlay.FlowSettings:
		return "Kratos is completing a " + flow + " flow: deny it, change the identity or let it continue"
	default:
		return "Kratos is completing a " + flow + " flow: deny it or let it continue"
	}
}

// Bound reports whether a hook (short name) is bound.
func (f *Flows) Bound(name string) bool {
	if name == overlay.DeliverHook {
		return f.deliver.Bound()
	}

	ref, ok := f.points[name]

	return ok && ref.Bound()
}

// Hooks are the declared hook names, Deliver first.
func (f *Flows) Hooks() []string {
	out := make([]string, 0, 1+2*len(overlay.Flows()))
	out = append(out, overlay.DeliverHook)

	for _, flow := range overlay.Flows() {
		out = append(out, overlay.HookName("before", flow), overlay.HookName("after", flow))
	}

	return out
}

// BindingChanges signals when the set of bound hooks changes.
func (f *Flows) BindingChanges(ctx context.Context) <-chan struct{} {
	return f.deliver.BindingChanges(ctx)
}

// Stats of every point called since start, by point.
func (f *Flows) Stats() []Stat {
	f.mu.Lock()
	defer f.mu.Unlock()

	out := make([]Stat, 0, len(f.stats))
	for _, s := range f.stats {
		out = append(out, *s)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Point < out[j].Point })

	return out
}

func (f *Flows) record(point string, start time.Time, outcome string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	s := f.stats[point]
	if s == nil {
		s = &Stat{Point: point}
		f.stats[point] = s
	}

	s.Calls++
	s.LastAt, s.LastOutcome, s.LastLatency, s.LastError = time.Now(), outcome, time.Since(start), ""

	if err != nil {
		s.Failures++
		s.LastError = err.Error()
	}
}

// Handler serves the callbacks: /courier/{channel}, /hooks/{when}/{flow}/{method},
// /events/{flow}/{method}.
func (f *Flows) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /courier/{channel}", f.courier)
	mux.HandleFunc("POST /hooks/{when}/{flow}/{method}", f.hook)
	mux.HandleFunc("POST /events/{flow}/{method}", f.event)

	return f.authorized(mux)
}

func (f *Flows) authorized(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(overlay.KeyHeader)), []byte(f.key)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)

			return
		}

		next.ServeHTTP(w, r)
	})
}

// kratosCtx is the Jsonnet context Kratos posts (overlay's body).
type kratosCtx struct {
	Flow struct {
		ID               string          `json:"id"`
		Type             string          `json:"type"`
		TransientPayload json.RawMessage `json:"transient_payload"`
	} `json:"flow"`
	Identity json.RawMessage `json:"identity"`
	// Session of a login; Kratos stores it, giving it its id, only after
	// the hooks ran.
	Session        *ory.Session        `json:"session"`
	RequestHeaders map[string][]string `json:"request_headers"`
	RequestMethod  string              `json:"request_method"`
	RequestURL     string              `json:"request_url"`

	// Courier messages.
	Recipient    string                     `json:"recipient"`
	Subject      string                     `json:"subject"`
	Body         string                     `json:"body"`
	HTMLBody     string                     `json:"html_body"`
	TemplateType string                     `json:"template_type"`
	TemplateData map[string]json.RawMessage `json:"template_data"`
}

func decode(r *http.Request) (kratosCtx, []byte, error) {
	var c kratosCtx

	raw, err := io.ReadAll(io.LimitReader(r.Body, maxCallback))
	if err != nil {
		return c, nil, fmt.Errorf("read callback: %w", err)
	}

	if err := json.Unmarshal(raw, &c); err != nil {
		return c, nil, fmt.Errorf("decode callback: %w", err)
	}

	return c, raw, nil
}

func (f *Flows) courier(w http.ResponseWriter, r *http.Request) {
	start, point := time.Now(), "courier/"+r.PathValue("channel")

	c, raw, err := decode(r)
	if err != nil {
		f.record(point, start, "bad_request", err)
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	in := DeliverIn{
		Channel: r.PathValue("channel"), Recipient: c.Recipient, TemplateType: c.TemplateType,
		Rendered: Rendered{Subject: c.Subject, Body: c.Body, HTML: c.HTMLBody},
	}
	splitTemplateData(&in, c.TemplateData)

	// Kratos retries the same message: one key per message content.
	sum := sha256.Sum256(raw)

	_, err = f.deliver.Call(r.Context(), in, hook.Key("kratos-message-"+hex.EncodeToString(sum[:16])))
	if err != nil {
		f.record(point, start, "failed", err)
		f.Log().Ctx().Warn(r.Context(), "courier message not delivered: kratos retries it",
			xlog.String("template_type", in.TemplateType), xlog.Err(err))
		http.Error(w, "delivery failed", http.StatusBadGateway)

		return
	}

	f.record(point, start, "delivered", nil)
	w.WriteHeader(http.StatusOK)
}

// splitTemplateData moves the code and link out of Kratos's template
// data (they are secret) and keeps the rest as Data.
func splitTemplateData(in *DeliverIn, data map[string]json.RawMessage) {
	rest := map[string]json.RawMessage{}

	for k, v := range data {
		var s string

		switch {
		case k == "identity":
			in.Identity = v
		case k == "transient_payload":
			in.TransientPayload = v
		case k == "expires_in_minutes":
			_ = json.Unmarshal(v, &in.ExpiresInMinutes)
		case k == "to":
		case strings.HasSuffix(k, "_code") && json.Unmarshal(v, &s) == nil:
			in.Code = s
		case strings.HasSuffix(k, "_url") && k != "request_url" && json.Unmarshal(v, &s) == nil:
			in.Link = s
		default:
			rest[k] = v
		}
	}

	if len(rest) > 0 {
		in.Data, _ = json.Marshal(rest) //nolint:errchkjson // raw JSON values marshal
	}
}

func (c kratosCtx) flowIn(flow, method string) FlowIn {
	headers := map[string]string{}

	for k, vs := range c.RequestHeaders {
		if strings.EqualFold(k, "Cookie") || strings.EqualFold(k, "Authorization") || len(vs) == 0 {
			continue
		}

		headers[k] = strings.Join(vs, ", ")
	}

	in := FlowIn{
		Flow: flow, Method: method, FlowID: c.Flow.ID, FlowType: c.Flow.Type, Identity: c.Identity,
		TransientPayload: c.Flow.TransientPayload, RequestURL: c.RequestURL, RequestMethod: c.RequestMethod,
		RequestHeaders: headers,
	}
	if len(in.Identity) == 0 || string(in.Identity) == "null" {
		in.Identity = nil
	}

	return in
}

// kratosMessages is Kratos's interrupt body.
type kratosMessages struct {
	Messages []kratosField `json:"messages"`
}

type kratosField struct {
	InstancePtr string          `json:"instance_ptr"`
	Messages    []kratosMessage `json:"messages"`
}

type kratosMessage struct {
	ID      int64           `json:"id"`
	Text    string          `json:"text"`
	Type    string          `json:"type"`
	Context json.RawMessage `json:"context,omitempty"`
}

func (d *Deny) kratos() kratosMessages {
	byField := map[string][]kratosMessage{}

	var order []string

	for _, m := range d.Messages {
		ptr := "#/" + strings.ReplaceAll(m.Field, ".", "/")
		if m.Field == "" {
			ptr = "#"
		}

		if _, seen := byField[ptr]; !seen {
			order = append(order, ptr)
		}

		typ := m.Type
		if typ == "" {
			typ = "error"
		}

		ctx := m.Context
		if len(ctx) == 0 {
			ctx = json.RawMessage("{}")
		}

		byField[ptr] = append(byField[ptr], kratosMessage{ID: m.ID, Text: m.Text, Type: typ, Context: ctx})
	}

	out := kratosMessages{Messages: []kratosField{}}
	for _, ptr := range order {
		out.Messages = append(out.Messages, kratosField{InstancePtr: ptr, Messages: byField[ptr]})
	}

	return out
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v) //nolint:errchkjson // the client went away
}

func (f *Flows) hook(w http.ResponseWriter, r *http.Request) {
	when, flow, method := r.PathValue("when"), r.PathValue("flow"), r.PathValue("method")
	name := overlay.HookName(when, flow)
	start, point := time.Now(), "hooks/"+when+"/"+flow

	ref, ok := f.points[name]
	if !ok || (when != "before" && when != "after") {
		http.NotFound(w, r)

		return
	}

	c, _, err := decode(r)
	if err != nil {
		f.record(point, start, "bad_request", err)
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	if !ref.Bound() {
		f.record(point, start, outcomeUnbound, nil)
		writeJSON(w, http.StatusOK, map[string]any{})

		return
	}

	out, err := ref.Call(r.Context(), c.flowIn(flow, method))
	status, body, outcome := f.verdict(name, when, flow, out, err)

	if err != nil && outcome != outcomeUnbound {
		f.Log().Ctx().Warn(r.Context(), "flow hook failed", xlog.String("hook", name),
			xlog.String("outcome", outcome), xlog.Err(err))
	}

	if outcome == outcomeUnbound {
		err = nil
	}

	f.record(point, start, outcome, err)
	writeJSON(w, status, body)
}

// verdict is Kratos's answer to a hook's result: status, body, outcome.
func (f *Flows) verdict(name, when, flow string, out FlowOut, err error) (int, any, string) {
	changes := when == "after" && (flow == overlay.FlowRegistration || flow == overlay.FlowSettings)

	switch {
	case errors.Is(err, hook.ErrNoBinding):
		return http.StatusOK, map[string]any{}, outcomeUnbound
	case err != nil && slices.Contains(f.failOpen.Get(), name):
		return http.StatusOK, map[string]any{}, "failed_open"
	case err != nil:
		return http.StatusBadRequest, (&Deny{Messages: []Message{{
			ID: UnavailableMessage, Text: "This is unavailable right now. Please try again later.",
		}}}).kratos(), "failed"
	case out.Deny != nil && len(out.Deny.Messages) > 0:
		return http.StatusBadRequest, out.Deny.kratos(), "denied"
	case out.Identity != nil && changes:
		return http.StatusOK, map[string]any{"identity": out.Identity}, "changed"
	default:
		return http.StatusOK, map[string]any{}, "continued"
	}
}

func (f *Flows) event(w http.ResponseWriter, r *http.Request) {
	flow, method := r.PathValue("flow"), r.PathValue("method")
	start, point := time.Now(), "events/"+flow

	ref, ok := f.events[flow]
	if !ok {
		http.NotFound(w, r)

		return
	}

	c, _, err := decode(r)
	if err != nil {
		f.record(point, start, "bad_request", err)
		http.Error(w, "bad request", http.StatusBadRequest)

		return
	}

	var id struct {
		ID       string          `json:"id"`
		SchemaID string          `json:"schema_id"`
		Traits   json.RawMessage `json:"traits"`
	}

	_ = json.Unmarshal(c.Identity, &id)

	if id.ID == "" {
		f.record(point, start, "no_identity", nil)
		w.WriteHeader(http.StatusOK)

		return
	}

	flowEvent := &kratoseventsv1.FlowEvent{
		IdentityId: id.ID, SchemaId: id.SchemaID, Method: method, FlowId: c.Flow.ID, Traits: events.Traits(id.Traits),
	}

	// Kratos does not wait for this answer: the event is best effort.
	if flow == overlay.FlowLogin && c.Session != nil && c.Session.AuthenticatedAt != nil {
		// LoggedIn means the session exists: wait for Kratos to store it.
		go f.publishLogin(context.WithoutCancel(r.Context()), ref, flowEvent, *c.Session, point, start)
	} else {
		f.publish(r.Context(), ref, flowEvent, flow, point, start)
	}

	w.WriteHeader(http.StatusOK)
}

func (f *Flows) publish(
	ctx context.Context, ref event.Ref[FlowEvent], flowEvent FlowEvent, flow, point string, start time.Time,
) {
	if err := ref.Publish(ctx, flowEvent, event.Key(flowEvent.GetIdentityId()),
		event.ID(flow+"-"+flowEvent.GetFlowId()+"-"+flowEvent.GetMethod())); err != nil {
		f.record(point, start, "failed", err)
		f.Log().Ctx().Warn(ctx, "flow event not published", xlog.String("flow", flow), xlog.Err(err))

		return
	}

	f.record(point, start, "published", nil)
}

// publishLogin publishes LoggedIn with the login's session once Kratos has
// stored it; a session never stored (the login failed after the hooks)
// publishes nothing.
func (f *Flows) publishLogin(ctx context.Context, ref event.Ref[FlowEvent], flowEvent FlowEvent, s ory.Session,
	point string, start time.Time,
) {
	ctx, cancel := context.WithTimeout(ctx, storedWait)
	defer cancel()

	stored, err := f.stored(ctx, flowEvent.GetIdentityId(), *s.AuthenticatedAt)
	if err != nil {
		f.record(point, start, "not_stored", err)
		f.Log().Ctx().Warn(ctx, "login event not published",
			xlog.String("identity", flowEvent.GetIdentityId()), xlog.Err(err))

		return
	}

	session := &kratoseventsv1.Session{
		Id: stored.ID, AuthenticatedAt: timestamppb.New(*stored.AuthenticatedAt), Aal: s.AuthenticatorAssuranceLevel,
	}
	if len(s.Devices) > 0 {
		d := s.Devices[len(s.Devices)-1]
		session.IpAddress, session.UserAgent, session.Location = d.IPAddress, d.UserAgent, d.Location
	}

	flowEvent.Session = session

	f.publish(ctx, ref, flowEvent, overlay.FlowLogin, point, start)
}

// stored waits for the identity's session authenticated then: Kratos keeps
// timestamps to the microsecond.
func (f *Flows) stored(ctx context.Context, identity string, authenticated time.Time) (ory.Session, error) {
	active := true
	pause := storedPoll

	for {
		page, err := f.sessions.ListIdentitySessions(ctx, identity, ory.SessionFilter{Active: &active})
		if err == nil {
			for _, s := range page.Items {
				if s.AuthenticatedAt != nil && s.AuthenticatedAt.Sub(authenticated).Abs() < time.Millisecond {
					return s, nil
				}
			}
		}

		select {
		case <-ctx.Done():
			return ory.Session{}, errors.Join(errNotStored, err)
		case <-time.After(pause):
		}

		pause = min(pause<<1, time.Second)
	}
}

// DeliverRef, Point and Event are the declared refs (tests, wiring code).
func (f *Flows) DeliverRef() hook.Ref[DeliverIn, DeliverOut] { return f.deliver }

// Point is a flow hook by name, e.g. AfterRegistration.
func (f *Flows) Point(name string) hook.Ref[FlowIn, FlowOut] { return f.points[name] }

// Event is a flow's completion event.
func (f *Flows) Event(flow string) event.Ref[FlowEvent] { return f.events[flow] }

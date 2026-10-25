// Package it tests backplane-kratos against a real Kratos (make it-up): the
// overlay is written where that Kratos reads it and its callbacks reach
// this test's listener.
package it_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-kratos/internal/activities"
	"github.com/backplane-labs/backplane-kratos/internal/apply"
	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

const (
	adminURL  = "http://127.0.0.1:34434"
	publicURL = "http://127.0.0.1:34433"
	key       = "it-key"
	password  = "Very-Long-Pass-123!x"
)

// env is one started backplane-kratos against the shared Kratos.
type env struct {
	h          *backplanetest.Harness
	flows      *flows.Flows
	activities *activities.Activities
	settings   config.Live[overlay.Settings]
	tokenKey   config.Live[config.Secret]
	kratos     ory.Client
}

// defaults are Settings's schema defaults (Kratos's own).
func defaults() overlay.Settings {
	return overlay.Settings{
		Registration: overlay.Registration{
			Enabled:    true,
			Lifespan:   time.Hour,
			LoginAfter: true,
			Style:      "profile_first",
		},
		Login: overlay.Login{Lifespan: time.Hour, Style: "unified"},
		Settings: overlay.SettingsFlow{
			Lifespan: time.Hour, PrivilegedSessionMaxAge: time.Hour, RequiredAAL: "highest_available",
		},
		Recovery:     overlay.Recovery{Enabled: true, Lifespan: time.Hour, Use: "code"},
		Verification: overlay.Verification{Enabled: true, Lifespan: time.Hour, Use: "code"},
		Methods: overlay.Methods{
			Password: overlay.Password{Enabled: true, MinLength: 8, IdentifierSimilarityCheck: true},
			Code:     overlay.Code{Enabled: true, Lifespan: time.Hour},
			Profile:  overlay.ToggleOn{Enabled: true},
		},
		Features: overlay.Features{ContinueWith: true},
		Session: overlay.Session{
			Lifespan: 24 * time.Hour, WhoamiRequiredAAL: "highest_available", CookiePersistent: true, CookieSameSite: "Lax",
		},
	}
}

// The tests share one Kratos and one overlay: they run one at a time.
var serial sync.Mutex

func start(t *testing.T, bind func(*backplanetest.Harness, *flows.Flows)) env {
	t.Helper()

	return startWith(t, nil, bind)
}

// startWith is start with the settings changed by edit.
func startWith(t *testing.T, edit func(*overlay.Settings), bind func(*backplanetest.Harness, *flows.Flows)) env {
	t.Helper()

	return startKeyed(t, "", edit, bind)
}

// startKeyed is startWith with token_key set to tokenKey.
func startKeyed(t *testing.T, tokenKey string, edit func(*overlay.Settings), bind func(*backplanetest.Harness, *flows.Flows)) env {
	t.Helper()

	path := os.Getenv("KRATOS_IT_OVERLAY")
	if path == "" {
		t.Skip("KRATOS_IT_OVERLAY not set: make it-up it")
	}

	serial.Lock()
	t.Cleanup(serial.Unlock)

	lis, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	client, err := ory.New(ory.Options{Admin: adminURL, Public: publicURL})
	if err != nil {
		t.Fatal(err)
	}

	h := backplanetest.New(t, backplanetest.Name("kratos"))

	settings := defaults()
	if edit != nil {
		edit(&settings)
	}

	e := env{h: h, kratos: client, settings: config.LiveOf(settings), tokenKey: config.LiveOf(config.Secret(tokenKey))}
	e.flows = flows.New(h.Root(), key, config.LiveOf([]string(nil)), client)
	e.activities = activities.New(h.Root(), client)
	apply.New(h.Root(), path, 0o644, e.settings, apply.Secrets{
		OIDC: config.LiveOf(
			map[string]config.Secret{},
		), OAuth2ProviderHeaders: config.LiveOf(map[string]config.Secret{}),
		TokenKey: e.tokenKey,
	}, e.flows, overlay.Wiring{
		URL: "http://" + lis.Addr().String(), Key: key, Events: true,
	})

	if bind != nil {
		bind(h, e.flows)
	}

	srv := &http.Server{Handler: e.flows.Handler(), ReadHeaderTimeout: time.Second}

	go func() { _ = srv.Serve(lis) }()

	t.Cleanup(func() { _ = srv.Close() })

	h.Start()

	// Kratos reloads the file within a second or two; the callbacks URL
	// is new for every test, so a registration flow proves the reload.
	waitFor(t, "the overlay names this test's callbacks", func() bool {
		raw, err := os.ReadFile(path)

		return err == nil && bytes.Contains(raw, []byte(lis.Addr().String()))
	})

	// Kratos echoes nothing of its configuration: give its file watcher
	// the time it needs.
	time.Sleep(reload)

	return e
}

// reload is how long Kratos takes to see a changed file.
const reload = 2 * time.Second

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.Now().Add(20 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("not reached: %s", what)
		}

		time.Sleep(200 * time.Millisecond)
	}
}

// call is a JSON request to Kratos's public API.
func call(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()

	return callAs(t, "", method, path, body)
}

// callAs is call with a session token.
func callAs(t *testing.T, token, method, path string, body any) (int, map[string]any) {
	t.Helper()

	var in io.Reader

	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}

		in = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(t.Context(), method, publicURL+path, in)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	if token != "" {
		req.Header.Set("X-Session-Token", token)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var out map[string]any

	_ = json.NewDecoder(res.Body).Decode(&out)

	return res.StatusCode, out
}

func register(t *testing.T, email string) (int, map[string]any) {
	t.Helper()

	code, flow := call(t, http.MethodGet, "/self-service/registration/api", nil)
	if code != http.StatusOK {
		return code, flow
	}

	return call(t, http.MethodPost, fmt.Sprintf("/self-service/registration?flow=%v", flow["id"]),
		map[string]any{"method": "password", "traits": map[string]any{"email": email}, "password": password})
}

func unique(prefix string) string {
	return fmt.Sprintf("%s-%d@example.com", prefix, time.Now().UnixNano())
}

// awaitMessage waits for the message of kind to recipient. Kratos's
// courier queue is shared by the tests: a message queued by another one
// may reach this test's Deliver first, and is skipped.
func awaitMessage(t *testing.T, messages <-chan flows.DeliverIn, recipient, kind string) flows.DeliverIn {
	t.Helper()

	deadline := time.After(30 * time.Second)

	for {
		select {
		case msg := <-messages:
			if msg.Recipient == recipient && msg.TemplateType == kind {
				return msg
			}
		case <-deadline:
			t.Fatalf("no %s message to %s reached Deliver", kind, recipient)
		}
	}
}

// Kratos's verification mail reaches Deliver; its code verifies the address.
func TestDeliverVerifies(t *testing.T) {
	t.Parallel()

	codes := make(chan flows.DeliverIn, 64)

	e := start(t, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.DeliverRef(), func(_ context.Context, in flows.DeliverIn) (flows.DeliverOut, error) {
			codes <- in

			return flows.DeliverOut{}, nil
		})
	})

	email := unique("verify")

	status, reg := register(t, email)
	if status != http.StatusOK {
		t.Fatalf("registration: %d %v", status, reg)
	}

	msg := awaitMessage(t, codes, email, "verification_code_valid")

	if msg.Recipient != email || msg.TemplateType != "verification_code_valid" || msg.Code == "" ||
		msg.Channel != "email" {
		t.Fatalf("message: %+v", msg)
	}

	// The code completes the verification flow the link names.
	link, err := url.Parse(msg.Link)
	if err != nil || link.Query().Get("flow") == "" {
		t.Fatalf("link: %q %v", msg.Link, err)
	}

	status, body := call(t, http.MethodPost, "/self-service/verification?flow="+link.Query().Get("flow"),
		map[string]any{"method": "code", "code": msg.Code})
	if status != http.StatusOK || body["state"] != "passed_challenge" {
		t.Fatalf("verification: %d %v", status, body)
	}

	identity, err := e.kratos.GetIdentity(t.Context(), identityOf(t, reg))
	if err != nil || len(identity.VerifiableAddresses) != 1 || !identity.VerifiableAddresses[0].Verified {
		t.Fatalf("not verified: %+v %v", identity.VerifiableAddresses, err)
	}
}

func identityOf(t *testing.T, reg map[string]any) string {
	t.Helper()

	id, _ := reg["identity"].(map[string]any)
	s, _ := id["id"].(string)

	if s == "" {
		t.Fatalf("no identity in %v", reg)
	}

	return s
}

// AfterRegistration denies a domain; Kratos shows the message on the field.
func TestAfterRegistrationDenies(t *testing.T) {
	t.Parallel()

	start(t, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.Point("AfterRegistration"),
			func(_ context.Context, in flows.FlowIn) (flows.FlowOut, error) {
				if strings.Contains(string(in.Identity), "@evil.example") {
					return flows.FlowOut{Deny: &flows.Deny{Messages: []flows.Message{
						{Field: "traits.email", ID: 4000100, Text: "domain not allowed"},
					}}}, nil
				}

				return flows.FlowOut{
					Identity: &flows.IdentityPatch{MetadataPublic: json.RawMessage(`{"tier":"gold"}`)},
				}, nil
			})
	})

	status, body := register(t, fmt.Sprintf("x-%d@evil.example", time.Now().UnixNano()))
	if status != http.StatusBadRequest || !strings.Contains(fmt.Sprint(body), "domain not allowed") {
		t.Fatalf("deny: %d %v", status, body)
	}

	status, body = register(t, unique("gold"))
	if status != http.StatusOK {
		t.Fatalf("allow: %d %v", status, body)
	}

	id, _ := body["identity"].(map[string]any)
	if fmt.Sprint(id["metadata_public"]) != "map[tier:gold]" {
		t.Fatalf("metadata not set: %v", id["metadata_public"])
	}
}

// AfterRegistrationStored runs once Kratos stored the identity: it has the
// final id, which AfterRegistration, ahead of the store, has not.
func TestAfterRegistrationStored(t *testing.T) {
	t.Parallel()

	ids := make(chan [2]string, 2)
	idOf := func(in flows.FlowIn) string {
		var identity struct {
			ID string `json:"id"`
		}

		_ = json.Unmarshal(in.Identity, &identity)

		return identity.ID
	}

	start(t, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.Point("AfterRegistration"),
			func(_ context.Context, in flows.FlowIn) (flows.FlowOut, error) {
				ids <- [2]string{"after", idOf(in)}

				return flows.FlowOut{}, nil
			})
		backplanetest.Answer(h, f.Point(overlay.StoredHook),
			func(_ context.Context, in flows.FlowIn) (flows.FlowOut, error) {
				ids <- [2]string{"stored", idOf(in)}

				return flows.FlowOut{}, nil
			})
	})

	status, body := register(t, unique("stored"))
	if status != http.StatusOK {
		t.Fatalf("registration: %d %v", status, body)
	}

	identity, _ := body["identity"].(map[string]any)
	created, _ := identity["id"].(string)

	seen := map[string]string{}

	for range 2 {
		select {
		case id := <-ids:
			seen[id[0]] = id[1]
		case <-time.After(10 * time.Second):
			t.Fatalf("hooks seen: %v", seen)
		}
	}

	if seen["stored"] != created || created == "" {
		t.Fatalf("stored hook id %q, identity %q", seen["stored"], created)
	}

	if seen["after"] != "" {
		t.Fatalf("AfterRegistration id %q: the identity is not stored yet", seen["after"])
	}
}

// Turning registration off in the settings reaches Kratos.
func TestRegistrationToggle(t *testing.T) {
	t.Parallel()

	e := start(t, nil)

	s := defaults()
	s.Registration.Enabled = false
	backplanetest.SetLive(&e.settings, s)

	waitFor(t, "registration disabled", func() bool {
		code, body := call(t, http.MethodGet, "/self-service/registration/api", nil)

		return code == http.StatusBadRequest && strings.Contains(fmt.Sprint(body), "self_service_flow_disabled")
	})

	backplanetest.SetLive(&e.settings, defaults())

	waitFor(t, "registration enabled", func() bool {
		code, _ := call(t, http.MethodGet, "/self-service/registration/api", nil)

		return code == http.StatusOK
	})
}

// A completed registration publishes Registered.
func TestRegisteredEvent(t *testing.T) {
	t.Parallel()

	e := start(t, nil)

	email := unique("event")

	if status, body := register(t, email); status != http.StatusOK {
		t.Fatalf("registration: %d %v", status, body)
	}

	waitFor(t, "Registered published", func() bool {
		for _, ev := range backplanetest.Events(e.h, e.flows.Event(overlay.FlowRegistration)) {
			if strings.Contains(ev.GetTraits().String(), email) {
				return true
			}
		}

		return false
	})
}

// A login publishes LoggedIn once Kratos has stored its session, and the
// event carries it.
func TestLoggedInEvent(t *testing.T) {
	t.Parallel()

	e := start(t, nil)

	email := unique("login")

	if status, body := register(t, email); status != http.StatusOK {
		t.Fatalf("registration: %d %v", status, body)
	}

	code, flow := call(t, http.MethodGet, "/self-service/login/api", nil)
	if code != http.StatusOK {
		t.Fatalf("login flow: %d", code)
	}

	code, body := call(t, http.MethodPost, fmt.Sprintf("/self-service/login?flow=%v", flow["id"]),
		map[string]any{
			"method": "password", "identifier": email, "password": password,
			"transient_payload": map[string]any{"qr": "q-1"},
		})
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, body)
	}

	session, _ := body["session"].(map[string]any)

	var got *kratoseventsv1.FlowEvent

	waitFor(t, "LoggedIn published", func() bool {
		for _, ev := range backplanetest.Events(e.h, e.flows.Event(overlay.FlowLogin)) {
			if strings.Contains(ev.GetTraits().String(), email) {
				got = ev

				return true
			}
		}

		return false
	})

	s := got.GetSession()
	if s.GetId() != session["id"] || s.GetAuthenticatedAt() == nil || s.GetAal() != "aal1" || s.GetUserAgent() == "" {
		t.Fatalf("session %+v, want id %v", s, session["id"])
	}

	if qr := got.GetTransientPayload().GetFields()["qr"].GetStringValue(); qr != "q-1" {
		t.Fatalf("transient payload: %+v", got.GetTransientPayload())
	}
}

// The admin activities against the real admin API.
func TestActivities(t *testing.T) {
	t.Parallel()

	e := start(t, nil)
	ctx := t.Context()

	email := unique("admin")

	created, err := backplanetest.Activity[activities.IdentityIn, ory.Identity](
		ctx,
		e.h,
		"CreateIdentity",
		activities.IdentityIn{
			SchemaID: "default", Traits: json.RawMessage(fmt.Sprintf(`{"email":%q}`, email)), Password: password,
		},
	)
	if err != nil || created.ID == "" {
		t.Fatalf("create: %+v %v", created, err)
	}

	found, err := backplanetest.Activity[activities.FindIn, activities.FindOut](ctx, e.h, "FindIdentities",
		activities.FindIn{CredentialsIdentifier: email})
	if err != nil || len(found.Identities) != 1 || found.Identities[0].ID != created.ID {
		t.Fatalf("find: %+v %v", found, err)
	}

	patched, err := backplanetest.Activity[activities.PatchIn, ory.Identity](
		ctx,
		e.h,
		"PatchIdentity",
		activities.PatchIn{
			ID: created.ID, Patch: json.RawMessage(`[{"op":"replace","path":"/state","value":"inactive"}]`),
		},
	)
	if err != nil || patched.State != "inactive" {
		t.Fatalf("patch: %+v %v", patched, err)
	}

	recovery, err := backplanetest.Activity[activities.RecoveryIn, ory.RecoveryCode](ctx, e.h, "CreateRecoveryCode",
		activities.RecoveryIn{IdentityID: created.ID})
	if err != nil || recovery.Code == "" || recovery.Link == "" {
		t.Fatalf("recovery: %+v %v", recovery, err)
	}

	if _, err := backplanetest.Activity[activities.IDIn, activities.Empty](ctx, e.h, "DeleteIdentity",
		activities.IDIn{ID: created.ID}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	if _, err := e.kratos.GetIdentity(ctx, created.ID); !ory.IsNotFound(err) {
		t.Fatalf("still there: %v", err)
	}

	deleted := backplanetest.Events(e.h, e.activities.IdentityEvent("IdentityDeleted"))
	if len(deleted) != 1 || deleted[0].GetIdentityId() != created.ID {
		t.Fatalf("deleted event: %+v", deleted)
	}
}

// A batch import creates identities with verified addresses and their
// hashed passwords; a bad entry fails alone.
func TestImport(t *testing.T) {
	t.Parallel()

	e := start(t, nil)
	ctx := t.Context()

	email := unique("import")
	good := json.RawMessage(fmt.Sprintf(`{"schema_id":"default","traits":{"email":%q},
		"verifiable_addresses":[{"value":%q,"via":"email","verified":true,"status":"completed"}],
		"credentials":{"password":{"config":{"password":%q}}}}`, email, email, password))
	bad := json.RawMessage(`{"schema_id":"default","traits":{"email":"not an email"}}`)

	out, err := backplanetest.Activity[activities.ImportIn, activities.ImportOut](ctx, e.h, "ImportIdentities",
		activities.ImportIn{Identities: []json.RawMessage{good, bad}})
	if err != nil || len(out.Results) != 2 {
		t.Fatalf("import: %+v %v", out, err)
	}

	if out.Results[0].Action != "create" || out.Results[1].Action != "error" {
		t.Fatalf("results: %+v", out.Results)
	}

	ident, err := e.kratos.GetIdentity(ctx, out.Results[0].Identity)
	if err != nil || len(ident.VerifiableAddresses) != 1 || !ident.VerifiableAddresses[0].Verified {
		t.Fatalf("imported identity: %+v %v", ident, err)
	}

	// The imported password signs in.
	code, flow := call(t, http.MethodGet, "/self-service/login/api", nil)
	if code != http.StatusOK {
		t.Fatalf("login flow: %d", code)
	}

	code, body := call(t, http.MethodPost, fmt.Sprintf("/self-service/login?flow=%v", flow["id"]),
		map[string]any{"method": "password", "identifier": email, "password": password})
	if code != http.StatusOK {
		t.Fatalf("login: %d %v", code, body)
	}

	session, _ := body["session"].(map[string]any)

	got, err := backplanetest.Activity[activities.IDIn, ory.Session](
		ctx,
		e.h,
		"GetSession",
		activities.IDIn{ID: fmt.Sprint(session["id"])},
	)
	if err != nil || got.Identity == nil || got.Identity.ID != ident.ID {
		t.Fatalf("session: %+v %v", got, err)
	}
}

// newUser creates an identity with a password through the activity.
func (e env) newUser(t *testing.T, email string) string {
	t.Helper()

	ident, err := backplanetest.Activity[activities.IdentityIn, ory.Identity](t.Context(), e.h, "CreateIdentity", activities.IdentityIn{
		SchemaID: "default", Traits: json.RawMessage(fmt.Sprintf(`{"email":%q}`, email)), Password: password,
	})
	if err != nil {
		t.Fatal(err)
	}

	return ident.ID
}

// finishRecovery submits a recovery code to its flow, sets a new password
// with the session the recovery grants and proves it signs in.
func finishRecovery(t *testing.T, flowID, code, email string) {
	t.Helper()

	status, body := call(t, http.MethodPost, "/self-service/recovery?flow="+flowID, map[string]any{"method": "code", "code": code})
	if status != http.StatusOK {
		t.Fatalf("recovery code: %d %v", status, body)
	}

	var token, settings string

	steps, _ := body["continue_with"].([]any)
	for _, step := range steps {
		m, _ := step.(map[string]any)

		switch m["action"] {
		case "set_ory_session_token":
			token, _ = m["ory_session_token"].(string)
		case "show_settings_ui":
			f, _ := m["flow"].(map[string]any)
			settings, _ = f["id"].(string)
		}
	}

	if token == "" || settings == "" {
		t.Fatalf("recovery granted no session and settings flow: %v", body)
	}

	const newPassword = "Another-Long-Pass-456!y"

	status, body = callAs(t, token, http.MethodPost, "/self-service/settings?flow="+settings,
		map[string]any{"method": "password", "password": newPassword})
	if status != http.StatusOK {
		t.Fatalf("new password: %d %v", status, body)
	}

	_, flow := call(t, http.MethodGet, "/self-service/login/api", nil)

	status, body = call(t, http.MethodPost, fmt.Sprintf("/self-service/login?flow=%v", flow["id"]),
		map[string]any{"method": "password", "identifier": email, "password": newPassword})
	if status != http.StatusOK {
		t.Fatalf("login with the new password: %d %v", status, body)
	}
}

// A user who forgot the password: the recovery code travels through
// kratos.Deliver, redeeming it lets the user set a new password.
func TestRecoveryByEmail(t *testing.T) {
	t.Parallel()

	codes := make(chan flows.DeliverIn, 64)

	e := start(t, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.DeliverRef(), func(_ context.Context, in flows.DeliverIn) (flows.DeliverOut, error) {
			codes <- in

			return flows.DeliverOut{}, nil
		})
	})

	email := unique("forgot")
	e.newUser(t, email)

	status, flow := call(t, http.MethodGet, "/self-service/recovery/api", nil)
	if status != http.StatusOK {
		t.Fatalf("recovery flow: %d %v", status, flow)
	}

	flowID := fmt.Sprint(flow["id"])

	status, body := call(t, http.MethodPost, "/self-service/recovery?flow="+flowID, map[string]any{"method": "code", "email": email})
	if status != http.StatusOK {
		t.Fatalf("recovery email: %d %v", status, body)
	}

	msg := awaitMessage(t, codes, email, "recovery_code_valid")

	if msg.TemplateType != "recovery_code_valid" || msg.Recipient != email || msg.Code == "" {
		t.Fatalf("message: %+v", msg)
	}

	finishRecovery(t, flowID, msg.Code, email)
}

// An operator's recovery code (the console's, the activity's) lets the
// user in to set a new password; nothing is mailed.
func TestRecoveryByOperator(t *testing.T) {
	t.Parallel()

	e := start(t, nil)

	email := unique("operator")
	id := e.newUser(t, email)

	recovery, err := e.kratos.CreateRecoveryCode(t.Context(), id, "", "api")
	if err != nil || recovery.Code == "" || recovery.Link == "" {
		t.Fatalf("recovery code: %+v %v", recovery, err)
	}

	link, err := url.Parse(recovery.Link)
	if err != nil || link.Query().Get("flow") == "" {
		t.Fatalf("link: %q %v", recovery.Link, err)
	}

	finishRecovery(t, link.Query().Get("flow"), recovery.Code, email)
}

// phoneSchema identifies people by a phone: codes to sign in, verify and
// recover go by SMS.
const phoneSchema = `{
  "$id": "https://backplane-kratos.test/phone.schema.json",
  "$schema": "http://json-schema.org/draft-07/schema#",
  "type": "object",
  "properties": {"traits": {"type": "object", "properties": {"phone": {
    "type": "string", "format": "tel",
    "ory.sh/kratos": {
      "credentials": {"code": {"identifier": true, "via": "sms"}},
      "verification": {"via": "sms"},
      "recovery": {"via": "sms"}
    }
  }}, "required": ["phone"], "additionalProperties": false}}
}`

// A phone identity signs in with a code Kratos sends by SMS: it reaches
// kratos.Deliver on the sms channel and signs the user in.
func TestSMSCode(t *testing.T) {
	t.Parallel()

	codes := make(chan flows.DeliverIn, 64)

	e := startWith(t, func(s *overlay.Settings) {
		emailSchema, err := os.ReadFile("testdata/identity.schema.json")
		if err != nil {
			t.Fatal(err)
		}

		s.Identity = overlay.Identity{DefaultSchemaID: "default", Schemas: map[string]string{"default": string(emailSchema), "phone": phoneSchema}}
		s.Methods.Code.Passwordless = true
	}, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.DeliverRef(), func(_ context.Context, in flows.DeliverIn) (flows.DeliverOut, error) {
			codes <- in

			return flows.DeliverOut{}, nil
		})
	})

	phone := fmt.Sprintf("+49151%08d", time.Now().UnixNano()%100_000_000)

	ident, err := backplanetest.Activity[activities.IdentityIn, ory.Identity](t.Context(), e.h, "CreateIdentity", activities.IdentityIn{
		SchemaID: "phone", Traits: json.RawMessage(fmt.Sprintf(`{"phone":%q}`, phone)),
	})
	if err != nil {
		t.Fatalf("phone identity: %v", err)
	}

	status, flow := call(t, http.MethodGet, "/self-service/login/api", nil)
	if status != http.StatusOK {
		t.Fatalf("login flow: %d %v", status, flow)
	}

	flowPath := fmt.Sprintf("/self-service/login?flow=%v", flow["id"])

	status, body := call(t, http.MethodPost, flowPath, map[string]any{"method": "code", "identifier": phone})
	if status != http.StatusBadRequest && status != http.StatusOK { // Kratos answers the form asking for the code
		t.Fatalf("ask for a code: %d %v", status, body)
	}

	msg := awaitMessage(t, codes, phone, "login_code_valid")
	if msg.Channel != "sms" || msg.Code == "" {
		t.Fatalf("sms: %+v", msg)
	}

	status, body = call(t, http.MethodPost, flowPath, map[string]any{"method": "code", "identifier": phone, "code": msg.Code})
	if status != http.StatusOK {
		t.Fatalf("sign in with the code: %d %v", status, body)
	}

	session, _ := body["session"].(map[string]any)
	who, _ := session["identity"].(map[string]any)

	if who["id"] != ident.ID {
		t.Fatalf("signed in as %v, want %s", who["id"], ident.ID)
	}
}

// A phone identity recovers by SMS (Kratos's recovery with a chosen
// address): the code reaches kratos.Deliver on the sms channel and grants
// a session.
func TestSMSRecovery(t *testing.T) {
	t.Parallel()

	codes := make(chan flows.DeliverIn, 64)

	e := startWith(t, func(s *overlay.Settings) {
		emailSchema, err := os.ReadFile("testdata/identity.schema.json")
		if err != nil {
			t.Fatal(err)
		}

		s.Identity = overlay.Identity{DefaultSchemaID: "default", Schemas: map[string]string{"default": string(emailSchema), "phone": phoneSchema}}
		s.Features.ChooseRecoveryAddress = true
	}, func(h *backplanetest.Harness, f *flows.Flows) {
		backplanetest.Answer(h, f.DeliverRef(), func(_ context.Context, in flows.DeliverIn) (flows.DeliverOut, error) {
			codes <- in

			return flows.DeliverOut{}, nil
		})
	})

	phone := fmt.Sprintf("+49151%08d", time.Now().UnixNano()%100_000_000)

	ident, err := backplanetest.Activity[activities.IdentityIn, ory.Identity](t.Context(), e.h, "CreateIdentity", activities.IdentityIn{
		SchemaID: "phone", Traits: json.RawMessage(fmt.Sprintf(`{"phone":%q}`, phone)),
	})
	if err != nil {
		t.Fatalf("phone identity: %v", err)
	}

	status, flow := call(t, http.MethodGet, "/self-service/recovery/api", nil)
	if status != http.StatusOK {
		t.Fatalf("recovery flow: %d %v", status, flow)
	}

	flowPath := fmt.Sprintf("/self-service/recovery?flow=%v", flow["id"])

	status, body := call(t, http.MethodPost, flowPath, map[string]any{"method": "code", "recovery_address": phone})
	if status != http.StatusOK {
		t.Fatalf("recovery address: %d %v", status, body)
	}

	msg := awaitMessage(t, codes, phone, "recovery_code_valid")
	if msg.Channel != "sms" || msg.Code == "" {
		t.Fatalf("sms: %+v", msg)
	}

	status, body = call(t, http.MethodPost, flowPath, map[string]any{"method": "code", "code": msg.Code})
	if status != http.StatusOK {
		t.Fatalf("recovery code: %d %v", status, body)
	}

	token := ""

	steps, _ := body["continue_with"].([]any)
	for _, step := range steps {
		if m, _ := step.(map[string]any); m["action"] == "set_ory_session_token" {
			token, _ = m["ory_session_token"].(string)
		}
	}

	who, err := e.kratos.WhoAmI(t.Context(), token, "")
	if err != nil || who.Identity == nil || who.Identity.ID != ident.ID {
		t.Fatalf("recovered session: %+v %v (%v)", who, err, body)
	}
}

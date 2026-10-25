package overlay

import (
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Flows Kratos runs hooks around.
const (
	FlowRegistration = "registration"
	FlowLogin        = "login"
	FlowSettings     = "settings"
	FlowRecovery     = "recovery"
	FlowVerification = "verification"
)

// Flows in a stable order.
func Flows() []string {
	return []string{FlowRegistration, FlowLogin, FlowSettings, FlowRecovery, FlowVerification}
}

// methods are the per-method after-hook lists of a flow; nil: the flow
// has one generic list (after.hooks).
func methods(flow string) []string {
	switch flow {
	case FlowRegistration:
		return []string{"password", "webauthn", "passkey", "oidc", "code"}
	case FlowLogin:
		return []string{"password", "webauthn", "passkey", "oidc", "code", "totp", "lookup_secret"}
	case FlowSettings:
		return []string{"password", "totp", "oidc", "webauthn", "passkey", "lookup_secret", "profile"}
	default:
		return nil
	}
}

// GenericMethod names the after-hook list of a flow without per-method
// lists in callback paths.
const GenericMethod = "any"

// MethodsOf are the after-hook lists of a flow: its methods, or
// GenericMethod alone.
func MethodsOf(flow string) []string {
	if m := methods(flow); m != nil {
		return m
	}

	return []string{GenericMethod}
}

// HookName is the backplane hook of a flow's before or after point, e.g.
// "AfterRegistration".
func HookName(when, flow string) string {
	return strings.ToUpper(when[:1]) + when[1:] + strings.ToUpper(flow[:1]) + flow[1:]
}

// Stored is the point of a registration after Kratos stored the identity.
const Stored = "stored"

// StoredHook is the backplane hook of Stored: the identity's id is final.
const StoredHook = "AfterRegistrationStored"

// PointName is the backplane hook of a flow point: HookName, or StoredHook.
func PointName(when, flow string) string {
	if when == Stored {
		return StoredHook
	}

	return HookName(when, flow)
}

// DeliverHook is the hook the courier calls.
const DeliverHook = "Deliver"

// Wiring is how Kratos reaches backplane-kratos and what is bound.
type Wiring struct {
	// URL is the callbacks listener as Kratos reaches it.
	URL string
	// Key authenticates Kratos's calls (header KeyHeader).
	Key string
	// Bound reports whether a hook (short name) is bound.
	Bound func(hook string) bool
	// Events: publish flow events (an event transport is configured).
	Events bool
}

// KeyHeader carries Wiring.Key on every callback.
const KeyHeader = "X-Backplane-Kratos-Key"

// body is the Jsonnet every callback sends: Kratos's whole context but its
// cookies, which must never reach wiring.
const body = `function(ctx) { [k]: ctx[k] for k in std.objectFields(ctx) if k != "request_cookies" }`

// Errors of Render.
var (
	ErrOverrides = errors.New("overrides")
	ErrConflict  = errors.New("is set by the settings or the callbacks; change it there")
)

// Render is the overlay document for s, its secrets and w.
func Render(s Settings, sec Secrets, w Wiring) (map[string]any, error) {
	r := renderer{s: s, sec: sec, w: w, doc: map[string]any{}}
	r.selfservice()
	r.courier()
	r.session()

	if err := r.identity(); err != nil {
		return nil, err
	}

	r.oauth2()

	if err := r.tokens(); err != nil {
		return nil, err
	}

	r.set("feature_flags.use_continue_with_transitions", s.Features.ContinueWith)
	r.set("feature_flags.choose_recovery_address", s.Features.ChooseRecoveryAddress)

	if err := r.overrides(); err != nil {
		return nil, err
	}

	return r.doc, nil
}

type renderer struct {
	s   Settings
	sec Secrets
	w   Wiring
	doc map[string]any
}

// set assigns a dotted path.
func (r renderer) set(path string, v any) { setPath(r.doc, strings.Split(path, "."), v) }

func setPath(m map[string]any, keys []string, v any) {
	for _, k := range keys[:len(keys)-1] {
		next, ok := m[k].(map[string]any)
		if !ok {
			next = map[string]any{}
			m[k] = next
		}

		m = next
	}

	m[keys[len(keys)-1]] = v
}

func (r renderer) setURL(path, v string) {
	if v != "" {
		r.set(path, v)
	}
}

func (r renderer) selfservice() {
	s := r.s
	r.setURL("selfservice.default_browser_return_url", s.DefaultReturnURL)

	if len(s.AllowedReturnURLs) > 0 {
		r.set("selfservice.allowed_return_urls", s.AllowedReturnURLs)
	}

	r.setURL("selfservice.flows.error.ui_url", s.ErrorUIURL)

	const f = "selfservice.flows."

	r.set(f+"registration.enabled", s.Registration.Enabled)
	r.set(f+"registration.lifespan", s.Registration.Lifespan.String())
	r.set(f+"registration.style", s.Registration.Style)
	r.setURL(f+"registration.ui_url", s.Registration.UIURL)

	r.set(f+"login.lifespan", s.Login.Lifespan.String())
	r.set(f+"login.style", s.Login.Style)
	r.setURL(f+"login.ui_url", s.Login.UIURL)

	r.set(f+"settings.lifespan", s.Settings.Lifespan.String())
	r.set(f+"settings.privileged_session_max_age", s.Settings.PrivilegedSessionMaxAge.String())
	r.set(f+"settings.required_aal", s.Settings.RequiredAAL)
	r.setURL(f+"settings.ui_url", s.Settings.UIURL)

	r.set(f+"recovery.enabled", s.Recovery.Enabled)
	r.set(f+"recovery.lifespan", s.Recovery.Lifespan.String())
	r.set(f+"recovery.use", s.Recovery.Use)
	r.set(f+"recovery.notify_unknown_recipients", s.Recovery.NotifyUnknownRecipients)
	r.setURL(f+"recovery.ui_url", s.Recovery.UIURL)

	r.set(f+"verification.enabled", s.Verification.Enabled)
	r.set(f+"verification.lifespan", s.Verification.Lifespan.String())
	r.set(f+"verification.use", s.Verification.Use)
	r.set(f+"verification.notify_unknown_recipients", s.Verification.NotifyUnknownRecipients)
	r.setURL(f+"verification.ui_url", s.Verification.UIURL)

	for _, flow := range Flows() {
		r.set(f+flow+".before.hooks", r.before(flow))

		for _, m := range MethodsOf(flow) {
			path := f + flow + ".after." + m + ".hooks"
			if m == GenericMethod {
				path = f + flow + ".after.hooks"
			}

			r.set(path, r.after(flow, m))
		}
	}

	r.methods()
}

// How Kratos treats a web hook's answer.
type answer int

const (
	// parsed: Kratos waits and applies the answer; on registration and
	// settings it runs before the identity is stored.
	parsed answer = iota
	// awaited: Kratos waits for a success after storing the identity.
	awaited
	// ignored: Kratos fires and forgets, after storing the identity.
	ignored
)

// webHook is a callback entry.
func (r renderer) webHook(path string, a answer) map[string]any {
	response := map[string]any{"parse": true}

	switch a {
	case parsed:
	case awaited:
		response = map[string]any{"parse": false}
	case ignored:
		response = map[string]any{"ignore": true}
	}

	return map[string]any{"hook": "web_hook", "config": map[string]any{
		"url": strings.TrimRight(r.w.URL, "/") + path, "method": "POST",
		"body":     "base64://" + base64.StdEncoding.EncodeToString([]byte(body)),
		"response": response,
		"auth": map[string]any{
			"type":   "api_key",
			"config": map[string]any{"name": KeyHeader, "value": r.w.Key, "in": "header"},
		},
	}}
}

func (r renderer) bound(hook string) bool { return r.w.Bound != nil && r.w.Bound(hook) }

func (r renderer) before(flow string) []any {
	hooks := []any{}
	if r.bound(HookName("before", flow)) {
		hooks = append(hooks, r.webHook("/hooks/before/"+flow+"/"+GenericMethod, parsed))
	}

	return hooks
}

func (r renderer) after(flow, method string) []any {
	hooks := []any{}
	if r.bound(HookName("after", flow)) {
		hooks = append(hooks, r.webHook("/hooks/after/"+flow+"/"+method, parsed))
	}

	// Ahead of the session hook, which ends the flow.
	if flow == FlowRegistration && r.bound(StoredHook) {
		hooks = append(hooks, r.webHook("/hooks/"+Stored+"/"+flow+"/"+method, awaited))
	}

	if r.w.Events {
		hooks = append(hooks, r.webHook("/events/"+flow+"/"+method, ignored))
	}

	s := r.s

	switch flow {
	case FlowRegistration:
		if s.Registration.LoginAfter {
			hooks = append(hooks, map[string]any{"hook": "session"})
		}

		if s.Registration.ShowVerificationUI {
			hooks = append(hooks, map[string]any{"hook": "show_verification_ui"})
		}
	case FlowLogin:
		if s.Login.RequireVerifiedAddress && method == "password" {
			hooks = append(hooks, map[string]any{"hook": "require_verified_address"})
		}

		if s.Login.RevokeOtherSessions {
			hooks = append(hooks, map[string]any{"hook": "revoke_active_sessions"})
		}
	case FlowRecovery:
		if s.Recovery.RevokeSessions {
			hooks = append(hooks, map[string]any{"hook": "revoke_active_sessions"})
		}
	}

	return hooks
}

func (r renderer) methods() {
	m := r.s.Methods

	const p = "selfservice.methods."

	r.set(p+"password.enabled", m.Password.Enabled)
	r.set(p+"password.config.min_password_length", m.Password.MinLength)
	r.set(p+"password.config.identifier_similarity_check_enabled", m.Password.IdentifierSimilarityCheck)
	r.set(p+"password.config.haveibeenpwned_enabled", m.Password.HaveIBeenPwned)

	r.set(p+"code.enabled", m.Code.Enabled)
	r.set(p+"code.passwordless_enabled", m.Code.Passwordless)
	r.set(p+"code.mfa_enabled", m.Code.MFA)
	r.set(p+"code.config.lifespan", m.Code.Lifespan.String())

	r.set(p+"totp.enabled", m.TOTP.Enabled)
	r.setURL(p+"totp.config.issuer", m.TOTP.Issuer)

	r.set(p+"lookup_secret.enabled", m.LookupSecret.Enabled)
	r.set(p+"profile.enabled", m.Profile.Enabled)
	r.set(p+"link.enabled", m.Link.Enabled)

	r.set(p+"webauthn.enabled", m.WebAuthn.Enabled)

	if m.WebAuthn.Enabled {
		r.set(p+"webauthn.config.passwordless", m.WebAuthn.Passwordless)
		r.set(p+"webauthn.config.rp", rp(m.WebAuthn.RP))
	}

	r.set(p+"passkey.enabled", m.Passkey.Enabled)

	if m.Passkey.Enabled {
		r.set(p+"passkey.config.rp", rp(m.Passkey.RP))
	}

	r.set(p+"oidc.enabled", m.OIDC.Enabled)

	if len(m.OIDC.Providers) > 0 {
		providers := make([]any, 0, len(m.OIDC.Providers))
		for i := range m.OIDC.Providers {
			providers = append(providers, provider(m.OIDC.Providers[i], r.sec.OIDC[m.OIDC.Providers[i].ID]))
		}

		r.set(p+"oidc.config.providers", providers)
	}
}

func rp(r RelyingParty) map[string]any {
	out := map[string]any{"id": r.ID, "display_name": r.DisplayName}
	if len(r.Origins) > 0 {
		out["origins"] = r.Origins
	}

	return out
}

func provider(p OIDCProvider, secret string) map[string]any {
	out := map[string]any{
		"id": p.ID, "provider": p.Provider, "client_id": p.ClientID, "client_secret": secret,
		"mapper_url": "base64://" + base64.StdEncoding.EncodeToString([]byte(p.Mapper)),
	}

	if p.Label != "" {
		out["label"] = p.Label
	}

	if p.IssuerURL != "" {
		out["issuer_url"] = p.IssuerURL
	}

	if len(p.Scope) > 0 {
		out["scope"] = p.Scope
	}

	for _, k := range slices.Sorted(maps.Keys(p.Extra)) {
		out[k] = p.Extra[k]
	}

	return out
}

func (r renderer) courier() {
	if !r.bound(DeliverHook) {
		return
	}

	request := func(path string) map[string]any {
		return map[string]any{
			"url": strings.TrimRight(r.w.URL, "/") + path, "method": "POST",
			"body":    "base64://" + base64.StdEncoding.EncodeToString([]byte(body)),
			"headers": map[string]any{"Content-Type": "application/json"},
			"auth": map[string]any{
				"type":   "api_key",
				"config": map[string]any{"name": KeyHeader, "value": r.w.Key, "in": "header"},
			},
		}
	}

	r.set("courier.delivery_strategy", "http")
	r.set("courier.http.request_config", request("/courier/email"))
	r.set(
		"courier.channels",
		[]any{map[string]any{"id": "sms", "type": "http", "request_config": request("/courier/sms")}},
	)
}

func (r renderer) session() {
	s := r.s.Session
	r.set("session.lifespan", s.Lifespan.String())

	if s.EarliestPossibleExtend > 0 {
		r.set("session.earliest_possible_extend", s.EarliestPossibleExtend.String())
	}

	r.set("session.whoami.required_aal", s.WhoamiRequiredAAL)
	r.set("session.cookie.persistent", s.CookiePersistent)
	r.set("session.cookie.same_site", s.CookieSameSite)
	r.setURL("session.cookie.domain", s.CookieDomain)
}

// ErrSchema: an identity schema is not JSON or the default names none.
var ErrSchema = errors.New("identity schema")

func (r renderer) identity() error {
	id := r.s.Identity
	if len(id.Schemas) == 0 {
		r.setURL("identity.default_schema_id", id.DefaultSchemaID)

		return nil
	}

	schemas := make([]any, 0, len(id.Schemas))

	for _, name := range slices.Sorted(maps.Keys(id.Schemas)) {
		doc := strings.TrimSpace(id.Schemas[name])

		var probe any
		if err := yaml.Unmarshal([]byte(doc), &probe); err != nil {
			return fmt.Errorf("%w %q: %w", ErrSchema, name, err)
		}

		schemas = append(schemas, map[string]any{
			"id": name, "url": "base64://" + base64.StdEncoding.EncodeToString([]byte(doc)),
		})
	}

	def := id.DefaultSchemaID
	if def == "" && len(id.Schemas) == 1 {
		def = slices.Collect(maps.Keys(id.Schemas))[0]
	}

	if _, ok := id.Schemas[def]; !ok {
		return fmt.Errorf("%w: default_schema_id %q is not one of the schemas", ErrSchema, def)
	}

	r.set("identity.schemas", schemas)
	r.set("identity.default_schema_id", def)

	return nil
}

func (r renderer) oauth2() {
	o := r.s.OAuth2Provider
	if o.URL == "" {
		return
	}

	r.set("oauth2_provider.url", o.URL)
	r.set("oauth2_provider.override_return_to", o.OverrideReturnTo)

	if len(r.sec.OAuth2ProviderHeaders) > 0 {
		h := map[string]any{}
		for k, v := range r.sec.OAuth2ProviderHeaders {
			h[k] = v
		}

		r.set("oauth2_provider.headers", h)
	}
}

// overrides merges the raw YAML; a leaf the rest set is a conflict.
func (r renderer) overrides() error {
	raw := strings.TrimSpace(r.s.Overrides)
	if raw == "" {
		return nil
	}

	var extra map[string]any
	if err := yaml.Unmarshal([]byte(raw), &extra); err != nil {
		return fmt.Errorf("%w: %w", ErrOverrides, err)
	}

	return merge(r.doc, extra, "")
}

func merge(dst, src map[string]any, prefix string) error {
	for _, k := range slices.Sorted(maps.Keys(src)) {
		path := k
		if prefix != "" {
			path = prefix + "." + k
		}

		sv := src[k]

		dv, exists := dst[k]
		if !exists {
			dst[k] = sv

			continue
		}

		dstMap, dIsMap := dv.(map[string]any)
		srcMap, sIsMap := sv.(map[string]any)

		if !dIsMap || !sIsMap {
			return fmt.Errorf("%w: %s %w", ErrOverrides, path, ErrConflict)
		}

		if err := merge(dstMap, srcMap, path); err != nil {
			return err
		}
	}

	return nil
}

// Package flows turns Kratos's callbacks into Backplane hooks and events:
// the courier's messages (hook Deliver), the before/after points of the
// self-service flows (hooks Before<Flow>/After<Flow>) and the facts of
// completed flows (events).
package flows

import (
	"encoding/json"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// DeliverIn is a message Kratos's courier hands over: deliver it.
type DeliverIn struct {
	// Channel is "email" or "sms".
	Channel   string `json:"channel"   validate:"oneof=email sms"`
	Recipient string `json:"recipient" schemapb:"description=Address or phone number"`
	// TemplateType is Kratos's message kind, e.g. verification_code_valid,
	// recovery_code_valid, login_code_valid, registration_code_valid.
	TemplateType string `json:"template_type"`
	// Code is the one-time code the message carries, if any.
	Code string `json:"code,omitempty" schemapb:"secret=true"`
	// Link is the link the message carries (verification, recovery), if any.
	Link             string `json:"link,omitempty"               schemapb:"secret=true"`
	ExpiresInMinutes int64  `json:"expires_in_minutes,omitempty"`
	// Identity the message is about, as Kratos sends it.
	Identity json.RawMessage `json:"identity,omitempty"`
	// Data is the rest of Kratos's template data.
	Data json.RawMessage `json:"data,omitempty"`
	// Rendered is Kratos's own rendering of the message.
	Rendered Rendered `json:"rendered"`
	// TransientPayload the flow carried.
	TransientPayload json.RawMessage `json:"transient_payload,omitempty"`
}

// Rendered is a message as Kratos's templates render it; it holds the code.
type Rendered struct {
	Subject string `json:"subject,omitempty" schemapb:"secret=true"`
	Body    string `json:"body,omitempty"    schemapb:"secret=true"`
	HTML    string `json:"html,omitempty"    schemapb:"secret=true"`
}

// DeliverOut is empty: a returned error makes Kratos retry the message.
type DeliverOut struct{}

// FlowIn is a self-service flow at a before or after point.
type FlowIn struct {
	// Flow is registration, login, settings, recovery or verification.
	Flow string `json:"flow"`
	// Method is the method the flow completed with (after points); "any"
	// where Kratos does not tell.
	Method string `json:"method,omitempty"`
	// FlowID and FlowType ("api" or "browser").
	FlowID   string `json:"flow_id,omitempty"`
	FlowType string `json:"flow_type,omitempty"`
	// ClientFlowID is the flow the client submitted or started, as this
	// service's proxy vouches for it. It differs from FlowID only when Kratos
	// converted the flow: an OIDC login of an unknown subject completes as a
	// new registration flow, an OIDC registration of a known one as a new
	// login flow. Empty when the request did not pass the proxy.
	ClientFlowID string `json:"client_flow_id,omitempty"`
	// Identity of the flow (after points). At AfterRegistration it is not
	// stored yet and has no id; AfterRegistrationStored has the final one.
	Identity json.RawMessage `json:"identity,omitempty"`
	// Session acting in the flow, as Kratos sends it: at BeforeSettings and
	// AfterSettings the signed-in one; after login and registration the new
	// one, which Kratos stores only after the hooks, so its id (and its
	// devices' ids) are empty there. Absent where Kratos sends none. No
	// token or cookie.
	Session          ory.Session     `json:"session,omitzero"`
	TransientPayload json.RawMessage `json:"transient_payload,omitempty"`
	RequestURL       string          `json:"request_url,omitempty"`
	RequestMethod    string          `json:"request_method,omitempty"`
	// RequestHeaders Kratos forwards (its allowlist); never cookies.
	RequestHeaders map[string]string `json:"request_headers,omitempty"`
}

// FlowOut is the hook's verdict: nothing lets the flow continue.
type FlowOut struct {
	// Deny stops the flow and shows these messages.
	Deny *Deny `json:"deny,omitempty"`
	// Identity replaces parts of the identity (registration and settings).
	Identity *IdentityPatch `json:"identity,omitempty"`
}

// Deny stops a flow.
type Deny struct {
	Messages []Message `json:"messages"`
}

// Message shown to the user.
type Message struct {
	// Field is the form field, e.g. "traits.email"; empty: the whole form.
	Field string `json:"field,omitempty"`
	// ID lets a UI translate the message.
	ID   int64  `json:"id,omitempty"`
	Text string `json:"text"`
	// Type is error (default), info or success.
	Type    string          `json:"type,omitempty"    validate:"omitempty,oneof=error info success"`
	Context json.RawMessage `json:"context,omitempty"`
}

// IdentityPatch replaces whole parts of an identity; absent parts stay.
type IdentityPatch struct {
	Traits         json.RawMessage `json:"traits,omitempty"`
	MetadataPublic json.RawMessage `json:"metadata_public,omitempty"`
	MetadataAdmin  json.RawMessage `json:"metadata_admin,omitempty"`
}

// Channels a new session's credential leaves by.
const (
	// ChannelBrowser: a session cookie.
	ChannelBrowser = "browser"
	// ChannelAPI: a session token in the flow's answer.
	ChannelAPI = "api"
	// ChannelNativeExchange: a session token from /sessions/token-exchange.
	ChannelNativeExchange = "native_exchange"
)

// SessionIssuedIn is a session Kratos has stored whose credential has not
// left yet.
type SessionIssuedIn struct {
	// Flow is login, registration or recovery: the flow the client
	// submitted; empty for an OIDC callback whose start is unknown.
	Flow string `json:"flow,omitempty"`
	// Method is the session's latest authentication method (password, code,
	// oidc, webauthn, passkey, totp, lookup_secret, code_recovery, ...).
	Method string `json:"method"`
	// FlowID is the client's flow, the ClientFlowID of the after hooks: the
	// submit's ?flow=, for an OIDC sign-in the flow that started it, for the
	// native exchange the app's X-Kratos-Flow-Id header (unverified). Empty
	// when unknown.
	FlowID string `json:"flow_id,omitempty"`
	// Channel is browser, api or native_exchange.
	Channel string `json:"channel"`
	// Identity of the session, stored.
	Identity ory.Identity `json:"identity"`
	// Session as Kratos stored it, without its identity, token or cookie.
	Session ory.Session `json:"session"`
	// TransientPayload of the submit that issued the session; empty for an
	// OIDC callback and the native exchange (the after hooks had it).
	TransientPayload json.RawMessage `json:"transient_payload,omitempty"`
}

// SessionIssuedOut: nothing lets the credential go; Deny revokes the
// session and refuses the client.
type SessionIssuedOut struct {
	Deny *SessionDeny `json:"deny,omitempty"`
}

// SessionDeny refuses a new session.
type SessionDeny struct {
	// Code is the machine reason the client gets (error.reason).
	Code     string    `json:"code"               validate:"required"`
	Messages []Message `json:"messages,omitempty"`
}

// FlowEvent is a completed flow: Registered, LoggedIn, SettingsChanged,
// Recovered, Verified.
type FlowEvent = *kratoseventsv1.FlowEvent

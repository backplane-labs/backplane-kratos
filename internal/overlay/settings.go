// Package overlay renders the Kratos configuration file backplane-kratos
// owns: the settings an operator edits in the console and the callbacks
// of bound hooks. Kratos loads it after the deployment's base file
// (`kratos serve -c base.yml -c overlay.yml`) and reloads it when it
// changes; a key set here wins over the base, a list replaces the base's.
package overlay

import (
	"time"
)

// Settings are the Kratos settings the overlay owns. Flags and durations
// are always written (their defaults are Kratos's); an empty string or
// list is left to the base file.
type Settings struct {
	DefaultReturnURL  string   `json:"default_return_url,omitempty"  schemapb:"description=Where a browser goes after a flow without return_to"`
	AllowedReturnURLs []string `json:"allowed_return_urls,omitempty" schemapb:"description=return_to values a flow accepts"`
	ErrorUIURL        string   `json:"error_ui_url,omitempty"        schemapb:"description=The UI page that shows a flow error"`

	Registration Registration `json:"registration,omitempty"`
	Login        Login        `json:"login,omitempty"`
	Settings     SettingsFlow `json:"settings,omitempty"`
	Recovery     Recovery     `json:"recovery,omitempty"`
	Verification Verification `json:"verification,omitempty"`
	Methods      Methods      `json:"methods,omitempty"`
	Session      Session      `json:"session,omitempty"`
	Identity     Identity     `json:"identity,omitempty"`

	Features Features `json:"features,omitempty"`

	// Tokens are the session tokens services verify (active with token_key).
	Tokens Tokens `json:"tokens,omitempty"`

	OAuth2Provider OAuth2Provider `json:"oauth2_provider,omitempty"`

	// Overrides is raw Kratos YAML merged last, for what Settings does not
	// model; it may not set a key Settings or the callbacks set.
	Overrides string `json:"overrides,omitempty" schemapb:"description=Raw Kratos YAML for keys these settings do not model"`
}

// Registration flow.
type Registration struct {
	Enabled  bool          `json:"enabled,omitempty"  schemapb:"default=true;description=Accept new registrations"`
	UIURL    string        `json:"ui_url,omitempty"`
	Lifespan time.Duration `json:"lifespan,omitempty" schemapb:"default=1h"`
	// LoginAfter signs the new identity in (Kratos's session hook).
	LoginAfter bool `json:"login_after,omitempty" schemapb:"default=true;description=Sign the new identity in"`
	// ShowVerificationUI sends a browser to the verification UI afterwards.
	ShowVerificationUI bool   `json:"show_verification_ui,omitempty" schemapb:"default=false"`
	Style              string `json:"style,omitempty"                schemapb:"default={\"stringValue\":\"profile_first\"}" validate:"oneof=profile_first unified"`
}

// Login flow.
type Login struct {
	UIURL    string        `json:"ui_url,omitempty"`
	Lifespan time.Duration `json:"lifespan,omitempty" schemapb:"default=1h"`
	Style    string        `json:"style,omitempty"    schemapb:"default={\"stringValue\":\"unified\"}" validate:"oneof=unified identifier_first"`
	// RequireVerifiedAddress refuses a login before an address is verified.
	RequireVerifiedAddress bool `json:"require_verified_address,omitempty" schemapb:"default=false"`
	// RevokeOtherSessions ends the identity's other sessions at login.
	RevokeOtherSessions bool `json:"revoke_other_sessions,omitempty" schemapb:"default=false"`
}

// SettingsFlow is the account settings flow.
type SettingsFlow struct {
	UIURL                   string        `json:"ui_url,omitempty"`
	Lifespan                time.Duration `json:"lifespan,omitempty"                   schemapb:"default=1h"`
	PrivilegedSessionMaxAge time.Duration `json:"privileged_session_max_age,omitempty" schemapb:"default=1h"`
	RequiredAAL             string        `json:"required_aal,omitempty"               schemapb:"default={\"stringValue\":\"highest_available\"}" validate:"oneof=highest_available aal1"`
}

// Recovery flow.
type Recovery struct {
	Enabled                 bool          `json:"enabled,omitempty"                   schemapb:"default=false"`
	UIURL                   string        `json:"ui_url,omitempty"`
	Lifespan                time.Duration `json:"lifespan,omitempty"                  schemapb:"default=1h"`
	Use                     string        `json:"use,omitempty"                       schemapb:"default={\"stringValue\":\"code\"}" validate:"oneof=code link"`
	NotifyUnknownRecipients bool          `json:"notify_unknown_recipients,omitempty" schemapb:"default=false"`
	// RevokeSessions ends the identity's sessions after a recovery.
	RevokeSessions bool `json:"revoke_sessions,omitempty" schemapb:"default=false"`
}

// Verification flow.
type Verification struct {
	Enabled                 bool          `json:"enabled,omitempty"                   schemapb:"default=false"`
	UIURL                   string        `json:"ui_url,omitempty"`
	Lifespan                time.Duration `json:"lifespan,omitempty"                  schemapb:"default=1h"`
	Use                     string        `json:"use,omitempty"                       schemapb:"default={\"stringValue\":\"code\"}" validate:"oneof=code link"`
	NotifyUnknownRecipients bool          `json:"notify_unknown_recipients,omitempty" schemapb:"default=false"`
}

// Methods are the sign-in and second-factor methods.
type Methods struct {
	Password     Password `json:"password,omitempty"`
	Code         Code     `json:"code,omitempty"`
	TOTP         TOTP     `json:"totp,omitempty"`
	LookupSecret Toggle   `json:"lookup_secret,omitempty"`
	WebAuthn     WebAuthn `json:"webauthn,omitempty"`
	Passkey      Passkey  `json:"passkey,omitempty"`
	OIDC         OIDC     `json:"oidc,omitempty"`
	Profile      ToggleOn `json:"profile,omitempty"`
	Link         Toggle   `json:"link,omitempty"`
}

// Toggle is a method that is off by default.
type Toggle struct {
	Enabled bool `json:"enabled,omitempty" schemapb:"default=false"`
}

// ToggleOn is a method that is on by default.
type ToggleOn struct {
	Enabled bool `json:"enabled,omitempty" schemapb:"default=true"`
}

// Password method.
type Password struct {
	Enabled                   bool  `json:"enabled,omitempty"                     schemapb:"default=true"`
	MinLength                 int64 `json:"min_length,omitempty"                  schemapb:"default=8;gte=6;lte=1024"`
	IdentifierSimilarityCheck bool  `json:"identifier_similarity_check,omitempty" schemapb:"default=true"`
	HaveIBeenPwned            bool  `json:"haveibeenpwned,omitempty"              schemapb:"default=true;description=Refuse passwords found in breaches"`
}

// Code method: one-time codes by email or SMS.
type Code struct {
	Enabled bool `json:"enabled,omitempty" schemapb:"default=true"`
	// Passwordless signs in with a code alone.
	Passwordless bool `json:"passwordless,omitempty" schemapb:"default=false"`
	// MFA offers a code as a second factor.
	MFA      bool          `json:"mfa,omitempty"      schemapb:"default=false"`
	Lifespan time.Duration `json:"lifespan,omitempty" schemapb:"default=1h"`
}

// TOTP method.
type TOTP struct {
	Enabled bool   `json:"enabled,omitempty" schemapb:"default=false"`
	Issuer  string `json:"issuer,omitempty"  schemapb:"description=The name authenticator apps show"`
}

// RelyingParty of WebAuthn and passkeys.
type RelyingParty struct {
	ID          string   `json:"id,omitempty"           schemapb:"description=The domain, e.g. example.com"`
	DisplayName string   `json:"display_name,omitempty"`
	Origins     []string `json:"origins,omitempty"`
}

// WebAuthn method (security keys).
type WebAuthn struct {
	Enabled      bool         `json:"enabled,omitempty"      schemapb:"default=false"`
	Passwordless bool         `json:"passwordless,omitempty" schemapb:"default=false"`
	RP           RelyingParty `json:"rp,omitempty"`
}

// Passkey method.
type Passkey struct {
	Enabled bool         `json:"enabled,omitempty" schemapb:"default=false"`
	RP      RelyingParty `json:"rp,omitempty"`
}

// OIDC is sign-in with other identity providers.
type OIDC struct {
	Enabled   bool           `json:"enabled,omitempty"   schemapb:"default=false"`
	Providers []OIDCProvider `json:"providers,omitempty"`
}

// OIDCProvider is one upstream provider.
type OIDCProvider struct {
	ID        string   `json:"id,omitempty"         schemapb:"description=Stable id: part of the callback URL and of credentials"`
	Provider  string   `json:"provider,omitempty"   schemapb:"description=generic, google, github, apple, microsoft, …"`
	Label     string   `json:"label,omitempty"`
	ClientID  string   `json:"client_id,omitempty"`
	IssuerURL string   `json:"issuer_url,omitempty"`
	Scope     []string `json:"scope,omitempty"`
	// Mapper is the Jsonnet mapping the provider's claims to traits.
	Mapper string `json:"mapper,omitempty" schemapb:"description=Jsonnet from claims to traits"`
	// Tenant, Team and similar provider-specific keys.
	Extra map[string]string `json:"extra,omitempty"`
}

// Session settings.
type Session struct {
	Lifespan               time.Duration `json:"lifespan,omitempty"                 schemapb:"default=24h"`
	EarliestPossibleExtend time.Duration `json:"earliest_possible_extend,omitempty" schemapb:"description=Zero: any time"`
	WhoamiRequiredAAL      string        `json:"whoami_required_aal,omitempty"      schemapb:"default={\"stringValue\":\"highest_available\"}" validate:"oneof=highest_available aal1"`
	CookieDomain           string        `json:"cookie_domain,omitempty"`
	CookiePersistent       bool          `json:"cookie_persistent,omitempty"        schemapb:"default=true"`
	CookieSameSite         string        `json:"cookie_same_site,omitempty"         schemapb:"default={\"stringValue\":\"Lax\"}"               validate:"oneof=Lax Strict None"`
}

// Identity schemas. Empty keeps the base file's.
type Identity struct {
	DefaultSchemaID string `json:"default_schema_id,omitempty"`
	// Schemas by id: JSON Schema documents.
	Schemas map[string]string `json:"schemas,omitempty"`
}

// Features are Kratos's feature flags.
type Features struct {
	// ContinueWith lets API flows (native apps) finish with continue_with
	// steps — a session token, the next flow — instead of a browser
	// redirect; recovery from a native app needs it.
	ContinueWith bool `json:"continue_with,omitempty" schemapb:"default=false;description=Let native apps finish flows (recovery included) without a browser"`
	// ChooseRecoveryAddress lets a user pick the address (email or phone) a
	// recovery code goes to.
	ChooseRecoveryAddress bool `json:"choose_recovery_address,omitempty" schemapb:"default=false"`
}

// Secrets the overlay needs, kept apart from Settings (their own Live
// paths): the console shows Settings in full and writes a secret only when
// the operator enters a new one.
type Secrets struct {
	// OIDC are the client secrets of the OIDC providers, by provider id.
	OIDC map[string]string
	// OAuth2ProviderHeaders go with Kratos's requests to Hydra.
	OAuth2ProviderHeaders map[string]string
	// TokenKey is the private JWK the session tokens are signed with; empty:
	// no tokens.
	TokenKey string
	// Masked: the secrets are placeholders (a rendering to show, not to
	// write).
	Masked bool
}

// OAuth2Provider makes login and registration serve Ory Hydra's
// login_challenge (Kratos as Hydra's login provider).
type OAuth2Provider struct {
	// URL of Hydra's admin API; empty: off.
	URL              string `json:"url,omitempty"`
	OverrideReturnTo bool   `json:"override_return_to,omitempty" schemapb:"default=false"`
}

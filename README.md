# backplane-kratos

[Ory Kratos](https://www.ory.sh/kratos/) joined to a Backplane installation.
Kratos stays a stock installation (official image, official chart); this
service sits next to it and turns it into parts of Wiring:

- **Kratos's courier → hook `kratos.Deliver`.** Verification, recovery and
  login codes go wherever the installation binds the hook — typically
  `templates.Render → courier.SendMail` or `courier.SendSms`. A failed delivery
  is retried by Kratos's own queue.
- **Self-service flows → hooks `kratos.Before<Flow>` / `kratos.After<Flow>`**
  (registration, login, settings, recovery, verification). A binding can let
  the flow continue, deny it with messages on the form, or — after
  registration and settings — replace traits and metadata. A `Before<Flow>`
  hook runs before Kratos creates the flow, so there is no form yet: a deny
  there makes the flow's creation fail with an error (Kratos answers it as a
  server error), not form messages. To refuse a step with messages the user
  sees, deny at `After<Flow>`.
  `kratos.AfterRegistration` runs before Kratos stores the identity, so its
  `req.identity` has no id yet. `req.session` is the acting session as
  Kratos sends it — id, active, `authenticator_assurance_level`,
  `authenticated_at`, `issued_at`, `expires_at`, `authentication_methods`
  (method, aal, provider, completed_at) and `devices` — with no token or
  cookie: at `kratos.BeforeSettings`/`AfterSettings` the signed-in session,
  so a binding can refuse a settings change for a session the product does
  not trust (by `req.session.id`) or one without a second factor; after login
  and registration the new session, whose id is empty because Kratos stores
  it only after the hooks. `req.client_flow_id` is the flow the client
  submitted or started, as this service's proxy vouches for it (see
  [Routing](#routing)). It differs from `req.flow_id` only when Kratos
  converted the flow: an OIDC login of an unknown subject completes as a new
  registration flow, and an OIDC registration of a known one as a new login
  flow (Kratos v26, browser and API flows alike). A value the client
  forges never reaches the hooks. The field is empty when the request did
  not pass the proxy, and it never falls back to `flow_id`, so a product
  that binds a proof to the client's flow refuses an empty one.
- **Stored registration → hook `kratos.AfterRegistrationStored`**. Kratos
  calls it after it stores the identity and waits for the answer.
  `req.identity.id` is final, so it is the place to record anything keyed by
  the new identity (e.g. legal evidence). An error or a denial fails the
  flow, but the identity stays stored.
- **Completed flows → events** `Registered`, `LoggedIn`, `SettingsChanged`,
  `Recovered`, `Verified` for rules and reactors. Kratos runs its after-login
  hooks before it stores the session, so `LoggedIn` waits until the session
  is stored and carries it (id, `authenticated_at`, AAL, address, user agent);
  a login whose session is never stored publishes nothing. A registration
  that signs the identity in (setting *Sign the new identity in*) publishes
  `Registered` the same way, with the session the registration issued; one
  that does not sign in publishes it at once, without a session. A redeemed
  recovery signs the identity in too, and Kratos stores that session only after
  its hooks and sends none to them (`kratos.AfterRecovery` gets the identity
  alone). So `Recovered` waits for the session authenticated by a recovery
  method (`code_recovery`, `link_recovery`) since the recovery flow began, and
  carries it. A recovery whose session is never stored publishes nothing. Every flow event
  carries the flow's `transient_payload`, the same one its `Deliver` saw:
  Kratos gives a courier message no flow id, so a client marker in the
  payload is how a message and its completed flow are matched.
  `SettingsChanged` also carries `previous_traits`, the traits before the
  change as the signed-in session held them (Kratos changes a copy of the
  identity), so a product can notify the old address of an email change
  without keeping a copy. They equal `traits` when the flow changed no trait.
- **Self-service logout → event `LoggedOut`**. Kratos has no logout hooks, so
  this service serves Kratos's logout endpoints (`/self-service/logout`,
  `/self-service/logout/browser`, `/self-service/logout/api`) on its HTTP
  port and passes every request to Kratos's public URL unchanged (see
  [Routing](#routing)). Before forwarding a
  browser logout (`GET /self-service/logout?token=`, with the session
  cookie) or an API one (`DELETE /self-service/logout/api`), it asks Kratos
  whose session it is. Once Kratos has ended that session, it publishes
  `LoggedOut`: a flow event with the identity, its traits, `method: logout`
  and the session (id, `authenticated_at`, AAL, address, user agent). A
  logout Kratos refuses, a browser logout without the session cookie, and a
  logout that bypasses the route publish nothing. Delivery is best effort,
  like every flow event.
- **Native apps' session token exchange.** A native app signs in through the
  system browser with an API flow asking for
  `return_session_token_exchange_code=true` and a `return_to` it handles. It
  then trades the flow's `init_code` and the callback's `code` at
  `/sessions/token-exchange` for the session token. Kratos answers such a pair
  again and again, at any age, even for an ended session. So this service also
  serves `/sessions/token-exchange` on its HTTP port, in front of Kratos as for
  logout: it answers only for an active session authenticated within
  `token_exchange.max_age` (default `5m`), else `404` as for an unknown pair.
  Answers before the session exists (a polling app) pass as they are (see
  [Routing](#routing)).
  `return_to` must be listed in `allowed_return_urls` and carry a host:
  Kratos puts the default return URL's host into a private-use URI without one
  (`ru.app:/callback`), which then matches nothing. Use `ru.app://callback`.
- **New sessions → hook `kratos.SessionIssued`** (fail-closed, never in
  `fail_open`). Kratos stores a session before its credential leaves; this
  service sees that answer on its way out (see [Routing](#routing)) and asks
  the hook before the cookie or token reaches the client. This covers every
  answer under `/self-service/` that carries a session: the submits, a
  recovery link's GET, the OIDC callbacks, FedCM's token, and the native
  token exchange. `req`:
  - `flow`: login, registration or recovery, the flow the client submitted;
    empty for an OIDC callback with no start cookie.
  - `method`: the session's latest authentication method.
  - `flow_id`: the client's flow, the `client_flow_id` of the after hooks.
    It is the submit's `?flow=`, the start of an OIDC sign-in (browser and
    native), or for the native exchange the app's `X-Kratos-Flow-Id` header.
    This service does not verify that header: the product checks it against
    what its after hooks recorded for that flow.
  - `channel`: `browser` (cookie), `api` (token in the answer) or
    `native_exchange`.
  - `identity` and `session`: both as Kratos stored them; the session has
    no token.
  - `transient_payload`: the submit's; empty for an OIDC callback and the
    exchange, whose after hook had it.

  The result `deny: {code, messages}` revokes the session. So does an error
  or a timeout of the hook. The revoke retries until it succeeds, because
  Kratos refuses one that races its own write. The client then gets no
  credential: every `Set-Cookie` is stripped and the token is never
  returned.
  - API, JSON and exchange clients get Kratos's error shape: `403
    {"error": {"id": "session_refused", "reason": <code>, "details":
    {"messages": [...]}}}`, or `503` with `"id": "session_unavailable"`
    when the hook failed.
  - A browser form flow is sent with a 303 to `settings.error_ui_url?id=
    session_refused|session_unavailable&reason=<code>`, or gets the JSON
    when no error page is set.

  A session that cannot be used yet (`session.whoami.required_aal` asks
  for a second factor the user has) is admitted when the step-up
  completes, with the same session id. An answer that names the session
  (JSON) is admitted at each step, so the binding is idempotent by session
  id. A settings flow (an OIDC link among them) and a verification flow
  issue no session: Kratos only sets the cookie of a session that already
  exists (the signed-in one, or the registration's for a Hydra login), so
  the hook is not asked.
  The hop's cookie tells an OIDC link's callback from a sign-in's. A
  callback with no start cookie is asked with an empty `flow` and
  `flow_id`. While the hook is unbound, sessions pass unchecked. An answer
  the service cannot read whole (encoded, over 1 MiB, or not the JSON it
  claims) gets a 502 rather than passing unchecked. The client's
  `Accept-Encoding` is not sent to Kratos.
- **Section `kratos.login`** (backplane live section): how identities sign
  up and sign in — registration on or off, first and second factors, OIDC
  providers (id, kind, label), required AALs, recovery and verification —
  following the console settings, without secrets. `identifiers` lists the
  traits sign-in takes as the identifier (`traits.email`, `traits.phone`),
  their kind (`email`, `tel`, `username`) and the enabled first factors that
  take each (`password`, `code`, `webauthn`). They are read from the identity
  schemas, merged across schemas. The source is the schemas set in the
  settings; when the settings set none, it is the schemas Kratos runs (its
  base file's), read from Kratos every `kratos.schema_poll`. A `tel`
  identifier means phone login is on. Services follow it with
  `sections.Follow[*kratoseventsv1.LoginSection](root, "kratos.login")`.
- **Admin API → activities**: `GetIdentity`, `FindIdentities`,
  `CreateIdentity`, `UpdateIdentity`, `PatchIdentity`, `DeleteIdentity`,
  `DeleteCredentials`, `ListSessions`, `RevokeSessions`, `ExtendSession`,
  `CheckSession`, `GetSession`, `CreateRecoveryCode`, `ListMessages`,
  `ImportIdentities`. Changes, whether wiring makes them through these
  activities or an operator in the console, publish
  `IdentityCreated/Updated/Deleted` and `SessionsRevoked`. The event's `by`
  says who made the change: `wiring` or `console`. `SessionsRevoked` names
  the identity even when one session was revoked (`session_id` set),
  keyed by the identity.
- **Event contract**: the payloads are proto messages in
  `proto/kratos/events/v1` (Go: `github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1`),
  in protojson with proto field names: `FlowEvent`, `IdentityEvent`,
  `SessionsRevoked`. TypeScript (protobuf-es v2): the npm package
  `@backplane-labs/kratos-events`, released with the service.
- **Readiness without Kratos**: Kratos calls this service (webhooks), so the
  service is ready without it; Kratos's admin API is probed for the console's
  health only. Kratos can depend on it with `service_healthy`.
- **Console module**: Kratos's state and every hook point, identities (traits
  editor checked against the identity schema, credentials, verified addresses,
  sessions with extend and revoke, recovery codes and links), a batch import,
  sessions, the courier's queue, identity schemas, and a Settings page that
  saves revisions of this service's configuration. Every operator
  change is application audit.
- **Settings from the console**: flows on/off (registration included), UI
  URLs, lifespans, methods (password, codes, passkeys, WebAuthn, TOTP, social
  sign-in), sessions, identity schemas, the Hydra login provider — live.

## Routing

This service fronts Kratos's public host for everything that issues or ends
a session. Route these paths of Kratos's public host (behind any prefix the
host has, e.g. `/auth`) to this service's HTTP port; it passes every request
on to `kratos.public_url`. Route the whole `/self-service/` prefix: a
narrower set leaves a way to a session `SessionIssued` never sees (a
recovery link is a GET, FedCM has its own endpoint). Kratos's
`serve.public.base_url` stays the public host as clients see it.

| Path | Why |
| --- | --- |
| `/self-service/` | `SessionIssued`, `client_flow_id`, the OIDC start hop, `LoggedOut` |
| `GET /sessions/token-exchange` | The native exchange's age check and `SessionIssued` |

How the client's flow travels:

- Every request this service forwards to Kratos carries the header
  `X-Backplane-Kratos-Flow`. It holds the client's flow, HMAC-signed with
  the callbacks key, and the service drops any copy the client sent.
- The overlay adds the header to Kratos's `clients.web_hook.header_allowlist`
  (Kratos's default list plus this header), so Kratos hands it back to the
  after hooks.
- An OIDC start answer sends the browser through a hop on the public host,
  `/self-service/methods/oidc/backplane/start?t=<signed>`. The service
  rewrites the provider redirect (a 303 `Location`, or `redirect_browser_to`
  in JSON) to point at it. The hop takes the host of the provider URL's
  `redirect_uri`, so it needs no configuration. It works for the system
  browser of a native app too, which never saw the start request.
- The hop sets the cookie `backplane_kratos_flow_<hash of the OIDC state>`
  (HttpOnly, Secure, SameSite=Lax, living as long as the longest login,
  registration or recovery flow), then sends a 303 to exactly the provider
  URL it was signed for. A link that is tampered with, foreign or expired
  gets a 400.
- The OIDC callback reads the cookie for its `state` and deletes it. A
  form_post callback is a cross-site POST that brings no cookie and
  deletes none; Kratos sends it on to a GET that brings the cookie.
- Apple's form_post callback works: Kratos answers the POST with a
  redirect to a GET, and the session is issued on that GET.

## How Kratos picks up the settings

Kratos reloads configuration files, nothing else. Kratos runs with two files:
the deployment's own and an overlay this service writes:

```
kratos serve -c /etc/config/kratos.yml -c /etc/backplane/kratos.yml
```

A key in the overlay wins over the deployment's; lists (hooks) are replaced.
The overlay owns the self-service flows and methods, sessions, the courier
while `kratos.Deliver` is bound, identity schemas when the settings define
some, and `oauth2_provider` when set. The deployment keeps `dsn`, `serve`,
`secrets`, `log` and everything the settings do not model (or set it through
`settings.overrides`).

Hook points are written only for bound hooks: binding `kratos.AfterLogin` in
Wiring adds its webhook to the overlay within seconds; an unbound point costs
Kratos nothing.

The overlay lives on a volume shared with the Kratos container — run this
service as a sidecar. `deployments/examples/helm-values.yaml` does that with
the official chart (a native sidecar: Kratos starts once the overlay is
written). Without a shared file (`overlay` empty) the console shows the
rendered configuration to paste instead.

The file holds client secrets: keep it on a pod-private in-memory volume.
`overlay_mode` (default `0644`) must let Kratos's user read it; a file Kratos
cannot read leaves it on the previous configuration.

## Configuration

| Key | |
| --- | --- |
| `kratos.admin_url`, `kratos.public_url` | Kratos's APIs (default `127.0.0.1:4434/4433`) |
| `kratos.headers` | Secret headers of every request (a proxy's authorization) |
| `kratos.timeout` | Bound of one request to Kratos (default `10s`) |
| `kratos.schema_poll` | How often `kratos.login` reads the identity schemas from Kratos while the settings set none (default `1m`) |
| `callbacks.listen`, `callbacks.url` | Where Kratos calls this service (default `:8090`, `http://127.0.0.1:8090`) |
| `callbacks.key` | Authenticates Kratos: every callback (hooks, events, courier) carries Basic `kratos:<key>`, the Authorization header Kratos redacts in its logs; default: derived from the internal secret |
| `overlay`, `overlay_mode` | The overlay file and its permissions |
| `settings` | Live: the Kratos settings above, edited on the module's Settings page |
| `oidc_secrets`, `oauth2_provider_headers` | Live secrets kept apart from the settings: the console writes them only when an operator enters new ones |
| `fail_open` | Live: flow hooks whose failure lets the flow continue (default: none — a failing hook stops the flow) |
| `token_exchange.max_age` | How long after sign-in a native app's exchange code pair is answered (default `5m`) |

### Tracing

A flow is one trace from the browser's request to the product's hooks:
Kratos continues the request's trace into its webhook calls, the callbacks
listener continues it (a server span), and the hook call carries it to the
product (`AfterRegistration`, `AfterLogin`, events). Kratos does this only
with its own tracing on: the deployment's base file sets `tracing.provider:
otel` and `tracing.providers.otlp` (`server_url`, `insecure`,
`sampling.sampling_ratio`) towards its Collector. Without it Kratos sends
no `traceparent` and the callback starts a new trace.
`TestCallbacksContinueKratosTrace` checks the whole chain on a real Kratos.

### Secrets in Kratos's logs

Kratos logs every webhook it dispatches with its request headers. The callback
key rides the Authorization header, which Kratos always redacts (unless the
deployment sets `log.leak_sensitive_values`), so it never appears even at
`trace`; webhook bodies and the overlay's secrets (OIDC client secrets,
`oauth2_provider_headers`, the token key) are not logged either
(`TestCallbackSecretsNotLogged` checks the key on a real Kratos at `trace`).
At `debug` and below, Kratos's own courier line "Courier sent out message."
logs the message subject, and Kratos's default verification and recovery
templates put the one-time code in it: run Kratos at `info` in production.

## Who made a request: session tokens and `pkg/auth`

A service learns who made a request without a user cache, so every replica
answers alike:

- **Session tokens** (the default way). Generate a signing key on the
  Settings page (Session tokens): Kratos then turns a session into a short JWT
  at `GET <Kratos public>/sessions/whoami?tokenize_as=backplane`, and this
  service serves the public keys at `<its public URL>/.well-known/jwks.json`.
  A client sends the token as `Authorization: Bearer`; a service verifies it
  locally — no call per request. A revoked session gets no new token at once;
  a token already issued stays valid for the token lifetime (default 5m).
- **whoami**. The session cookie or session token itself, asked of Kratos on
  every request — no cache: a revocation shows on the next request. For the
  few actions that must not outlive a revocation.

```go
tokens, _ := auth.NewTokens(auth.TokensOptions{
	KeysURL: "http://backplane-kratos/.well-known/jwks.json",
	Issuer:  "https://auth.example.com/", // Kratos's serve.public.base_url
})
sessions, _ := auth.NewSessions("http://kratos:4433", nil)
a := auth.Authenticator{Tokens: tokens, Sessions: sessions}

mux.Handle("/api/", a.Required(api)) // a bearer JWT, a session token or Kratos's cookie
// in a handler:
who, _ := auth.FromContext(r.Context()) // who.IdentityID, who.HasRole("operator"), who.AtLeast(auth.AAL2)
```

Roles are the `roles` list of the identity's public metadata. The token's
claims come from Jsonnet (Settings → Session tokens → Claims): by default
`aal`, `amr`, `authenticated_at`, `email`, `schema_id` and `metadata`, next to
Kratos's `iss`, `sub`, `sid`, `iat`, `nbf`, `exp`, `jti`.

A refused token is never an Auth. One that is authentic (signature, issuer
and audience verified) but out of its time, `exp` passed or `nbf` not come
beyond the leeway (30s), fails with `auth.ErrExpired` wrapped in
`*auth.ExpiredError`, whose `Auth` names the session it was:

```go
var late *auth.ExpiredError
if errors.As(err, &late) {
	reason := terminated[late.Auth.SessionID] // e.g. why a long-offline device's session ended
}
```

Rotating the key: generate a new one on the same page and save; the earlier
public key stays listed so the tokens it signed keep verifying, and is removed
after a token lifetime. The only cache in `pkg/auth` is of these public keys:
fetched on first use, again on a token with an unknown kid (at most once per
30s) and in the background every 10m; when the keys cannot be fetched, the
last good set keeps verifying.

## Example wiring

Kratos's messages through the installation's templates and courier:

```yaml
hook: kratos.Deliver
steps:
  rendered:
    activity: templates.Render
    input: {template: "'kratos.' + req.template_type", data: {code: req.code, link: req.link}}
  mail:
    activity: courier.SendMail
    when: req.channel == 'email'
    input: {to: [req.recipient], subject: rendered.parts.subject, text: rendered.parts.text, html: rendered.parts.html}
  sms:
    activity: courier.SendSms
    when: req.channel == 'sms'
    input: {to: req.recipient, text: rendered.parts.text}
result: {}
```

Codes by SMS: give a trait `"format": "tel"` and `"via": "sms"` in the
identity schema (credentials `code`, verification, recovery); Kratos sends
those codes on the `sms` channel of the same hook, `req.channel == 'sms'`,
`req.recipient` the phone in E.164. Recovery by SMS needs the setting
*Choose the recovery address*. courier delivers SMS through a provider
plugin (`courier.SendSms`).

A registration policy in CEL alone:

```yaml
hook: kratos.AfterRegistration
steps: {}
result:
  deny: "req.identity.traits.email.endsWith('@example.org') ? dyn({'messages': [{'field': 'traits.email', 'id': 4000100, 'text': 'Use your work address'}]}) : dyn(null)"
```

## Develop

```sh
make configure configure-web   # tools into ./bin, web dependencies
make gen web build             # protos, console module, binary
make test                      # unit tests
make it-up it                  # integration tests against a real Kratos (docker)
```

Kratos v26.2.0; the overlay is validated against its configuration schema
before it is written.

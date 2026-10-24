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
  registration and settings — replace traits and metadata.
- **Completed flows → events** `Registered`, `LoggedIn`, `SettingsChanged`,
  `Recovered`, `Verified` for rules and reactors. Kratos runs its after-login
  hooks before it stores the session, so `LoggedIn` waits until the session
  is stored and carries it (id, `authenticated_at`, AAL, address, user agent);
  a login whose session is never stored publishes nothing. Every flow event
  carries the flow's `transient_payload`, the same one its `Deliver` saw:
  Kratos gives a courier message no flow id, so a client marker in the
  payload is how a message and its completed flow are matched.
- **Section `kratos.login`** (backplane live section): how identities sign
  up and sign in — registration on or off, first and second factors, OIDC
  providers (id, kind, label), required AALs, recovery and verification —
  following the console settings, without secrets. Services follow it with
  `sections.Follow[*kratoseventsv1.LoginSection](root, "kratos.login")`.
- **Admin API → activities**: `GetIdentity`, `FindIdentities`,
  `CreateIdentity`, `UpdateIdentity`, `PatchIdentity`, `DeleteIdentity`,
  `DeleteCredentials`, `ListSessions`, `RevokeSessions`, `ExtendSession`,
  `CheckSession`, `GetSession`, `CreateRecoveryCode`, `ListMessages`,
  `ImportIdentities`; changes publish
  `IdentityCreated/Updated/Deleted` and `SessionsRevoked`.
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
| `callbacks.listen`, `callbacks.url` | Where Kratos calls this service (default `:8090`, `http://127.0.0.1:8090`) |
| `callbacks.key` | Authenticates Kratos; default: derived from the internal secret |
| `overlay`, `overlay_mode` | The overlay file and its permissions |
| `settings` | Live: the Kratos settings above, edited on the module's Settings page |
| `oidc_secrets`, `oauth2_provider_headers` | Live secrets kept apart from the settings: the console writes them only when an operator enters new ones |
| `fail_open` | Live: flow hooks whose failure lets the flow continue (default: none — a failing hook stops the flow) |

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

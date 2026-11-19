// Package kratos is backplane-kratos as a library: Main runs it. It joins
// an Ory Kratos installation to Backplane: the courier's messages and the
// self-service flows become hooks and events, the admin API becomes
// activities and a console module, and the settings an operator edits are
// written to a configuration overlay Kratos reloads.
package kratos

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane"
	"github.com/backplane-labs/backplane/pkg/backplane/api"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/drivers/standard"
	infranats "github.com/backplane-labs/backplane/pkg/backplane/infra/nats"
	"github.com/backplane-labs/backplane/pkg/backplane/infra/postgres"
	"github.com/backplane-labs/backplane/pkg/backplane/tracehttp"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc"

	"github.com/gopherex/xprobe/pkg/probe"

	"github.com/backplane-labs/backplane-kratos/internal/activities"
	"github.com/backplane-labs/backplane-kratos/internal/admin"
	"github.com/backplane-labs/backplane-kratos/internal/apply"
	"github.com/backplane-labs/backplane-kratos/internal/backchannel"
	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/jwks"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/outbox"
	"github.com/backplane-labs/backplane-kratos/internal/overlay"
	"github.com/backplane-labs/backplane-kratos/internal/scim"
	"github.com/backplane-labs/backplane-kratos/internal/tokenkeys"
	"github.com/backplane-labs/backplane-kratos/internal/ui"
	kratosconsolev1 "github.com/backplane-labs/backplane-kratos/proto/kratos/console/v1"
)

// Config is the whole configuration: file (BACKPLANE_CONFIG_FILE) < env
// KRATOS_* (BACKPLANE_* for the SDK block) < Consul KV for Live fields.
type Config struct {
	config.Backplane `json:"backplane"`

	// Kratos is the installation.
	Kratos Connection `json:"kratos"`
	// Callbacks is the listener Kratos calls (courier, hooks, events).
	Callbacks Callbacks `json:"callbacks"`
	// Overlay is the file Kratos loads after its own (-c base -c overlay),
	// shared with the Kratos container; empty: nothing is written, the
	// console shows the configuration to paste.
	Overlay string `json:"overlay,omitempty" schemapb:"description=Path of the overlay file Kratos loads (empty: snippets only)"`
	// OverlayMode is the file's permission bits (octal): Kratos's user
	// must read it.
	OverlayMode string `json:"overlay_mode,omitempty" schemapb:"default=0644"`
	// Settings are Kratos's settings rendered into the overlay; live.
	Settings config.Live[overlay.Settings] `json:"settings"`
	// OIDCSecrets are the OIDC providers' client secrets by provider id;
	// live, kept apart from the settings.
	OIDCSecrets config.Live[map[string]config.Secret] `json:"oidc_secrets,omitempty" schemapb:"description=Client secrets of the OIDC providers by provider id"`
	// OAuth2ProviderHeaders go with Kratos's requests to Hydra; live.
	OAuth2ProviderHeaders config.Live[map[string]config.Secret] `json:"oauth2_provider_headers,omitempty" schemapb:"description=Headers of Kratos's requests to Hydra's admin API"`
	// TokenKey is the private JWK (JSON) session tokens are signed with; its
	// public key must be the first of settings.tokens.keys. Live, a secret.
	TokenKey config.Live[config.Secret] `json:"token_key,omitempty" schemapb:"description=Private JWK the session tokens are signed with (empty: no tokens)"`
	// TokenRotation is how long a minted signing key signs before the next
	// one takes over (token_key empty, NATS on).
	TokenRotation time.Duration `json:"token_rotation" schemapb:"default=720h;description=How long a minted token signing key signs before the next one"`
	// FailOpen names flow hooks whose failure lets the flow continue.
	FailOpen config.Live[[]string] `json:"fail_open,omitempty" schemapb:"description=Flow hooks (e.g. AfterLogin) whose failure lets the flow continue"`
	// TokenExchange bounds the native apps' session token exchange.
	TokenExchange TokenExchange `json:"token_exchange"`
	// DB keeps the security events until the broker took them (pg-outbox);
	// required with events (NATS), absent without them.
	DB *postgres.Config `json:"db,omitempty"`
	// Directories are the corporate IdPs provisioning people over SCIM; live.
	Directories config.Live[[]scim.Directory] `json:"directories,omitempty" schemapb:"description=Corporate directories provisioning people over SCIM 2.0"`
	// DirectoryTokens are the directories' bearer tokens by directory id;
	// live secrets, kept apart from the directories.
	DirectoryTokens config.Live[map[string]config.Secret] `json:"directory_tokens,omitempty" schemapb:"description=Bearer token of each directory's SCIM requests by directory id"`
	// OIDCBackchannel are the OIDC providers whose IdPs send back-channel
	// logout tokens; live.
	OIDCBackchannel config.Live[[]backchannel.Provider] `json:"oidc_backchannel,omitempty" schemapb:"description=OIDC providers sending back-channel logout tokens"`
}

// keysTimeout bounds a fetch of an IdP's signing keys.
const keysTimeout = 10 * time.Second

// TokenExchange of the native sign-in: Kratos answers an exchange code
// pair for ever; the service answers it only this long after the session
// was authenticated, and only while the session is active.
type TokenExchange struct {
	MaxAge time.Duration `json:"max_age" schemapb:"default=5m;gt=0;description=How long after sign-in an exchange code pair is answered"`
}

// Connection to Kratos.
type Connection struct {
	AdminURL  string                   `json:"admin_url"         schemapb:"default=http://127.0.0.1:4434"`
	PublicURL string                   `json:"public_url"        schemapb:"default=http://127.0.0.1:4433"`
	Headers   map[string]config.Secret `json:"headers,omitempty" schemapb:"description=Headers of every request (a proxy's authorization)"`
	Timeout   time.Duration            `json:"timeout"           schemapb:"default=10s"`
	// SchemaPoll is how often the identity schemas are read from Kratos
	// for kratos.login while the settings set none (the base file's).
	SchemaPoll time.Duration `json:"schema_poll" schemapb:"default=1m;gt=0;description=How often kratos.login reads the base file's identity schemas from Kratos"`
}

// Callbacks listener.
type Callbacks struct {
	Listen string `json:"listen" schemapb:"default=:8090"`
	// URL is the listener as Kratos reaches it.
	URL string `json:"url" schemapb:"default=http://127.0.0.1:8090"`
	// Key authenticates Kratos; empty: derived from the internal secret,
	// the same on every replica.
	Key config.Secret `json:"key,omitempty"`
}

// Validate what the schema cannot: the settings must render into a
// configuration Kratos accepts.
func (c *Config) Validate() error {
	every := func(string) bool { return true }

	doc, err := overlay.Render(
		c.Settings.Get(), overlay.Secrets{},
		overlay.Wiring{URL: c.Callbacks.URL, Key: "k", Bound: every, Events: true},
	)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	if err := overlay.Validate(doc); err != nil {
		return fmt.Errorf("settings: %w", err)
	}

	if err := scim.Validate(c.Directories.Get()); err != nil {
		return fmt.Errorf("directories: %w", err)
	}

	if err := backchannel.Validate(c.OIDCBackchannel.Get(), false); err != nil {
		return fmt.Errorf("oidc_backchannel: %w", err)
	}

	if c.NATS.Enabled() && c.DB == nil {
		return ErrNoDB
	}

	return nil
}

// callbackKey is the configured key or one derived from the internal
// secret.
func (c *Config) callbackKey() (string, error) {
	if k := c.Callbacks.Key.Reveal(); k != "" {
		return k, nil
	}

	secret := c.InternalSecret.Reveal()
	if secret == "" {
		return "", ErrNoKey
	}

	m := hmac.New(sha256.New, []byte(secret))
	m.Write([]byte("backplane-kratos callbacks"))

	return hex.EncodeToString(m.Sum(nil)), nil
}

// ErrOverlayMode: overlay_mode is not octal permission bits.
var ErrOverlayMode = errors.New("kratos: overlay_mode must be octal permission bits like 0640")

// ErrNoDB: events are on (NATS) and no database keeps them until published.
var ErrNoDB = errors.New("kratos: db.dsn is required with events (nats): it keeps the security events")

// ErrNoKey: neither a callbacks key nor an internal secret is configured.
var ErrNoKey = errors.New("kratos: callbacks.key or backplane.internal_secret is required")

// State is the service's tree.
type State struct {
	// Kratos is the installation, probed for the console's health but not
	// part of readiness: Kratos calls this service (webhooks), so it starts
	// after it is ready.
	Kratos      deps.Optional[ory.Client]
	Flows       *flows.Flows
	Applier     *apply.Applier
	Activities  *activities.Activities
	Admin       *admin.Admin
	Directories *scim.Directories
	Outbox      *outbox.Outbox
	Backchannel *backchannel.Receiver
	// TokenKeys sign and verify the session tokens.
	TokenKeys tokenkeys.Source

	callbacks string                        // listen address of the callbacks
	settings  config.Live[overlay.Settings] // the tokens' public keys among them
	public    http.Handler                  // Kratos's public endpoints that issue and end sessions
}

// Main runs backplane-kratos until a signal stops it, exiting on error.
func Main() {
	if err := Run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Run runs backplane-kratos until ctx ends or a signal stops it.
func Run(ctx context.Context) error {
	svc, err := backplane.Open(ctx, newState, standard.Drivers())
	if err != nil {
		return fmt.Errorf("kratos: %w", err)
	}

	st := svc.State()

	svc.HTTP("/", st.Flows.Handler(), api.Listen("callbacks", st.callbacks))
	svc.HTTP("/.well-known/", jwks.Handler(st.settings, st.TokenKeys))
	svc.HTTP(flows.SelfServicePath, st.public)
	svc.HTTP(flows.TokenExchangePath, st.public)
	svc.HTTP(scim.Path, st.Directories.Handler())
	svc.HTTP(backchannel.Path, st.Backchannel.Handler())
	svc.Internal(func(r grpc.ServiceRegistrar) { kratosconsolev1.RegisterAdminServiceServer(r, st.Admin) })

	if bundle := ui.Bundle(); bundle != nil {
		svc.UI(bundle)
	}

	svc.ReadinessProbe(probe.FromError(st.Applier.Ready))

	if err := svc.Run(ctx); err != nil {
		return fmt.Errorf("kratos: %w", err)
	}

	return nil
}

func newState(root backplane.Root[Config]) (*State, error) {
	cfg := root.Config()

	key, err := cfg.callbackKey()
	if err != nil {
		return nil, err
	}

	headers := map[string]string{}
	for k, v := range cfg.Kratos.Headers {
		headers[k] = v.Reveal()
	}

	// Kratos is part of the installation and continues the trace: its admin
	// and public calls carry the trace context.
	client, err := ory.New(ory.Options{
		Admin: cfg.Kratos.AdminURL, Public: cfg.Kratos.PublicURL, Headers: headers, Timeout: cfg.Kratos.Timeout,
		Transport: tracehttp.NewTransport(nil, tracehttp.WithPropagator(otel.GetTextMapPropagator())),
	})
	if err != nil {
		return nil, fmt.Errorf("kratos: %w", err)
	}

	st := &State{
		Kratos:    installation(root, client),
		callbacks: cfg.Callbacks.Listen,
		settings:  cfg.Settings,
	}

	st.Outbox = securityOutbox(root, cfg)

	st.Flows = flows.New(root, key, cfg.FailOpen, client, st.Outbox)
	events.NewLogin(root, cfg.Settings, client, cfg.Kratos.SchemaPoll)

	public, err := url.Parse(client.PublicURL())
	if err != nil {
		return nil, fmt.Errorf("kratos: public url: %w", err)
	}

	st.public = st.Flows.Public(public, headers, cfg.TokenExchange.MaxAge, cfg.Settings)

	mode, err := strconv.ParseUint(cfg.OverlayMode, 8, 32)
	if err != nil || mode > 0o777 {
		return nil, fmt.Errorf("%w: %q", ErrOverlayMode, cfg.OverlayMode)
	}

	st.TokenKeys = tokenKeys(root, cfg)

	st.Applier = apply.New(
		root,
		cfg.Overlay,
		os.FileMode(mode),
		cfg.Settings,
		apply.Secrets{
			OIDC:                  cfg.OIDCSecrets,
			OAuth2ProviderHeaders: cfg.OAuth2ProviderHeaders,
			TokenKeys:             st.TokenKeys,
		},
		st.Flows,
		overlay.Wiring{
			URL: cfg.Callbacks.URL, Key: key, Events: cfg.NATS.Enabled(),
		},
	)
	st.Activities = activities.New(root, client)
	st.Directories = scim.New(root, cfg.Directories, cfg.DirectoryTokens, client, st.Outbox,
		st.Activities.IdentityEvent("IdentityCreated"), st.Activities.IdentityEvent("IdentityUpdated"),
		st.Activities.IdentityEvent("IdentityDeleted"))
	st.Backchannel = backchannel.New(root, cfg.OIDCBackchannel, client, st.Activities.RevokedEvent(),
		&http.Client{Transport: tracehttp.NewTransport(nil), Timeout: keysTimeout}, time.Now)
	st.Admin = admin.New(
		root, client, st.Flows, st.Applier, cfg.FailOpen, cfg.Settings, st.TokenKeys, cfg.NATS.Enabled(), st.Activities,
	)

	return st, nil
}

// securityOutbox keeps the security events in cfg.DB until the broker took
// them; without a broker there are no events and nothing is kept.
func securityOutbox(root backplane.Root[Config], cfg Config) *outbox.Outbox {
	if !cfg.NATS.Enabled() {
		return outbox.Off()
	}

	db := deps.NewDependency(root, postgres.New(*cfg.DB,
		postgres.Schema(outbox.Schema), postgres.Migrations(outbox.Migrations())))
	box := outbox.New(root, db, outbox.Schema)
	box.Go(box.Run)

	return box
}

// installation is the Kratos installation under parent: probed, never part
// of readiness.
func installation(parent deps.Scope, client ory.Client) deps.Optional[ory.Client] {
	return deps.NewOptional[ory.Client](parent, dependency{client: client}, deps.ProbeOptional())
}

// dependency is the Kratos installation: present while its admin API is
// ready.
type dependency struct{ client ory.Client }

func (dependency) Name() string { return "kratos" }

func (d dependency) Provide(context.Context, deps.Scope) (ory.Client, error) { return d.client, nil }

func (d dependency) Probe(ctx context.Context, _ ory.Client) error {
	if err := d.client.Ready(ctx); err != nil {
		return fmt.Errorf("kratos at %s: %w", d.client.AdminURL(), err)
	}

	return nil
}

func (dependency) Close(context.Context, ory.Client) error { return nil }

// propagation is how long a minted key is published before it signs.
const propagation = 2 * time.Minute

// tokenKeys are the configured signing keys, else (token_key empty, NATS
// on) the ones minted, kept in NATS KV and rotated every token_rotation.
func tokenKeys(root backplane.Root[Config], cfg Config) tokenkeys.Source {
	if cfg.TokenKey.Get().Reveal() != "" || !cfg.NATS.Enabled() {
		return tokenkeys.NewConfigured(cfg.TokenKey, cfg.Settings)
	}

	section := infranats.FromBackplane(cfg.NATS)
	conn := deps.NewDependency(root, infranats.New(section), deps.Name("nats token keys"))

	minted := tokenkeys.NewMinted(root, conn, section, int(cfg.NATS.Replicas), func() tokenkeys.Schedule {
		ttl := cfg.Settings.Get().Tokens.TTL
		if ttl <= 0 {
			ttl = overlay.DefaultTokenTTL
		}

		return tokenkeys.Schedule{Every: cfg.TokenRotation, Propagation: propagation, TokenTTL: ttl}
	})

	return minted.Source()
}

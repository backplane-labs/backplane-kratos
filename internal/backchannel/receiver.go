package backchannel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/deps"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// Path is the prefix of the receivers, /oidc/backchannel-logout/<provider>.
const Path = "/oidc/backchannel-logout/"

// ByBackchannel is the `by` of the sessions a logout token revokes.
const ByBackchannel = "backchannel"

const (
	// maxForm bounds a logout request's body.
	maxForm = 64 << 10
	// timeout bounds one logout's work: keys, Kratos, the broker.
	timeout = 15 * time.Second
)

// Kratos is the admin API a logout needs.
type Kratos interface {
	ListIdentities(ctx context.Context, f ory.IdentityFilter) (ory.Page[ory.Identity], error)
	DeleteIdentitySessions(ctx context.Context, id string) error
}

// SessionsRevoked is kratos.SessionsRevoked.
type SessionsRevoked = *kratoseventsv1.SessionsRevoked

// Receiver ends the Kratos sessions of the people an IdP logs out.
type Receiver struct {
	deps.Component

	providers config.Live[[]Provider]
	kratos    Kratos
	revoked   event.Ref[SessionsRevoked]
	keys      *keys
	seen      *seen
	now       func() time.Time
}

// New is the receiver of providers' logout tokens under parent: it ends
// sessions through kratos and publishes them on revoked; client fetches the
// providers' keys, now is the clock.
func New(
	parent deps.Scope, providers config.Live[[]Provider], kratos Kratos, revoked event.Ref[SessionsRevoked],
	client *http.Client, now func() time.Time,
) *Receiver {
	return &Receiver{
		Component: deps.NewComponent(parent, "backchannel"), providers: providers, kratos: kratos, revoked: revoked,
		keys: newKeys(client), seen: newSeen(), now: now,
	}
}

// Handler serves POST Path<provider>.
func (r *Receiver) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+Path+"{provider}", r.logout)

	return mux
}

func (r *Receiver) logout(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	p, ok := find(r.providers.Get(), req.PathValue("provider"))
	if !ok {
		http.NotFound(w, req)

		return
	}

	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	defer cancel()

	req.Body = http.MaxBytesReader(w, req.Body, maxForm)
	if err := req.ParseForm(); err != nil || req.PostForm.Get("logout_token") == "" {
		invalid(w, "a logout_token form field is required")

		return
	}

	now := r.now()

	claims, err := r.verify(ctx, p, req.PostForm.Get("logout_token"), now)

	switch {
	case errors.Is(err, ErrKeys):
		r.Log().Ctx().Warn(ctx, "backchannel: provider keys unavailable", xlog.String("provider", p.ID), xlog.Err(err))
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	case err != nil:
		r.Log().Ctx().Info(ctx, "backchannel: logout token refused", xlog.String("provider", p.ID), xlog.Err(err))
		invalid(w, err.Error())

		return
	}

	jti := p.ID + ":" + claims.JTI
	if r.seen.has(jti, now) {
		w.WriteHeader(http.StatusOK)

		return
	}

	if err := r.end(ctx, p, claims); err != nil {
		r.Log().Ctx().Error(ctx, "backchannel: logout not completed", xlog.String("provider", p.ID), xlog.Err(err))
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	r.seen.add(jti, claims.Expiry, now)
	w.WriteHeader(http.StatusOK)
}

func (r *Receiver) verify(ctx context.Context, p Provider, raw string, now time.Time) (Claims, error) {
	kid, err := KeyID(raw)
	if err != nil {
		return Claims{}, err
	}

	set, err := r.keys.get(ctx, p.JWKSURL, kid, now)
	if err != nil {
		return Claims{}, err
	}

	return Verify(raw, p, set, now)
}

// end deletes the sessions of the identity holding <provider>:<sub> and
// publishes it; a person Kratos does not know is already signed out.
func (r *Receiver) end(ctx context.Context, p Provider, c Claims) error {
	page, err := r.kratos.ListIdentities(ctx, ory.IdentityFilter{CredentialsIdentifier: p.ID + ":" + c.Subject})
	if err != nil {
		return err
	}

	for i := range page.Items {
		id := page.Items[i].ID
		if err := r.kratos.DeleteIdentitySessions(ctx, id); err != nil && !ory.IsNotFound(err) {
			return err
		}

		ev := &kratoseventsv1.SessionsRevoked{IdentityId: id, By: ByBackchannel}
		evID := event.ID("backchannel-" + p.ID + "-" + c.JTI + "-" + id)

		if err := r.revoked.Publish(ctx, ev, event.Key(id), evID); err != nil {
			return fmt.Errorf("backchannel: publish: %w", err)
		}
	}

	return nil
}

func invalid(w http.ResponseWriter, detail string) {
	body, err := json.Marshal(map[string]string{"error": "invalid_request", "error_description": detail})
	if err != nil {
		body = []byte(`{"error":"invalid_request"}`)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write(body)
}

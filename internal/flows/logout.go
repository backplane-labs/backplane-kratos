package flows

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/backplane-labs/backplane/pkg/backplane/event"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gopherex/xlog"

	"github.com/backplane-labs/backplane-kratos/internal/events"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// LogoutPath is the prefix of Kratos's self-service logout endpoints the
// deployment routes to this service instead of Kratos.
const LogoutPath = "/self-service/logout"

const (
	// maxLogoutBody bounds the body of an API logout ({"session_token"}).
	maxLogoutBody = 64 << 10
	// logoutCheck bounds the look-ups around a logout.
	logoutCheck = 5 * time.Second
	// logoutPoint is the stats point of the logout proxy.
	logoutPoint = "logout"
)

// Logout serves Kratos's logout endpoints (LogoutPath and below) in front
// of Kratos at public: Kratos ends the session as always, and when it has,
// LoggedOut is published with it. Kratos itself has no logout hooks.
// headers go with every request to Kratos (a proxy's authorization).
func (f *Flows) Logout(public *url.URL, headers map[string]string) http.Handler {
	proxy := kratosProxy(public, headers)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		session := f.loggingOut(r)

		proxy.ServeHTTP(w, r)

		if session.ID != "" {
			f.loggedOut(context.WithoutCancel(r.Context()), session, start)
		}
	})
}

// loggingOut is the session a logout request ends: the cookie's for a
// browser logout, the body's token for an API one; zero for any other
// request or when Kratos knows no session.
func (f *Flows) loggingOut(r *http.Request) ory.Session {
	var token, cookie string

	switch {
	case r.Method == http.MethodGet && r.URL.Path == LogoutPath:
		cookie = r.Header.Get("Cookie")
	case r.Method == http.MethodDelete && r.URL.Path == LogoutPath+"/api":
		body, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, maxLogoutBody))
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))

		var in struct {
			Token string `json:"session_token"`
		}

		if err != nil || json.Unmarshal(body, &in) != nil {
			return ory.Session{}
		}

		token = in.Token
	}

	if token == "" && cookie == "" {
		return ory.Session{}
	}

	ctx, cancel := context.WithTimeout(r.Context(), logoutCheck)
	defer cancel()

	s, err := f.sessions.WhoAmI(ctx, token, cookie)
	if err != nil || s.Identity == nil {
		return ory.Session{}
	}

	return s
}

// loggedOut publishes LoggedOut once Kratos reports the session ended;
// a logout Kratos refused publishes nothing.
func (f *Flows) loggedOut(ctx context.Context, s ory.Session, start time.Time) {
	ctx, cancel := context.WithTimeout(ctx, logoutCheck)
	defer cancel()

	stored, err := f.sessions.GetSession(ctx, s.ID)

	switch {
	case err != nil:
		f.record(logoutPoint, start, "failed", err)
		f.Log().Ctx().Warn(ctx, "logout event not published: session not read", xlog.Err(err))

		return
	case stored.Active:
		f.record(logoutPoint, start, "refused", nil)

		return
	}

	ev := &kratoseventsv1.FlowEvent{
		IdentityId: s.Identity.ID, SchemaId: s.Identity.SchemaID, Method: "logout",
		Traits: events.Traits(s.Identity.Traits), Session: sessionEvent(s),
	}

	if err := f.logout.Publish(ctx, ev, event.Key(s.Identity.ID), event.ID("logout-"+s.ID)); err != nil {
		f.record(logoutPoint, start, "failed", err)
		f.Log().Ctx().Warn(ctx, "logout event not published", xlog.Err(err))

		return
	}

	f.record(logoutPoint, start, "published", nil)
}

// sessionEvent is s in an event: its id, authentication and last device.
func sessionEvent(s ory.Session) *kratoseventsv1.Session {
	out := &kratoseventsv1.Session{Id: s.ID, Aal: s.AuthenticatorAssuranceLevel}
	if s.AuthenticatedAt != nil {
		out.AuthenticatedAt = timestamppb.New(*s.AuthenticatedAt)
	}

	if len(s.Devices) > 0 {
		d := s.Devices[len(s.Devices)-1]
		out.IpAddress, out.UserAgent, out.Location = d.IPAddress, d.UserAgent, d.Location
	}

	return out
}

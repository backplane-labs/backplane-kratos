package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Authenticator finds a request's credential and verifies it: a bearer JWT
// with Tokens, a session token or Kratos's cookie with Sessions. Either may
// be absent: that credential is then refused.
type Authenticator struct {
	// Tokens verifies bearer JWTs; nil: refused.
	Tokens *Tokens
	// Sessions asks Kratos about session tokens and cookies; zero: refused.
	Sessions Sessions
	// CookieName is Kratos's session cookie; empty: ory_kratos_session.
	CookieName string
}

// DefaultCookie is Kratos's session cookie name.
const DefaultCookie = "ory_kratos_session"

// Authenticate verifies the credential the headers carry. A JWT bearer goes
// to Tokens; a non-JWT bearer, X-Session-Token or the session cookie to
// Sessions.
func (a Authenticator) Authenticate(ctx context.Context, h http.Header) (Auth, error) {
	return a.authenticate(ctx, h.Get("Authorization"), h.Get("X-Session-Token"), h.Get("Cookie"))
}

func (a Authenticator) authenticate(ctx context.Context, authorization, sessionToken, cookie string) (Auth, error) {
	if bearer, ok := strings.CutPrefix(authorization, "Bearer "); ok {
		bearer = strings.TrimSpace(bearer)
		if isJWT(bearer) {
			if a.Tokens == nil {
				return Auth{}, ErrNoCredential
			}

			return a.Tokens.Verify(ctx, bearer)
		}

		sessionToken = bearer
	}

	if a.Sessions.whoami == "" {
		return Auth{}, ErrNoCredential
	}

	c := Credential{Token: sessionToken}
	if c.Token == "" && hasCookie(cookie, a.cookieName()) {
		c.Cookie = cookie
	}

	return a.Sessions.Verify(ctx, c)
}

func (a Authenticator) cookieName() string {
	if a.CookieName != "" {
		return a.CookieName
	}

	return DefaultCookie
}

// isJWT: three base64url parts, two dots.
func isJWT(s string) bool { return strings.Count(s, ".") == jwtDots }

const jwtDots = 2

func hasCookie(header, name string) bool {
	for part := range strings.SplitSeq(header, ";") {
		if k, _, ok := strings.Cut(strings.TrimSpace(part), "="); ok && k == name {
			return true
		}
	}

	return false
}

type authKey struct{}

// WithAuth returns ctx carrying a.
func WithAuth(ctx context.Context, a Auth) context.Context {
	return context.WithValue(ctx, authKey{}, a)
}

// FromContext returns the Auth the middleware put into ctx.
func FromContext(ctx context.Context) (Auth, bool) {
	a, ok := ctx.Value(authKey{}).(Auth)

	return a, ok && !a.IsZero()
}

// Required lets through only requests a credential authenticates; the
// others get 401 (403 when the second factor is pending, 503 when the keys
// or Kratos are unreachable).
func (a Authenticator) Required(next http.Handler) http.Handler {
	return a.handler(next, true)
}

// Optional lets anonymous requests through without an Auth; a credential
// that fails still gets 401.
func (a Authenticator) Optional(next http.Handler) http.Handler {
	return a.handler(next, false)
}

func (a Authenticator) handler(next http.Handler, required bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, err := a.Authenticate(r.Context(), r.Header)
		if err != nil {
			if !required && errors.Is(err, ErrNoCredential) {
				next.ServeHTTP(w, r)

				return
			}

			refuse(w, err)

			return
		}

		next.ServeHTTP(w, r.WithContext(WithAuth(r.Context(), who)))
	})
}

// HTTPStatus is the status a refusal for err answers with.
func HTTPStatus(err error) int {
	switch {
	case errors.Is(err, ErrUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, ErrSecondFactor):
		return http.StatusForbidden
	default:
		return http.StatusUnauthorized
	}
}

func refuse(w http.ResponseWriter, err error) {
	code := HTTPStatus(err)
	if code == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
	}

	body, _ := json.Marshal(map[string]string{"error": err.Error()}) //nolint:errchkjson // a string map

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

// GRPCCode is the code a refusal for err answers with.
func GRPCCode(err error) codes.Code {
	switch {
	case errors.Is(err, ErrUnavailable):
		return codes.Unavailable
	case errors.Is(err, ErrSecondFactor):
		return codes.PermissionDenied
	default:
		return codes.Unauthenticated
	}
}

func (a Authenticator) fromMetadata(ctx context.Context, required bool) (context.Context, error) {
	incoming, _ := metadata.FromIncomingContext(ctx)
	first := func(k string) string {
		if v := incoming.Get(k); len(v) > 0 {
			return v[0]
		}

		return ""
	}

	cookies := strings.Join(incoming.Get("cookie"), "; ")

	who, err := a.authenticate(ctx, first("authorization"), first("x-session-token"), cookies)
	if err != nil {
		if !required && errors.Is(err, ErrNoCredential) {
			return ctx, nil
		}

		return ctx, status.Error(GRPCCode(err), err.Error())
	}

	return WithAuth(ctx, who), nil
}

// UnaryInterceptor authenticates every unary call (required: refuses
// anonymous calls too).
func (a Authenticator) UnaryInterceptor(required bool) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, next grpc.UnaryHandler) (any, error) {
		ctx, err := a.fromMetadata(ctx, required)
		if err != nil {
			return nil, err
		}

		return next(ctx, req)
	}
}

// StreamInterceptor authenticates every stream (required: refuses anonymous
// streams too).
func (a Authenticator) StreamInterceptor(required bool) grpc.StreamServerInterceptor {
	return func(srv any, stream grpc.ServerStream, _ *grpc.StreamServerInfo, next grpc.StreamHandler) error {
		ctx, err := a.fromMetadata(stream.Context(), required)
		if err != nil {
			return err
		}

		return next(srv, &authStream{ServerStream: stream, ctx: ctx})
	}
}

type authStream struct {
	grpc.ServerStream

	ctx context.Context //nolint:containedctx // the stream's context with its Auth
}

func (s *authStream) Context() context.Context { return s.ctx }

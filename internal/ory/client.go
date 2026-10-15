// Package ory is a small client of an Ory Kratos installation: the admin
// API (identities, sessions, recovery, courier messages) and the parts of
// the public API an operator needs (identity schemas, whoami). Payloads
// that Kratos owns the shape of (traits, metadata, credentials) stay JSON.
package ory

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// defaultTimeout of one request.
const defaultTimeout = 10 * time.Second

// maxBody bounds a response read from Kratos.
const maxBody = 16 << 20

// Client of one Kratos installation. It holds no state of its own:
// share it by value.
type Client struct {
	admin   *url.URL
	public  *url.URL
	headers map[string]string
	http    *http.Client
}

// Options of New.
type Options struct {
	// Admin and Public are the base URLs of the APIs.
	Admin, Public string
	// Headers go with every request (a proxy's authorization).
	Headers map[string]string
	// Timeout of one request; default 10s.
	Timeout time.Duration
	// Transport overrides the HTTP transport (tests).
	Transport http.RoundTripper
}

// New creates the client.
func New(o Options) (Client, error) {
	admin, err := parseBase(o.Admin)
	if err != nil {
		return Client{}, fmt.Errorf("kratos admin url: %w", err)
	}

	public, err := parseBase(o.Public)
	if err != nil {
		return Client{}, fmt.Errorf("kratos public url: %w", err)
	}

	timeout := o.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	return Client{
		admin: admin, public: public, headers: o.Headers,
		http: &http.Client{Timeout: timeout, Transport: o.Transport},
	}, nil
}

// ErrBaseURL: a base URL must be absolute http(s).
var ErrBaseURL = errors.New("must be an absolute http(s) URL")

func parseBase(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil {
		return nil, fmt.Errorf("%q: %w", raw, err)
	}

	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("%q: %w", raw, ErrBaseURL)
	}

	return u, nil
}

// AdminURL and PublicURL are the configured bases.
func (c Client) AdminURL() string  { return c.admin.String() }
func (c Client) PublicURL() string { return c.public.String() }

// Error is a failed Kratos call: the HTTP status and Kratos's own error
// body when it sent one.
type Error struct {
	Status  int
	ID      string // Kratos's error id, e.g. "self_service_flow_disabled"
	Message string
	Reason  string
}

func (e *Error) Error() string {
	msg := e.Message
	if e.Reason != "" {
		msg += ": " + e.Reason
	}

	if msg == "" {
		msg = http.StatusText(e.Status)
	}

	return fmt.Sprintf("kratos: %d %s", e.Status, msg)
}

// IsNotFound reports a 404 from Kratos.
func IsNotFound(err error) bool {
	var e *Error

	return errors.As(err, &e) && e.Status == http.StatusNotFound
}

// Temporary reports a failure worth retrying: Kratos unreachable, timed
// out, rate limited or failing on its side.
func Temporary(err error) bool {
	var e *Error
	if errors.As(err, &e) {
		return e.Status == http.StatusTooManyRequests || e.Status >= http.StatusInternalServerError
	}

	return err != nil
}

// request is one call: method, base (admin or public), path with query.
type request struct {
	method string
	base   *url.URL
	path   string
	query  url.Values
	body   any
	header http.Header
}

// do sends r and decodes a 2xx JSON answer into out (nil: discard); the
// response headers come back for pagination.
func (c Client) do(ctx context.Context, r request, out any) (http.Header, error) {
	u := *r.base
	u.Path = strings.TrimRight(u.Path, "/") + r.path
	u.RawQuery = r.query.Encode()

	var body io.Reader

	if r.body != nil {
		raw, err := json.Marshal(r.body)
		if err != nil {
			return nil, fmt.Errorf("kratos: encode %s %s: %w", r.method, r.path, err)
		}

		body = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), body)
	if err != nil {
		return nil, fmt.Errorf("kratos: %s %s: %w", r.method, r.path, err)
	}

	req.Header.Set("Accept", "application/json")

	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	for k, vs := range r.header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kratos: %s %s: %w", r.method, u.Redacted(), err)
	}
	defer res.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("kratos: %s %s: read: %w", r.method, r.path, err)
	}

	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, decodeError(res.StatusCode, raw)
	}

	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return nil, fmt.Errorf("kratos: %s %s: decode: %w", r.method, r.path, err)
		}
	}

	return res.Header, nil
}

func decodeError(status int, raw []byte) error {
	var body struct {
		Error struct {
			ID      string `json:"id"`
			Message string `json:"message"`
			Reason  string `json:"reason"`
		} `json:"error"`
	}

	e := &Error{Status: status}
	if json.Unmarshal(raw, &body) == nil {
		e.ID, e.Message, e.Reason = body.Error.ID, body.Error.Message, body.Error.Reason
	}

	return e
}

// Ready is Kratos's readiness (/health/ready on the admin API).
func (c Client) Ready(ctx context.Context) error {
	_, err := c.do(ctx, request{method: http.MethodGet, base: c.admin, path: "/health/ready"}, nil)

	return err
}

// Version of the installation (/version on the admin API).
func (c Client) Version(ctx context.Context) (string, error) {
	var out struct {
		Version string `json:"version"`
	}

	_, err := c.do(ctx, request{method: http.MethodGet, base: c.admin, path: "/version"}, &out)

	return out.Version, err
}

package flows

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

// TokenExchangePath is Kratos's session token exchange, the end of a
// native app's browser sign-in; the deployment routes it to this service
// instead of Kratos.
const TokenExchangePath = "/sessions/token-exchange"

// maxExchangeAnswer bounds Kratos's answer to an exchange (the session).
const maxExchangeAnswer = 1 << 20

// refusedExchange is the answer to a pair whose session is too old or
// ended, shaped as Kratos answers a pair it does not know.
const refusedExchange = `{"error":{"code":404,"status":"Not Found",` +
	`"reason":"the session token exchange code has expired or its session has ended",` +
	`"message":"The requested resource could not be found"}}`

// NativeFlowHeader names the app's flow on a session token exchange; it
// reaches SessionIssued unverified.
const NativeFlowHeader = "X-Kratos-Flow-Id"

// TokenExchange serves Kratos's session token exchange in front of Kratos
// at public. Kratos answers a code pair again and again, at any age, even
// for a session that has ended; this answers only for an active session
// authenticated within maxAge, else 404 as for an unknown pair, and only
// once SessionIssued admitted the session. Answers before the session
// exists (a polling app) pass unchanged. headers go with every request to
// Kratos.
func (f *Flows) TokenExchange(public *url.URL, headers map[string]string, maxAge time.Duration) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, iss := r.Context(), issuance{channel: ChannelNativeExchange, flowID: r.Header.Get(NativeFlowHeader)}

		proxy := kratosProxy(public, headers)
		proxy.ModifyResponse = func(res *http.Response) error {
			if res.StatusCode != http.StatusOK {
				return nil
			}

			raw, err := io.ReadAll(io.LimitReader(res.Body, maxExchangeAnswer))
			_ = res.Body.Close()

			a := answerOf{status: http.StatusOK, header: res.Header, raw: raw, replaced: true}

			if err != nil || !freshSession(raw, maxAge) {
				a.status, a.raw = http.StatusNotFound, []byte(refusedExchange)
				a.header.Set("Content-Type", "application/json")
			} else {
				f.admit(ctx, &a, iss, "")
			}

			a.write(res)

			return nil
		}
		proxy.ServeHTTP(w, r)
	})
}

// freshSession: the exchange answer's session is active and was
// authenticated within maxAge.
func freshSession(raw []byte, maxAge time.Duration) bool {
	var answer struct {
		Session struct {
			Active          bool       `json:"active"`
			AuthenticatedAt *time.Time `json:"authenticated_at"`
		} `json:"session"`
	}

	if json.Unmarshal(raw, &answer) != nil || !answer.Session.Active || answer.Session.AuthenticatedAt == nil {
		return false
	}

	return time.Since(*answer.Session.AuthenticatedAt) <= maxAge
}

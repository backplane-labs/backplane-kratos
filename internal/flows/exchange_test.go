package flows_test

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
)

// The exchange passes Kratos's answer for an active session authenticated
// within max_age, and answers 404 for an older or ended one; answers
// before the session exists pass as they are.
func TestTokenExchange(t *testing.T) {
	t.Parallel()

	answer := func(active bool, age time.Duration) string {
		return fmt.Sprintf(`{"session_token":"tok","session":{"id":"s-1","active":%t,"authenticated_at":%q}}`,
			active, time.Now().Add(-age).UTC().Format(time.RFC3339Nano))
	}

	for name, c := range map[string]struct {
		status   int
		body     string
		want     int
		passThru bool
	}{
		"fresh":            {status: http.StatusOK, body: answer(true, time.Second), want: http.StatusOK, passThru: true},
		"too old":          {status: http.StatusOK, body: answer(true, 10*time.Minute), want: http.StatusNotFound},
		"ended":            {status: http.StatusOK, body: answer(false, time.Second), want: http.StatusNotFound},
		"not a session":    {status: http.StatusOK, body: `{"session_token":"tok"}`, want: http.StatusNotFound},
		"not json":         {status: http.StatusOK, body: `tok`, want: http.StatusNotFound},
		"pending":          {status: http.StatusNotFound, body: `{"error":{"code":404}}`, want: http.StatusNotFound, passThru: true},
		"flow with errors": {status: http.StatusUnprocessableEntity, body: `{"ui":{}}`, want: http.StatusUnprocessableEntity, passThru: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			kratos := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != flows.TokenExchangePath || r.URL.Query().Get("init_code") != "i" {
					http.NotFound(w, r)

					return
				}

				w.WriteHeader(c.status)
				_, _ = w.Write([]byte(c.body))
			}))
			t.Cleanup(kratos.Close)

			public, err := url.Parse(kratos.URL)
			if err != nil {
				t.Fatal(err)
			}

			proxy := httptest.NewServer(flows.TokenExchange(public, nil, 5*time.Minute))
			t.Cleanup(proxy.Close)

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
				proxy.URL+flows.TokenExchangePath+"?init_code=i&return_to_code=r", http.NoBody)
			if err != nil {
				t.Fatal(err)
			}

			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer res.Body.Close()

			body, _ := io.ReadAll(res.Body)

			if res.StatusCode != c.want {
				t.Fatalf("status %d %s, want %d", res.StatusCode, body, c.want)
			}

			if c.passThru != (string(body) == c.body) {
				t.Fatalf("body %s", body)
			}

			if !c.passThru && (strings.Contains(string(body), `"session_token"`) || !strings.Contains(string(body), `"code":404`)) {
				t.Fatalf("refusal %s", body)
			}
		})
	}
}

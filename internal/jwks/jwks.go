// Package jwks serves the session tokens' public keys: services verify a
// token's signature with them (pkg/auth). Every replica serves the same
// keys, the settings are one.
package jwks

import (
	"encoding/json"
	"net/http"

	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// Path is where the keys are served.
const Path = "/.well-known/jwks.json"

// maxAge lets verifiers cache the set a minute: a new key reaches them
// sooner anyway, a token with an unknown kid makes them fetch again.
const maxAge = "public, max-age=60"

// Handler serves the public keys of settings.tokens.keys as a JWK set.
func Handler(settings config.Live[overlay.Settings]) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+Path, func(w http.ResponseWriter, _ *http.Request) {
		keys, err := overlay.PublicKeys(settings.Get().Tokens.Keys)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)

			return
		}

		body, err := json.Marshal(map[string]any{"keys": keys})
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", "application/jwk-set+json")
		w.Header().Set("Cache-Control", maxAge)
		_, _ = w.Write(body)
	})

	return mux
}

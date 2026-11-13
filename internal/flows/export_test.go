package flows

import (
	"net/http"

	"github.com/backplane-labs/backplane/pkg/backplane/config"

	"github.com/backplane-labs/backplane-kratos/internal/overlay"
)

// Proof and its purposes, for the tests.
type Proof = proof

const (
	PurposeHop    = purposeHop
	PurposeHeader = purposeHeader
)

// PurposeCookie is the purpose of state's OIDC flow cookie.
func PurposeCookie(state string) string { return purposeCookie + stateHash(state) }

// FlowCookieFor names the OIDC flow cookie of state.
func FlowCookieFor(state string) string { return flowCookie + stateHash(state) }

func (f *Flows) Seal(purpose string, p Proof) string { return f.seal(purpose, p) }

func (f *Flows) Open(purpose, sealed string) (Proof, bool) { return f.open(purpose, sealed) }

// Hop is the OIDC start hop alone.
func (f *Flows) Hop() http.Handler {
	return http.HandlerFunc(front{f: f, settings: config.LiveOf(overlay.Settings{})}.hop)
}

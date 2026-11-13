package flows

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
)

// Purposes of a proof: one signed for one cannot be used as another.
const (
	// purposeHeader: FlowHeader on a request to Kratos.
	purposeHeader = "flow-header"
	// purposeHop: the OIDC start hop's link.
	purposeHop = "oidc-hop"
	// purposeCookie (with the OIDC state's hash): the OIDC flow cookie.
	purposeCookie = "oidc-cookie:"
)

// proof is what the proxy vouches for: the flow a client submitted or
// started, until Exp.
type proof struct {
	// Kind is login, registration or recovery.
	Kind string `json:"k"`
	Flow string `json:"f"`
	// To is the provider URL the OIDC hop redirects to.
	To  string `json:"t,omitempty"`
	Exp int64  `json:"e"`
}

// seal signs p for purpose under the callbacks key: payload.mac, both
// base64url.
func (f *Flows) seal(purpose string, p proof) string {
	raw, err := json.Marshal(p)
	if err != nil {
		return ""
	}

	payload := base64.RawURLEncoding.EncodeToString(raw)

	return payload + "." + base64.RawURLEncoding.EncodeToString(f.mac(purpose, payload))
}

// open is the proof sealed for purpose, if its mac holds and it has not
// expired.
func (f *Flows) open(purpose, sealed string) (proof, bool) {
	payload, sum, ok := strings.Cut(sealed, ".")
	if !ok {
		return proof{}, false
	}

	mac, err := base64.RawURLEncoding.DecodeString(sum)
	if err != nil || !hmac.Equal(mac, f.mac(purpose, payload)) {
		return proof{}, false
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return proof{}, false
	}

	var p proof
	if json.Unmarshal(raw, &p) != nil || time.Now().Unix() >= p.Exp {
		return proof{}, false
	}

	return p, true
}

func (f *Flows) mac(purpose, payload string) []byte {
	m := hmac.New(sha256.New, []byte(f.key))
	m.Write([]byte("backplane-kratos proof\x00" + purpose + "\x00" + payload))

	return m.Sum(nil)
}

// stateHash names an OIDC state without revealing it.
func stateHash(state string) string {
	sum := sha256.Sum256([]byte(state))

	return hex.EncodeToString(sum[:12])
}

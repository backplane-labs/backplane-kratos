package flows

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// CredentialTypes are the credentials a settings flow changes, read with
// their configurations to tell a change from none.
func CredentialTypes() []string {
	return []string{"password", "totp", "webauthn", "passkey", "lookup_secret", typeOIDC, "code"}
}

// typeOIDC is the credential of the OIDC links, one identifier per provider.
const typeOIDC = "oidc"

// Changes of a credential.
const (
	ChangeAdded    = "added"
	ChangeRemoved  = "removed"
	ChangeReplaced = "replaced"
)

// credential is what a change is told by, never a secret: the identifiers,
// a digest of the configuration and, for a list of keys, their count.
type credential struct {
	Identifiers []string `json:"identifiers,omitempty"`
	Digest      string   `json:"digest"`
	Count       int      `json:"count,omitempty"`
}

// credentials are an identity's credentials by type; a type with neither an
// identifier nor a configuration is absent.
type credentials map[string]credential

// credentialsOf summarizes id's credentials (read with their configurations).
func credentialsOf(id ory.Identity) credentials {
	out := credentials{}

	for kind, c := range id.Credentials {
		cfg := bytes.TrimSpace(c.Config)
		empty := len(cfg) == 0 || string(cfg) == jsonNull || string(cfg) == "{}"

		if len(c.Identifiers) == 0 && empty {
			continue
		}

		var keys struct {
			Credentials []json.RawMessage `json:"credentials"`
		}

		_ = json.Unmarshal(cfg, &keys)

		sum := sha256.Sum256(cfg)
		ids := slices.Clone(c.Identifiers)
		slices.Sort(ids)

		out[kind] = credential{Identifiers: ids, Digest: hex.EncodeToString(sum[:]), Count: len(keys.Credentials)}
	}

	return out
}

// types are the credential types present, sorted.
func (c credentials) types() []string {
	out := make([]string, 0, len(c))
	for kind := range c {
		out = append(out, kind)
	}

	slices.Sort(out)

	return out
}

// diffCredentials is what turned before into after, by type: added,
// removed, replaced; per provider for oidc; for webauthn and passkey a key
// more is added, one fewer removed.
func diffCredentials(before, after credentials) []*kratoseventsv1.CredentialChange {
	kinds := append(before.types(), after.types()...)
	slices.Sort(kinds)
	kinds = slices.Compact(kinds)

	var out []*kratoseventsv1.CredentialChange

	for _, kind := range kinds {
		b, wasThere := before[kind]
		a, isThere := after[kind]

		switch {
		case kind == typeOIDC:
			out = append(out, diffProviders(b.Identifiers, a.Identifiers)...)
		case !wasThere:
			out = append(out, &kratoseventsv1.CredentialChange{Type: kind, Change: ChangeAdded})
		case !isThere:
			out = append(out, &kratoseventsv1.CredentialChange{Type: kind, Change: ChangeRemoved})
		case (kind == "webauthn" || kind == "passkey") && a.Count != b.Count:
			change := ChangeAdded
			if a.Count < b.Count {
				change = ChangeRemoved
			}

			out = append(out, &kratoseventsv1.CredentialChange{Type: kind, Change: change})
		case a.Digest != b.Digest || !slices.Equal(a.Identifiers, b.Identifiers):
			out = append(out, &kratoseventsv1.CredentialChange{Type: kind, Change: ChangeReplaced})
		}
	}

	return out
}

// diffProviders are the OIDC links added and removed, by provider: an
// identifier is <provider>:<subject>.
func diffProviders(before, after []string) []*kratoseventsv1.CredentialChange {
	var out []*kratoseventsv1.CredentialChange

	for _, id := range after {
		if !slices.Contains(before, id) {
			out = append(out, &kratoseventsv1.CredentialChange{Type: typeOIDC, Change: ChangeAdded, Provider: provider(id)})
		}
	}

	for _, id := range before {
		if !slices.Contains(after, id) {
			out = append(out, &kratoseventsv1.CredentialChange{Type: typeOIDC, Change: ChangeRemoved, Provider: provider(id)})
		}
	}

	return out
}

func provider(identifier string) string {
	p, _, _ := strings.Cut(identifier, ":")

	return p
}

// address is a verifiable address as a settings entry keeps it.
type address struct {
	Via   string `json:"via"`
	Value string `json:"value"`
}

func addressesOf(id ory.Identity) []address {
	out := make([]address, 0, len(id.VerifiableAddresses))
	for _, a := range id.VerifiableAddresses {
		out = append(out, address{Via: a.Via, Value: a.Value})
	}

	return out
}

// diffAddresses pairs, per channel, the addresses that went with the ones
// that came: an email changed is previous → current; one only removed or
// only added has the other side empty.
func diffAddresses(before, after []address) []*kratoseventsv1.AddressChange {
	vias := make([]string, 0, len(before)+len(after))
	for _, a := range slices.Concat(before, after) {
		vias = append(vias, a.Via)
	}

	slices.Sort(vias)
	vias = slices.Compact(vias)

	var out []*kratoseventsv1.AddressChange

	for _, via := range vias {
		gone, came := missing(before, after, via), missing(after, before, via)

		for i := range max(len(gone), len(came)) {
			change := &kratoseventsv1.AddressChange{Via: via}
			if i < len(gone) {
				change.Previous = gone[i]
			}

			if i < len(came) {
				change.Current = came[i]
			}

			out = append(out, change)
		}
	}

	return out
}

// missing are the values of via in from that to lacks.
func missing(from, to []address, via string) []string {
	var out []string

	for _, a := range from {
		if a.Via == via && !slices.ContainsFunc(to, func(b address) bool { return b == a }) {
			out = append(out, a.Value)
		}
	}

	return out
}

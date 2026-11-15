package scim

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

// metadataKey is the identity's metadata_admin key this service owns.
const metadataKey = "scim"

// Kinds of a pending event.
const (
	kindCreated = "created"
	kindUpdated = "updated"
	kindState   = "state"
)

// Reasons of a state change.
const (
	ReasonDeactivated = "deactivated"
	ReasonReactivated = "reactivated"
	ReasonDeleted     = "deleted"
)

// Pending is an event written with the change it reports, published after
// it and then cleared: the change and its notification commit together, and
// any later request of the IdP publishes what an earlier one could not.
type Pending struct {
	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`
	// ID is the event's id, fixed when the change is written, so publishing
	// it again is the same event.
	ID string `json:"id"`
}

// record is what the identity's metadata_admin holds for its directory.
type record struct {
	Directory string    `json:"directory"`
	User      User      `json:"user"`
	Pending   []Pending `json:"pending,omitempty"`
}

// stored is the directory record of an identity; false when the identity is
// no directory's.
func stored(id ory.Identity) (record, bool) {
	var meta map[string]json.RawMessage
	if json.Unmarshal(id.MetadataAdmin, &meta) != nil {
		return record{}, false
	}

	var r record
	if json.Unmarshal(meta[metadataKey], &r) != nil || r.Directory == "" || r.User == nil {
		return record{}, false
	}

	return r, true
}

// withRecord is the identity's metadata_admin with r under metadataKey,
// keeping every other key.
func withRecord(metadata json.RawMessage, r record) (json.RawMessage, error) {
	meta := map[string]json.RawMessage{}
	if len(metadata) > 0 && string(metadata) != "null" && json.Unmarshal(metadata, &meta) != nil {
		meta = map[string]json.RawMessage{}
	}

	raw, err := json.Marshal(r)
	if err != nil {
		return nil, fmt.Errorf("scim: record: %w", err)
	}

	meta[metadataKey] = raw

	out, err := json.Marshal(meta)
	if err != nil {
		return nil, fmt.Errorf("scim: metadata: %w", err)
	}

	return out, nil
}

// externalID is the identity's external id for a directory's userName:
// Kratos indexes it, so a userName filter is one lookup.
func externalID(dir, userName string) string {
	return dir + ":" + strings.ToLower(userName)
}

// credential is the OIDC credential identifier of a directory's user: what
// Kratos stores for <provider>:<subject>, the subject being the externalId.
func credential(provider, external string) string { return provider + ":" + external }

// state is Kratos's state for an active flag.
func state(active bool) string {
	if active {
		return "active"
	}

	return "inactive"
}

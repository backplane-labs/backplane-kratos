package scim_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

// kratos plays Kratos's admin API in memory: identities with their OIDC
// credentials, external ids, state and metadata, and the sessions deleted.
type kratos struct {
	mu         sync.Mutex
	identities map[string]ory.Identity
	next       int
	// sessionsDeleted counts DeleteIdentitySessions by identity.
	sessionsDeleted map[string]int
}

func newKratos() *kratos {
	return &kratos{identities: map[string]ory.Identity{}, sessionsDeleted: map[string]int{}}
}

func missing() error { return &ory.Error{Status: http.StatusNotFound} }

func (k *kratos) GetIdentity(_ context.Context, id string, _ ...string) (ory.Identity, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	i, ok := k.identities[id]
	if !ok {
		return ory.Identity{}, missing()
	}

	return i, nil
}

func (k *kratos) GetIdentityByExternalID(_ context.Context, ext string) (ory.Identity, error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	for _, i := range k.identities {
		if i.ExternalID == ext {
			return i, nil
		}
	}

	return ory.Identity{}, missing()
}

func (k *kratos) ListIdentities(_ context.Context, f ory.IdentityFilter) (ory.Page[ory.Identity], error) {
	k.mu.Lock()
	defer k.mu.Unlock()

	var out []ory.Identity

	for _, i := range k.identities {
		for _, c := range i.Credentials {
			if slices.Contains(c.Identifiers, f.CredentialsIdentifier) {
				out = append(out, i)
			}
		}
	}

	return ory.Page[ory.Identity]{Items: out}, nil
}

// body is the fields of Kratos's create and update bodies this plays.
type body struct {
	SchemaID       string          `json:"schema_id"`
	Traits         json.RawMessage `json:"traits"`
	MetadataPublic json.RawMessage `json:"metadata_public"`
	MetadataAdmin  json.RawMessage `json:"metadata_admin"`
	ExternalID     string          `json:"external_id"`
	State          string          `json:"state"`
	Credentials    struct {
		OIDC struct {
			Config struct {
				Providers []struct {
					Provider string `json:"provider"`
					Subject  string `json:"subject"`
				} `json:"providers"`
			} `json:"config"`
		} `json:"oidc"`
	} `json:"credentials"`
}

func (k *kratos) CreateIdentity(_ context.Context, raw json.RawMessage) (ory.Identity, error) {
	var b body
	if err := json.Unmarshal(raw, &b); err != nil {
		return ory.Identity{}, &ory.Error{Status: http.StatusBadRequest, Message: err.Error()}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	k.next++
	now := time.Now()
	id := ory.Identity{
		ID: fmt.Sprintf("id-%d", k.next), SchemaID: "default", Traits: b.Traits, MetadataPublic: b.MetadataPublic,
		MetadataAdmin: b.MetadataAdmin, ExternalID: b.ExternalID, State: b.State, CreatedAt: &now, UpdatedAt: &now,
		Credentials: map[string]ory.Credentials{},
	}

	for _, p := range b.Credentials.OIDC.Config.Providers {
		c := id.Credentials["oidc"]
		c.Type = "oidc"
		c.Identifiers = append(c.Identifiers, p.Provider+":"+p.Subject)
		id.Credentials["oidc"] = c
	}

	k.identities[id.ID] = id

	return id, nil
}

// signedIn is an identity a person created by signing in with OIDC.
func (k *kratos) signedIn(provider, subject string) string {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.next++
	id := fmt.Sprintf("id-%d", k.next)
	k.identities[id] = ory.Identity{
		ID: id, SchemaID: "default", State: "active", Traits: json.RawMessage(`{"email":"self@corp"}`),
		Credentials: map[string]ory.Credentials{"oidc": {Type: "oidc", Identifiers: []string{provider + ":" + subject}}},
	}

	return id
}

func (k *kratos) UpdateIdentity(_ context.Context, id string, raw json.RawMessage) (ory.Identity, error) {
	var b body
	if err := json.Unmarshal(raw, &b); err != nil {
		return ory.Identity{}, &ory.Error{Status: http.StatusBadRequest, Message: err.Error()}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	i, ok := k.identities[id]
	if !ok {
		return ory.Identity{}, missing()
	}

	now := time.Now()
	i.Traits, i.MetadataPublic, i.MetadataAdmin = b.Traits, b.MetadataPublic, b.MetadataAdmin
	i.ExternalID, i.State, i.UpdatedAt = b.ExternalID, b.State, &now
	k.identities[id] = i

	return i, nil
}

func (k *kratos) PatchIdentity(_ context.Context, id string, raw json.RawMessage) (ory.Identity, error) {
	var ops []struct {
		Path  string          `json:"path"`
		Value json.RawMessage `json:"value"`
	}

	if err := json.Unmarshal(raw, &ops); err != nil {
		return ory.Identity{}, &ory.Error{Status: http.StatusBadRequest, Message: err.Error()}
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	i, ok := k.identities[id]
	if !ok {
		return ory.Identity{}, missing()
	}

	for _, op := range ops {
		if op.Path == "/metadata_admin" {
			i.MetadataAdmin = op.Value
		}
	}

	k.identities[id] = i

	return i, nil
}

func (k *kratos) DeleteIdentity(_ context.Context, id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.identities[id]; !ok {
		return missing()
	}

	delete(k.identities, id)

	return nil
}

func (k *kratos) DeleteIdentitySessions(_ context.Context, id string) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	k.sessionsDeleted[id]++

	return nil
}

func (k *kratos) identity(id string) ory.Identity {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.identities[id]
}

func (k *kratos) deletedSessions(id string) int {
	k.mu.Lock()
	defer k.mu.Unlock()

	return k.sessionsDeleted[id]
}

// Package scim is the SCIM 2.0 service provider (RFC 7643, RFC 7644) a
// corporate IdP provisions its people through: each directory's users are
// Kratos identities pre-linked to the directory's OIDC provider, created,
// updated, deactivated, reactivated and deleted by the IdP.
package scim

import (
	"errors"
	"fmt"
	"regexp"
)

// OnDelete is what a SCIM DELETE does to the identity.
type OnDelete string

const (
	// Deactivate keeps the identity, inactive and readable (the default).
	Deactivate OnDelete = "deactivate"
	// Delete deletes the identity.
	Delete OnDelete = "delete"
)

// Directory is one IdP provisioning its people.
type Directory struct {
	// ID is the path segment of the directory's SCIM base URL.
	ID string `json:"id" schemapb:"description=Path segment of the SCIM base URL /scim/v2/<id>/"`
	// Provider is the Kratos OIDC provider the directory's people sign in
	// with: an identity's OIDC credential is <provider>:<externalId>.
	Provider string `json:"provider" schemapb:"description=Kratos OIDC provider id the directory's people sign in with"`
	// Mapper is Jsonnet turning the SCIM user (std.extVar('user')) into
	// {traits, metadata_public}; empty: the default mapping.
	Mapper string `json:"mapper,omitempty" schemapb:"description=Jsonnet: SCIM user -> {traits, metadata_public}"`
	// SchemaID is the identity schema of the identities it creates.
	SchemaID string `json:"schema_id,omitempty" schemapb:"description=Identity schema of created identities (empty: default)"`
	// OnDelete is what a SCIM DELETE does.
	OnDelete OnDelete `json:"on_delete,omitempty" schemapb:"enum=deactivate,delete;description=What a SCIM DELETE does"`
}

// Deletes reports whether a SCIM DELETE deletes the identity.
func (d Directory) Deletes() bool { return d.OnDelete == Delete }

// pathSafe is what a directory id may be: it is a URL path segment and the
// prefix of every external id the directory owns.
var pathSafe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

var (
	// ErrDirectoryID: a directory id is not a lowercase path segment.
	ErrDirectoryID = errors.New("scim: directory id must be lowercase letters, digits, '-' or '_'")
	// ErrDuplicateDirectory: two directories share an id.
	ErrDuplicateDirectory = errors.New("scim: directory ids must be unique")
	// ErrNoProvider: a directory names no OIDC provider.
	ErrNoProvider = errors.New("scim: a directory needs its OIDC provider")
	// ErrOnDelete: on_delete is neither deactivate nor delete.
	ErrOnDelete = errors.New("scim: on_delete must be deactivate or delete")
)

// Validate checks the directories of a configuration.
func Validate(dirs []Directory) error {
	seen := map[string]bool{}

	for _, d := range dirs {
		switch {
		case !pathSafe.MatchString(d.ID):
			return fmt.Errorf("%w: %q", ErrDirectoryID, d.ID)
		case seen[d.ID]:
			return fmt.Errorf("%w: %q", ErrDuplicateDirectory, d.ID)
		case d.Provider == "":
			return fmt.Errorf("%w: %q", ErrNoProvider, d.ID)
		case d.OnDelete != "" && d.OnDelete != Deactivate && d.OnDelete != Delete:
			return fmt.Errorf("%w: %q", ErrOnDelete, d.OnDelete)
		}

		seen[d.ID] = true
	}

	return nil
}

// find is the directory with that id.
func find(dirs []Directory, id string) (Directory, bool) {
	for _, d := range dirs {
		if d.ID == id {
			return d, true
		}
	}

	return Directory{}, false
}

package scim

import (
	"encoding/json"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

// Record is the identity's directory record as metadata_admin holds it.
type Record = record

// Stored is stored.
func Stored(id ory.Identity) (Record, bool) { return stored(id) }

// WithRecord is withRecord.
func WithRecord(metadata json.RawMessage, r Record) (json.RawMessage, error) {
	return withRecord(metadata, r)
}

// KratosFailure is kratosFailure.
func KratosFailure(err error) error { return kratosFailure(err) }

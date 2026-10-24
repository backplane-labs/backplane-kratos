// Package events builds the payloads of backplane-kratos's events, whose
// contract is proto/kratos/events/v1.
package events

import (
	"encoding/json"

	"google.golang.org/protobuf/types/known/structpb"
)

// Traits are an identity's traits, or a flow's transient payload, as Kratos
// gives them (a JSON object); nil when there are none or they are not an
// object.
func Traits(raw json.RawMessage) *structpb.Struct {
	if len(raw) == 0 {
		return nil
	}

	var out structpb.Struct
	if err := out.UnmarshalJSON(raw); err != nil {
		return nil
	}

	return &out
}

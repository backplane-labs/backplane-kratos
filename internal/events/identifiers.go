package events

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"

	kratoseventsv1 "github.com/backplane-labs/backplane-kratos/proto/kratos/events/v1"
)

// extensionKey is Kratos's extension keyword of an identity schema.
const extensionKey = "ory.sh/kratos"

// Kinds of identifiers.
const (
	kindEmail    = "email"
	kindTel      = "tel"
	kindUsername = "username"
)

// schemaNode is the part of a JSON Schema identifiers are read from.
type schemaNode struct {
	Format     string
	Properties map[string]schemaNode
	Kratos     struct {
		Credentials map[string]struct {
			Identifier bool   `json:"identifier"`
			Via        string `json:"via"`
		} `json:"credentials"`
	}
}

// UnmarshalJSON reads the node, Kratos's extension under its own key.
func (n *schemaNode) UnmarshalJSON(raw []byte) error {
	var node struct {
		Format     string                `json:"format"`
		Properties map[string]schemaNode `json:"properties"`
	}

	var keywords map[string]json.RawMessage

	if err := json.Unmarshal(raw, &node); err != nil {
		return fmt.Errorf("schema: %w", err)
	}

	if err := json.Unmarshal(raw, &keywords); err != nil {
		return fmt.Errorf("schema: %w", err)
	}

	n.Format, n.Properties = node.Format, node.Properties

	if ext, ok := keywords[extensionKey]; ok {
		if err := json.Unmarshal(ext, &n.Kratos); err != nil {
			return fmt.Errorf("schema %s: %w", extensionKey, err)
		}
	}

	return nil
}

// Identifiers are the traits of the identity schemas that an enabled
// first factor (first) takes as the identifier, merged across schemas by
// trait and kind, sorted by trait. A schema that does not parse adds
// nothing.
func Identifiers(schemas []json.RawMessage, first []string) []*kratoseventsv1.LoginIdentifier {
	type key struct{ trait, kind string }

	// The credentials whose schema extension marks a trait as the
	// identifier, in the order the section lists them.
	identifierMethods := []string{"password", "code", "webauthn"}
	found := map[key]map[string]bool{}

	var walk func(path string, n schemaNode)

	walk = func(path string, n schemaNode) {
		for method, c := range n.Kratos.Credentials {
			if c.Identifier && slices.Contains(identifierMethods, method) && slices.Contains(first, method) {
				k := key{path, kindOf(n.Format, c.Via)}
				if found[k] == nil {
					found[k] = map[string]bool{}
				}

				found[k][method] = true
			}
		}

		for name, child := range n.Properties {
			walk(path+"."+name, child)
		}
	}

	for _, raw := range schemas {
		var root schemaNode
		if json.Unmarshal(raw, &root) != nil {
			continue
		}

		if traits, ok := root.Properties["traits"]; ok {
			walk("traits", traits)
		}
	}

	out := make([]*kratoseventsv1.LoginIdentifier, 0, len(found))

	for k, methods := range found {
		id := &kratoseventsv1.LoginIdentifier{Trait: k.trait, Kind: k.kind}

		for _, m := range identifierMethods {
			if methods[m] {
				id.Methods = append(id.Methods, m)
			}
		}

		out = append(out, id)
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].GetTrait() != out[j].GetTrait() {
			return out[i].GetTrait() < out[j].GetTrait()
		}

		return out[i].GetKind() < out[j].GetKind()
	})

	return out
}

// kindOf is the kind of an identifier: its format, else where its code
// goes.
func kindOf(format, via string) string {
	switch {
	case format == kindEmail || (format == "" && via == kindEmail):
		return kindEmail
	case format == kindTel || (format == "" && via == "sms"):
		return kindTel
	default:
		return kindUsername
	}
}

package scim

import (
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
)

// Operation is one PATCH operation (RFC 7644 3.5.2), op lowercased.
type Operation struct {
	Op    string
	Path  string
	Value json.RawMessage
}

const (
	opAdd     = "add"
	opReplace = "replace"
	opRemove  = "remove"
)

// valuePath is `attr[sub eq "value"]` with an optional `.sub` after it: the
// only filter form IdPs put in a PATCH path (emails[type eq "work"].value).
var valuePath = regexp.MustCompile(
	`^([A-Za-z][\w$-]*)\[\s*([A-Za-z][\w$-]*)\s+eq\s+"([^"]*)"\s*\](?:\.([A-Za-z][\w$-]*))?$`)

func invalidPath(path string) *Error {
	return refuse(http.StatusBadRequest, "invalidPath", "unsupported path "+path)
}

// ParsePatch reads a PatchOp body. Operations is looked up in any case, and
// op is lowercased: Entra ID sends "Replace".
func ParsePatch(body []byte) ([]Operation, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal(body, &doc) != nil {
		return nil, refuse(http.StatusBadRequest, "invalidSyntax", "the body is not a PatchOp object")
	}

	var raw []map[string]json.RawMessage
	if json.Unmarshal(doc[keyOf(doc, "Operations")], &raw) != nil || len(raw) == 0 {
		return nil, refuse(http.StatusBadRequest, "invalidSyntax", "PatchOp needs Operations")
	}

	ops := make([]Operation, 0, len(raw))

	for _, o := range raw {
		var verb, path string

		_ = json.Unmarshal(o[keyOf(o, "op")], &verb)
		_ = json.Unmarshal(o[keyOf(o, "path")], &path)

		verb = strings.ToLower(verb)
		if verb != opAdd && verb != opReplace && verb != opRemove {
			return nil, refuse(http.StatusBadRequest, "invalidSyntax", "unsupported op "+verb)
		}

		ops = append(ops, Operation{Op: verb, Path: strings.TrimSpace(path), Value: o[keyOf(o, "value")]})
	}

	return ops, nil
}

// Apply applies ops to u in order and normalizes the result.
func (u User) Apply(ops []Operation) error {
	for _, o := range ops {
		if err := u.apply(o); err != nil {
			return err
		}
	}

	return u.normalize()
}

func (u User) apply(o Operation) error {
	if o.Path != "" {
		return u.applyPath(o.Op, o.Path, o.Value)
	}

	if o.Op == opRemove {
		return refuse(http.StatusBadRequest, "noTarget", "remove needs a path")
	}

	// A path-less add or replace carries an object: one operation per key
	// (Okta: {"active": false}; Entra ID: dotted keys and extension URNs).
	var fields map[string]json.RawMessage
	if json.Unmarshal(o.Value, &fields) != nil {
		return invalidValue("a path-less " + o.Op + " needs an object value")
	}

	for k, v := range fields {
		if err := u.applyPath(o.Op, k, v); err != nil {
			return err
		}
	}

	return nil
}

func (u User) applyPath(verb, path string, value json.RawMessage) error {
	if m := valuePath.FindStringSubmatch(path); m != nil {
		return u.applyValuePath(verb, m[1], m[2], m[3], m[4], value)
	}

	top, rest := splitPath(path)
	if top == "" {
		return invalidPath(path)
	}

	key := keyOf(u, top)
	if key == "id" || key == "meta" {
		return refuse(http.StatusBadRequest, "mutability", key+" is read-only")
	}

	if key == "password" {
		return nil
	}

	if verb == opRemove {
		if len(rest) == 0 {
			delete(u, key)

			return nil
		}

		out, err := removeIn(u[key], rest)
		if err != nil {
			return invalidPath(path)
		}

		u[key] = out

		return nil
	}

	if len(rest) == 0 {
		u[key] = merged(verb, u[key], value)

		return nil
	}

	out, err := setIn(u[key], rest, value)
	if err != nil {
		return invalidPath(path)
	}

	u[key] = out

	return nil
}

// splitPath turns a path into the top-level attribute and the sub-attributes
// below it: "name.givenName", an extension "urn:…:User:manager.value", or a
// core attribute written with its schema "urn:…:core:2.0:User:userName".
func splitPath(path string) (string, []string) {
	if strings.HasPrefix(strings.ToLower(path), "urn:") {
		i := strings.LastIndex(path, ":")
		urn, attr := path[:i], path[i+1:]

		if strings.EqualFold(urn, UserSchema) {
			return splitPath(attr)
		}

		if attr == "" {
			return urn, nil
		}

		return urn, strings.Split(attr, ".")
	}

	parts := strings.Split(path, ".")

	return parts[0], parts[1:]
}

// merged is value set by verb over old: add appends to a multi-valued
// attribute, anything else replaces it.
func merged(verb string, old, value json.RawMessage) json.RawMessage {
	if verb != opAdd {
		return value
	}

	var have, more []json.RawMessage
	if json.Unmarshal(old, &have) != nil || json.Unmarshal(value, &more) != nil {
		return value
	}

	out, err := json.Marshal(append(have, more...))
	if err != nil {
		return value
	}

	return out
}

// setIn sets value at path inside the object raw (created when absent).
func setIn(raw json.RawMessage, path []string, value json.RawMessage) (json.RawMessage, error) {
	obj := map[string]json.RawMessage{}
	if len(raw) > 0 && string(raw) != jsonNull {
		if json.Unmarshal(raw, &obj) != nil {
			return nil, errNotObject
		}
	}

	key := keyOf(obj, path[0])

	if len(path) == 1 {
		obj[key] = value
	} else {
		out, err := setIn(obj[key], path[1:], value)
		if err != nil {
			return nil, err
		}

		obj[key] = out
	}

	return marshal(obj)
}

// removeIn deletes path inside the object raw.
func removeIn(raw json.RawMessage, path []string) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) != nil {
		return nil, errNotObject
	}

	key := keyOf(obj, path[0])

	if len(path) == 1 {
		delete(obj, key)
	} else {
		out, err := removeIn(obj[key], path[1:])
		if err != nil {
			return nil, err
		}

		obj[key] = out
	}

	return marshal(obj)
}

// applyValuePath applies op to the elements of the multi-valued attr whose
// field equals want: emails[type eq "work"].value.
func (u User) applyValuePath(verb, attr, field, want, sub string, value json.RawMessage) error {
	key := keyOf(u, attr)

	var elems []map[string]json.RawMessage
	if raw, ok := u[key]; ok && json.Unmarshal(raw, &elems) != nil {
		return invalidPath(attr)
	}

	matched := false
	kept := elems[:0]

	for _, e := range elems {
		var got string

		_ = json.Unmarshal(e[keyOf(e, field)], &got)

		if !strings.EqualFold(got, want) {
			kept = append(kept, e)

			continue
		}

		matched = true

		switch {
		case verb == opRemove && sub == "":
			continue
		case verb == opRemove:
			delete(e, keyOf(e, sub))
		default:
			if err := setElement(e, sub, value); err != nil {
				return err
			}
		}

		kept = append(kept, e)
	}

	if !matched && verb != opRemove {
		e := map[string]json.RawMessage{field: quote(want)}
		if err := setElement(e, sub, value); err != nil {
			return err
		}

		kept = append(kept, e)
	}

	out, err := json.Marshal(kept)
	if err != nil {
		return invalidPath(attr)
	}

	u[key] = out

	return nil
}

// setElement sets sub of e to value, or merges an object value into e when
// there is no sub.
func setElement(e map[string]json.RawMessage, sub string, value json.RawMessage) error {
	if sub != "" {
		e[keyOf(e, sub)] = value

		return nil
	}

	var fields map[string]json.RawMessage
	if json.Unmarshal(value, &fields) != nil {
		return invalidValue("a filtered path without a sub-attribute needs an object value")
	}

	for k, v := range fields {
		e[keyOf(e, k)] = v
	}

	return nil
}

// keyOf is the key of m equal to name ignoring case (SCIM attribute names
// are case-insensitive), or name when m has none.
func keyOf[V any](m map[string]V, name string) string {
	if _, ok := m[name]; ok {
		return name
	}

	for k := range m {
		if strings.EqualFold(k, name) {
			return k
		}
	}

	return name
}

// errNotObject: a path goes through a value that is not an object.
var errNotObject = errors.New("scim: not an object")

// marshal encodes a decoded object back; it cannot fail for JSON it decoded.
func marshal(obj map[string]json.RawMessage) (json.RawMessage, error) {
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, errNotObject
	}

	return out, nil
}

func quote(s string) json.RawMessage {
	out, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`""`)
	}

	return out
}

package scim

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// UserSchema is the SCIM core user schema URN.
const UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"

// User is a SCIM user as the IdP sent it: top-level attributes with their
// JSON. Attributes this service does not model (title, extensions) are kept
// as they came, so a GET returns what the IdP last wrote; id and meta are the
// service's, a password is never kept.
type User map[string]json.RawMessage

// jsonNull is JSON's null.
const jsonNull = "null"

// Error is a request this service refuses: a SCIM error with its HTTP
// status and scimType (RFC 7644 3.12).
type Error struct {
	Status int
	Type   string
	Detail string
}

func (r *Error) Error() string { return "scim: " + r.Detail }

func refuse(status int, scimType, detail string) *Error {
	return &Error{Status: status, Type: scimType, Detail: detail}
}

func invalidValue(detail string) *Error {
	return refuse(http.StatusBadRequest, "invalidValue", detail)
}

// ParseUser reads a POST or PUT body: an object with a non-empty userName.
func ParseUser(body []byte) (User, error) {
	var u User
	if err := json.Unmarshal(body, &u); err != nil || u == nil {
		return nil, refuse(http.StatusBadRequest, "invalidSyntax", "the body is not a SCIM user object")
	}

	// id and meta are the service's; a password is dropped unread (Okta sends
	// a placeholder). Attribute names are case-insensitive.
	for k := range u {
		if serverOwned(k) {
			delete(u, k)
		}
	}

	if err := u.normalize(); err != nil {
		return nil, err
	}

	return u, nil
}

// serverOwned reports the attributes the IdP never sets, in any case: id and
// meta are the service's, a password is never kept.
func serverOwned(name string) bool {
	return strings.EqualFold(name, "id") || strings.EqualFold(name, "meta") || strings.EqualFold(name, "password")
}

// normalize checks userName and turns active into a JSON boolean (true when
// absent).
func (u User) normalize() error {
	if name, _ := u.String("userName"); name == "" {
		return invalidValue("userName is required")
	}

	active := true

	if raw, ok := u["active"]; ok {
		b, err := boolValue(raw)
		if err != nil {
			return err
		}

		active = b
	}

	u.setBool("active", active)

	return nil
}

// String is a string attribute; false when absent or not a string.
func (u User) String(name string) (string, bool) {
	raw, ok := u[name]
	if !ok {
		return "", false
	}

	var s string
	if json.Unmarshal(raw, &s) != nil {
		return "", false
	}

	return s, true
}

// Active is the active attribute (normalized to a boolean).
func (u User) Active() bool {
	b, err := boolValue(u["active"])

	return err == nil && b
}

func (u User) setBool(name string, v bool) {
	u[name] = json.RawMessage(map[bool]string{true: "true", false: "false"}[v])
}

// Email is the user's primary address: the one marked primary, else the work
// one, else the first; empty when there is none.
func (u User) Email() string {
	var emails []struct {
		Value   string `json:"value"`
		Type    string `json:"type"`
		Primary bool   `json:"primary"`
	}

	if json.Unmarshal(u["emails"], &emails) != nil || len(emails) == 0 {
		return ""
	}

	for _, e := range emails {
		if e.Primary {
			return e.Value
		}
	}

	for _, e := range emails {
		if strings.EqualFold(e.Type, "work") {
			return e.Value
		}
	}

	return emails[0].Value
}

// boolValue reads a SCIM boolean: true/false, or the strings Entra ID sends
// ("True", "False", in any case).
func boolValue(raw json.RawMessage) (bool, error) {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b, nil
	}

	var s string
	if json.Unmarshal(raw, &s) == nil {
		switch strings.ToLower(s) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}

	return false, invalidValue("active must be a boolean")
}

// Equal reports whether two users hold the same attributes.
func (u User) Equal(other User) bool {
	if len(u) != len(other) {
		return false
	}

	for k, v := range u {
		w, ok := other[k]
		if !ok || !jsonEqual(v, w) {
			return false
		}
	}

	return true
}

// jsonEqual compares two JSON values by their compact form.
func jsonEqual(a, b json.RawMessage) bool {
	var ca, cb bytes.Buffer
	if json.Compact(&ca, a) != nil || json.Compact(&cb, b) != nil {
		return bytes.Equal(a, b)
	}

	return bytes.Equal(ca.Bytes(), cb.Bytes())
}

// asError is err's Error, if it is one.
func asError(err error) (*Error, bool) {
	var r *Error

	ok := errors.As(err, &r)

	return r, ok
}

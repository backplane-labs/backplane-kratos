package scim

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/go-jsonnet"
)

// Mapped is what an identity takes from a SCIM user.
type Mapped struct {
	Traits         json.RawMessage
	MetadataPublic json.RawMessage
}

// Map turns u into an identity's traits and public metadata with the
// directory's Jsonnet mapper (std.extVar('user') is the SCIM user); without
// one, the traits are {email} from the primary e-mail, else userName.
func (d Directory) Map(u User) (Mapped, error) {
	if d.Mapper == "" {
		email := u.Email()
		if email == "" {
			email, _ = u.String("userName")
		}

		traits, err := json.Marshal(map[string]string{"email": email})
		if err != nil {
			return Mapped{}, fmt.Errorf("scim: traits: %w", err)
		}

		return Mapped{Traits: traits}, nil
	}

	user, err := json.Marshal(u)
	if err != nil {
		return Mapped{}, fmt.Errorf("scim: user: %w", err)
	}

	vm := jsonnet.MakeVM()
	vm.ExtCode("user", string(user))

	out, err := vm.EvaluateAnonymousSnippet("mapper.jsonnet", d.Mapper)
	if err != nil {
		return Mapped{}, misconfigured("the directory's mapper failed: " + err.Error())
	}

	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(out), &doc) != nil {
		return Mapped{}, misconfigured("the directory's mapper must return an object")
	}

	var traits map[string]json.RawMessage
	if json.Unmarshal(doc["traits"], &traits) != nil || traits == nil {
		return Mapped{}, misconfigured("the directory's mapper must return traits as an object")
	}

	m := Mapped{Traits: doc["traits"]}
	if raw, ok := doc["metadata_public"]; ok && string(raw) != jsonNull {
		m.MetadataPublic = raw
	}

	return m, nil
}

// misconfigured is a failure of the operator's configuration: a 500, so the
// IdP retries until the mapper is fixed.
func misconfigured(detail string) *Error { return refuse(http.StatusInternalServerError, "", detail) }

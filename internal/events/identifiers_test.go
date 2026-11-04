package events_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/events"
)

// schema is an identity schema with the traits' properties.
func schema(properties string) json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"traits":{"type":"object","properties":{` + properties + `}}}}`)
}

const (
	emailTrait = `"email":{"type":"string","format":"email","ory.sh/kratos":{"credentials":{` +
		`"password":{"identifier":true},"code":{"identifier":true,"via":"email"},"passkey":{"display_name":true}},` +
		`"verification":{"via":"email"}}}`
	phoneTrait = `"phone":{"type":"string","format":"tel","ory.sh/kratos":{"credentials":{"code":{"identifier":true,"via":"sms"}}}}`
	loginTrait = `"name":{"type":"object","properties":{"login":{"type":"string","ory.sh/kratos":{"credentials":{` +
		`"password":{"identifier":true},"webauthn":{"identifier":true}}}}}}`
)

func render(ids []string) string { return strings.Join(ids, ";") }

// Identifiers are the traits enabled first factors take, by schema.
func TestIdentifiers(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		schemas []json.RawMessage
		first   []string
		want    string
	}{
		{
			"email and phone",
			[]json.RawMessage{schema(emailTrait + "," + phoneTrait)},
			[]string{"password", "code"},
			"traits.email email password,code;traits.phone tel code",
		},
		{
			"code off: no phone",
			[]json.RawMessage{schema(emailTrait + "," + phoneTrait)},
			[]string{"password"},
			"traits.email email password",
		},
		{
			"nested username",
			[]json.RawMessage{schema(loginTrait)},
			[]string{"password", "webauthn", "passkey"},
			"traits.name.login username password,webauthn",
		},
		{
			"merged across schemas",
			[]json.RawMessage{schema(emailTrait), schema(emailTrait + "," + phoneTrait)},
			[]string{"code"},
			"traits.email email code;traits.phone tel code",
		},
		{
			"via without format",
			[]json.RawMessage{schema(`"p":{"type":"string","ory.sh/kratos":{"credentials":{"code":{"identifier":true,"via":"sms"}}}}`)},
			[]string{"code"},
			"traits.p tel code",
		},
		{
			"not an identifier",
			[]json.RawMessage{schema(`"x":{"type":"string","ory.sh/kratos":{"credentials":{"password":{"identifier":false}}}}`)},
			[]string{"password"},
			"",
		},
		{"no traits", []json.RawMessage{json.RawMessage(`{"type":"object"}`)}, []string{"password"}, ""},
		{"bad schema skipped", []json.RawMessage{json.RawMessage(`{`), schema(phoneTrait)}, []string{"code"}, "traits.phone tel code"},
		{"none", nil, []string{"password"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := events.Identifiers(tc.schemas, tc.first)

			out := make([]string, 0, len(got))
			for _, id := range got {
				out = append(out, fmt.Sprintf("%s %s %s", id.GetTrait(), id.GetKind(), strings.Join(id.GetMethods(), ",")))
			}

			if render(out) != tc.want {
				t.Fatalf("got %q, want %q", render(out), tc.want)
			}
		})
	}
}

func BenchmarkIdentifiers(b *testing.B) {
	schemas := []json.RawMessage{schema(emailTrait + "," + phoneTrait + "," + loginTrait)}
	first := []string{"password", "code", "webauthn"}

	for b.Loop() {
		events.Identifiers(schemas, first)
	}
}

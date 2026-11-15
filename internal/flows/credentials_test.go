package flows_test

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/flows"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

func identityWith(creds map[string]ory.Credentials, addresses ...ory.VerifiableAddress) ory.Identity {
	return ory.Identity{ID: "i", Credentials: creds, VerifiableAddresses: addresses}
}

func TestDiff(t *testing.T) {
	t.Parallel()

	keys := func(n int) string {
		list := make([]json.RawMessage, n)
		for i := range list {
			list[i] = json.RawMessage(`{"id":"` + string(rune('a'+i)) + `"}`)
		}

		raw, err := json.Marshal(struct {
			Credentials []json.RawMessage `json:"credentials"`
		}{list})
		if err != nil {
			t.Fatal(err)
		}

		return string(raw)
	}

	tests := []struct {
		name          string
		before, after map[string]ory.Credentials
		want          []string
	}{
		{
			name: "nothing", before: map[string]ory.Credentials{"password": credential("password", `{"h":1}`)},
			after: map[string]ory.Credentials{"password": credential("password", `{"h":1}`)},
		},
		{
			name: "password set", after: map[string]ory.Credentials{"password": credential("password", `{"h":1}`)},
			want: []string{"password:added:"},
		},
		{
			name: "password changed", before: map[string]ory.Credentials{"password": credential("password", `{"h":1}`)},
			after: map[string]ory.Credentials{"password": credential("password", `{"h":2}`)}, want: []string{"password:replaced:"},
		},
		{
			name: "backup codes regenerated", before: map[string]ory.Credentials{"lookup_secret": credential("lookup_secret", `{"c":[1]}`)},
			after: map[string]ory.Credentials{"lookup_secret": credential("lookup_secret", `{"c":[2]}`)},
			want:  []string{"lookup_secret:replaced:"},
		},
		{name: "two-step off", before: map[string]ory.Credentials{
			"totp": credential("totp", `{"u":1}`), "lookup_secret": credential("lookup_secret", `{"c":[1]}`),
		}, want: []string{"lookup_secret:removed:", "totp:removed:"}},
		{name: "an empty credential is none", before: map[string]ory.Credentials{"totp": credential("totp", `{}`)}},
		{
			name: "a key added", before: map[string]ory.Credentials{"webauthn": credential("webauthn", keys(1))},
			after: map[string]ory.Credentials{"webauthn": credential("webauthn", keys(2))}, want: []string{"webauthn:added:"},
		},
		{
			name: "a passkey removed", before: map[string]ory.Credentials{"passkey": credential("passkey", keys(2))},
			after: map[string]ory.Credentials{"passkey": credential("passkey", keys(1))}, want: []string{"passkey:removed:"},
		},
		{
			name: "oidc linked and unlinked", before: map[string]ory.Credentials{"oidc": credential("oidc", `{}`, "google:1")},
			after: map[string]ory.Credentials{"oidc": credential("oidc", `{}`, "apple:2")},
			want:  []string{"oidc:added:apple", "oidc:removed:google"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := []string{}
			for _, c := range flows.DiffCredentials(identityWith(tc.before), identityWith(tc.after)) {
				got = append(got, c.GetType()+":"+c.GetChange()+":"+c.GetProvider())
			}

			if !slices.Equal(got, append([]string{}, tc.want...)) {
				t.Fatalf("changes %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDiffAddresses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		before, after []ory.VerifiableAddress
		want          []string
	}{
		{name: "same", before: []ory.VerifiableAddress{address("email", "a")}, after: []ory.VerifiableAddress{address("email", "a")}},
		{
			name: "changed", before: []ory.VerifiableAddress{address("email", "a")}, after: []ory.VerifiableAddress{address("email", "b")},
			want: []string{"email:a>b"},
		},
		{name: "phone added", after: []ory.VerifiableAddress{address("sms", "+1")}, want: []string{"sms:>+1"}},
		{name: "email removed", before: []ory.VerifiableAddress{address("email", "a")}, want: []string{"email:a>"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := []string{}
			for _, a := range flows.DiffAddresses(identityWith(nil, tc.before...), identityWith(nil, tc.after...)) {
				got = append(got, a.GetVia()+":"+a.GetPrevious()+">"+a.GetCurrent())
			}

			if !slices.Equal(got, append([]string{}, tc.want...)) {
				t.Fatalf("addresses %v, want %v", got, tc.want)
			}
		})
	}
}

func BenchmarkDiff(b *testing.B) {
	before := identityWith(map[string]ory.Credentials{
		"password": credential("password", `{"h":1}`), "oidc": credential("oidc", `{}`, "google:1"),
	}, address("email", "a"))
	after := identityWith(map[string]ory.Credentials{
		"password": credential("password", `{"h":2}`), "totp": credential("totp", `{"u":1}`),
	}, address("email", "b"))

	for b.Loop() {
		_ = flows.DiffCredentials(before, after)
		_ = flows.DiffAddresses(before, after)
	}
}

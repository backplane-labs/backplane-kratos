package scim_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

const base = `{"userName":"ann","externalId":"x1","active":true,` +
	`"name":{"givenName":"Ann"},"emails":[{"value":"ann@corp","type":"work","primary":true}]}`

func TestApplyPatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, patch string
		// want maps attributes to their expected compact JSON.
		want map[string]string
		bad  bool
	}{
		{
			name:  "Entra: capitalized op, active as a string",
			patch: `{"Operations":[{"op":"Replace","path":"active","value":"False"}]}`,
			want:  map[string]string{"active": "false"},
		},
		{
			name:  "Entra flag: boolean value",
			patch: `{"Operations":[{"op":"replace","path":"active","value":false}]}`,
			want:  map[string]string{"active": "false"},
		},
		{
			name:  "Okta: path-less replace with an object",
			patch: `{"Operations":[{"op":"replace","value":{"active":false}}]}`,
			want:  map[string]string{"active": "false"},
		},
		{
			name:  "reactivate",
			patch: `{"Operations":[{"op":"replace","path":"active","value":"True"}]}`,
			want:  map[string]string{"active": "true"},
		},
		{
			name:  "dotted path",
			patch: `{"Operations":[{"op":"replace","path":"name.familyName","value":"Lee"}]}`,
			want:  map[string]string{"name": `{"familyName":"Lee","givenName":"Ann"}`},
		},
		{
			name: "path-less dotted keys and an extension URN (Entra)",
			patch: `{"Operations":[{"op":"Add","value":{"name.familyName":"Lee",` +
				`"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department":"Ops"}}]}`,
			want: map[string]string{
				"name": `{"familyName":"Lee","givenName":"Ann"}`,
				"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": `{"department":"Ops"}`,
			},
		},
		{
			name:  "core URN prefix",
			patch: `{"Operations":[{"op":"replace","path":"urn:ietf:params:scim:schemas:core:2.0:User:userName","value":"bob"}]}`,
			want:  map[string]string{"userName": `"bob"`},
		},
		{
			name:  "value filter replaces an element's sub-attribute",
			patch: `{"Operations":[{"op":"replace","path":"emails[type eq \"work\"].value","value":"a@new"}]}`,
			want:  map[string]string{"emails": `[{"primary":true,"type":"work","value":"a@new"}]`},
		},
		{
			name:  "value filter adds a missing element",
			patch: `{"Operations":[{"op":"add","path":"emails[type eq \"home\"].value","value":"a@home"}]}`,
			want: map[string]string{
				"emails": `[{"primary":true,"type":"work","value":"ann@corp"},{"type":"home","value":"a@home"}]`,
			},
		},
		{
			name:  "value filter removes elements",
			patch: `{"Operations":[{"op":"remove","path":"emails[type eq \"work\"]"}]}`,
			want:  map[string]string{"emails": `[]`},
		},
		{
			name:  "remove a sub-attribute",
			patch: `{"Operations":[{"op":"remove","path":"name.givenName"}]}`,
			want:  map[string]string{"name": `{}`},
		},
		{
			name:  "add appends to a multi-valued attribute",
			patch: `{"Operations":[{"op":"add","path":"emails","value":[{"value":"b@corp"}]}]}`,
			want: map[string]string{
				"emails": `[{"value":"ann@corp","type":"work","primary":true},{"value":"b@corp"}]`,
			},
		},
		{
			name: "operations in any case", patch: `{"operations":[{"op":"replace","path":"active","value":false}]}`,
			want: map[string]string{"active": "false"},
		},
		{
			name: "a password is dropped", patch: `{"Operations":[{"op":"replace","path":"password","value":"x"}]}`,
			want: map[string]string{"active": "true"},
		},
		{name: "read-only id", patch: `{"Operations":[{"op":"replace","path":"id","value":"x"}]}`, bad: true},
		{name: "read-only ID in any case", patch: `{"Operations":[{"op":"replace","path":"ID","value":"x"}]}`, bad: true},
		{name: "read-only meta path-less", patch: `{"Operations":[{"op":"replace","value":{"Meta":{}}}]}`, bad: true},
		{
			name:  "a Password in any case is dropped",
			patch: `{"Operations":[{"op":"add","value":{"PASSWORD":"x","displayName":"Ann"}}]}`,
			want:  map[string]string{"displayName": `"Ann"`},
		},
		{name: "remove without a path", patch: `{"Operations":[{"op":"remove"}]}`, bad: true},
		{name: "unknown op", patch: `{"Operations":[{"op":"move","path":"a"}]}`, bad: true},
		{name: "no operations", patch: `{"Operations":[]}`, bad: true},
		{name: "not JSON", patch: `{`, bad: true},
		{name: "active not a boolean", patch: `{"Operations":[{"op":"replace","path":"active","value":"maybe"}]}`, bad: true},
		{name: "path-less non-object", patch: `{"Operations":[{"op":"replace","value":"x"}]}`, bad: true},
		{name: "path through a string", patch: `{"Operations":[{"op":"replace","path":"userName.x","value":"y"}]}`, bad: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u, err := scim.ParseUser([]byte(base))
			if err != nil {
				t.Fatal(err)
			}

			ops, err := scim.ParsePatch([]byte(tc.patch))
			if err == nil {
				err = u.Apply(ops)
			}

			if tc.bad {
				if err == nil {
					t.Fatalf("patch %s applied, want an error", tc.patch)
				}

				return
			}

			if err != nil {
				t.Fatalf("patch %s: %v", tc.patch, err)
			}

			for k := range u {
				if strings.EqualFold(k, "password") {
					t.Fatalf("a password was kept as %s", k)
				}
			}

			for attr, want := range tc.want {
				if !jsonSame(t, u[attr], want) {
					t.Errorf("%s = %s, want %s", attr, u[attr], want)
				}
			}
		})
	}
}

// jsonSame compares raw with want as JSON values.
func jsonSame(t *testing.T, raw json.RawMessage, want string) bool {
	t.Helper()

	var a, b any
	if json.Unmarshal(raw, &a) != nil || json.Unmarshal([]byte(want), &b) != nil {
		return false
	}

	x, errA := json.Marshal(a)
	y, errB := json.Marshal(b)

	return errA == nil && errB == nil && string(x) == string(y)
}

func BenchmarkApplyPatch(b *testing.B) {
	ops, err := scim.ParsePatch([]byte(`{"Operations":[{"op":"Replace","path":"active","value":"False"},` +
		`{"op":"replace","path":"emails[type eq \"work\"].value","value":"a@new"}]}`))
	if err != nil {
		b.Fatal(err)
	}

	for b.Loop() {
		u, _ := scim.ParseUser([]byte(base))
		_ = u.Apply(ops)
	}
}

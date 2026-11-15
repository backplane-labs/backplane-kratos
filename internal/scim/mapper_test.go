package scim_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestMap(t *testing.T) {
	t.Parallel()

	const user = `{"userName":"ann@corp","name":{"givenName":"Ann"},"emails":[{"value":"a@corp","primary":true}]}`

	tests := []struct {
		name, mapper, body string
		traits, public     string
		status             int
	}{
		{name: "default: primary email", body: user, traits: `{"email":"a@corp"}`},
		{name: "default: userName without emails", body: `{"userName":"ann@corp"}`, traits: `{"email":"ann@corp"}`},
		{
			name:   "jsonnet",
			mapper: `local u = std.extVar('user'); {traits: {email: u.userName, name: u.name.givenName}, metadata_public: {dir: 'corp'}}`,
			body:   user, traits: `{"email":"ann@corp","name":"Ann"}`, public: `{"dir":"corp"}`,
		},
		{name: "mapper error", mapper: `error 'no'`, body: user, status: http.StatusInternalServerError},
		{name: "not an object", mapper: `[1]`, body: user, status: http.StatusInternalServerError},
		{name: "traits missing", mapper: `{metadata_public: {}}`, body: user, status: http.StatusInternalServerError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u, err := scim.ParseUser([]byte(tc.body))
			if err != nil {
				t.Fatal(err)
			}

			got, err := scim.Directory{ID: "corp", Provider: "p", Mapper: tc.mapper}.Map(u)
			if tc.status != 0 {
				var e *scim.Error
				if !errors.As(err, &e) || e.Status != tc.status {
					t.Fatalf("Map error %v, want status %d", err, tc.status)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if !jsonSame(t, got.Traits, tc.traits) {
				t.Errorf("traits %s, want %s", got.Traits, tc.traits)
			}

			if tc.public != "" && !jsonSame(t, got.MetadataPublic, tc.public) {
				t.Errorf("metadata_public %s, want %s", got.MetadataPublic, tc.public)
			}
		})
	}
}

func BenchmarkMap(b *testing.B) {
	u, _ := scim.ParseUser([]byte(base))
	d := scim.Directory{ID: "corp", Provider: "p", Mapper: `{traits: {email: std.extVar('user').userName}}`}

	for b.Loop() {
		_, _ = d.Map(u)
	}
}

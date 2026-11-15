package scim_test

import (
	"errors"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	ok := scim.Directory{ID: "corp", Provider: "entra"}

	tests := []struct {
		name string
		dirs []scim.Directory
		want error
	}{
		{name: "none", dirs: nil},
		{name: "valid", dirs: []scim.Directory{ok, {ID: "okta-1", Provider: "okta", OnDelete: scim.Delete}}},
		{name: "upper case id", dirs: []scim.Directory{{ID: "Corp", Provider: "x"}}, want: scim.ErrDirectoryID},
		{name: "path in id", dirs: []scim.Directory{{ID: "a/b", Provider: "x"}}, want: scim.ErrDirectoryID},
		{name: "empty id", dirs: []scim.Directory{{Provider: "x"}}, want: scim.ErrDirectoryID},
		{name: "duplicate", dirs: []scim.Directory{ok, ok}, want: scim.ErrDuplicateDirectory},
		{name: "no provider", dirs: []scim.Directory{{ID: "a"}}, want: scim.ErrNoProvider},
		{name: "bad on_delete", dirs: []scim.Directory{{ID: "a", Provider: "x", OnDelete: "purge"}}, want: scim.ErrOnDelete},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := scim.Validate(tc.dirs); !errors.Is(err, tc.want) || (tc.want == nil && err != nil) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestDeletes(t *testing.T) {
	t.Parallel()

	if (scim.Directory{}).Deletes() || !(scim.Directory{OnDelete: scim.Delete}).Deletes() {
		t.Fatal("Deletes is wrong")
	}
}

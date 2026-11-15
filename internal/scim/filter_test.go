package scim_test

import (
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestParseFilter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, in string
		want     scim.Filter
		bad      bool
	}{
		{name: "empty", in: "", want: scim.Filter{}},
		{name: "userName quoted", in: `userName eq "Ann@Corp.example"`, want: scim.Filter{UserName: "Ann@Corp.example"}},
		{name: "userName bare (Entra)", in: `userName eq Ann`, want: scim.Filter{UserName: "Ann"}},
		{name: "any case", in: `USERNAME EQ "Ann"`, want: scim.Filter{UserName: "Ann"}},
		{name: "externalId", in: `externalId eq "00u1"`, want: scim.Filter{ExternalID: "00u1"}},
		{
			name: "and", in: `externalId eq "00u1" and userName eq "ann"`,
			want: scim.Filter{ExternalID: "00u1", UserName: "ann"},
		},
		{name: "work email", in: `emails[type eq "work"].value eq "a@b.c"`, want: scim.Filter{Email: "a@b.c"}},
		{name: "email value", in: `emails.value eq "a@b.c"`, want: scim.Filter{Email: "a@b.c"}},
		{name: "escaped quote", in: `userName eq "a\"b"`, want: scim.Filter{UserName: `a"b`}},
		{name: "and inside a value", in: `userName eq "a and b"`, want: scim.Filter{UserName: "a and b"}},
		{name: "or", in: `userName eq "a" or userName eq "b"`, bad: true},
		{name: "other operator", in: `userName co "a"`, bad: true},
		{name: "other attribute", in: `displayName eq "a"`, bad: true},
		{name: "dangling and", in: `userName eq "a" and`, bad: true},
		{name: "broken string", in: `userName eq "a\"`, bad: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := scim.ParseFilter(tc.in)
			if tc.bad {
				if err == nil {
					t.Fatalf("ParseFilter(%q) = %+v, want an error", tc.in, got)
				}

				return
			}

			if err != nil || got != tc.want {
				t.Fatalf("ParseFilter(%q) = %+v, %v; want %+v", tc.in, got, err, tc.want)
			}
		})
	}
}

func TestFilterIsZero(t *testing.T) {
	t.Parallel()

	if !(scim.Filter{}).IsZero() || (scim.Filter{Email: "a"}).IsZero() {
		t.Fatal("IsZero is wrong")
	}
}

func BenchmarkParseFilter(b *testing.B) {
	for b.Loop() {
		_, _ = scim.ParseFilter(`externalId eq "00u1" and emails[type eq "work"].value eq "a@b.c"`)
	}
}

package backchannel_test

import (
	"errors"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/backchannel"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	ok := backchannel.Provider{ID: "corp", Issuer: "https://idp", Audience: "kratos", JWKSURL: "https://idp/jwks"}
	plain := ok
	plain.JWKSURL = "http://idp/jwks"

	tests := []struct {
		name      string
		providers []backchannel.Provider
		allowHTTP bool
		want      error
	}{
		{name: "none"},
		{name: "valid", providers: []backchannel.Provider{ok}},
		{name: "http refused", providers: []backchannel.Provider{plain}, want: backchannel.ErrJWKSURL},
		{name: "http in tests", providers: []backchannel.Provider{plain}, allowHTTP: true},
		{
			name: "relative", providers: []backchannel.Provider{{ID: "a", Issuer: "i", Audience: "a", JWKSURL: "/jwks"}},
			want: backchannel.ErrJWKSURL,
		},
		{
			name: "no audience", providers: []backchannel.Provider{{ID: "a", Issuer: "i", JWKSURL: "https://x"}},
			want: backchannel.ErrProvider,
		},
		{name: "duplicate", providers: []backchannel.Provider{ok, ok}, want: backchannel.ErrDuplicateProvider},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if err := backchannel.Validate(tc.providers, tc.allowHTTP); !errors.Is(err, tc.want) ||
				(tc.want == nil && err != nil) {
				t.Fatalf("Validate = %v, want %v", err, tc.want)
			}
		})
	}
}

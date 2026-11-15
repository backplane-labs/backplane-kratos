package scim_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestKratosFailure(t *testing.T) {
	t.Parallel()

	cause := errors.New("connection refused")

	tests := []struct {
		name   string
		err    error
		status int // 0: not a refusal
	}{
		{name: "not found", err: &ory.Error{Status: http.StatusNotFound}, status: http.StatusNotFound},
		{name: "conflict", err: &ory.Error{Status: http.StatusConflict}, status: http.StatusConflict},
		{name: "invalid", err: &ory.Error{Status: http.StatusBadRequest, Message: "traits"}, status: http.StatusBadRequest},
		{name: "kratos failing", err: &ory.Error{Status: http.StatusInternalServerError}},
		{name: "unreachable", err: cause},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := scim.KratosFailure(tc.err)

			var e *scim.Error
			if errors.As(got, &e) != (tc.status != 0) || (tc.status != 0 && e.Status != tc.status) {
				t.Fatalf("KratosFailure(%v) = %v", tc.err, got)
			}

			if tc.status == 0 && !errors.Is(got, tc.err) {
				t.Fatalf("the cause is lost: %v", got)
			}
		})
	}
}

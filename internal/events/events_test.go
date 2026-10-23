package events_test

import (
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/events"
)

func TestTraits(t *testing.T) {
	t.Parallel()

	got := events.Traits([]byte(`{"email":"a@b","name":{"first":"A"}}`))
	if got.GetFields()["email"].GetStringValue() != "a@b" ||
		got.GetFields()["name"].GetStructValue().GetFields()["first"].GetStringValue() != "A" {
		t.Fatalf("traits %v", got)
	}

	for _, raw := range []string{"", "null", "[1]", "{"} {
		if traits := events.Traits([]byte(raw)); traits != nil {
			t.Errorf("%q: %v", raw, traits)
		}
	}
}

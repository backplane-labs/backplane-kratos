package kratos_test

import (
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	kratos "github.com/backplane-labs/backplane-kratos"
	"github.com/backplane-labs/backplane-kratos/internal/ory"
)

// The service is ready without a live Kratos: Kratos calls it, so it
// starts after the service is ready.
func TestReadyWithoutKratos(t *testing.T) {
	t.Parallel()

	client, err := ory.New(ory.Options{Admin: "http://127.0.0.1:1", Public: "http://127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}

	h := backplanetest.New(t)
	kratos.Installation(h.Root(), client)
	h.Start()

	if err := backplanetest.Ready(h); err != nil {
		t.Fatalf("not ready: %v", err)
	}
}

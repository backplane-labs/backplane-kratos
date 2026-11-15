package scim_test

import (
	"net/http"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestEventPayloads(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	id := f.create(okta)
	f.do(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","path":"active","value":false}]}`)

	created := backplanetest.Events(f.h, f.created)
	if len(created) != 1 || created[0].GetIdentityId() != id || created[0].GetSchemaId() != "default" ||
		created[0].GetTraits().GetFields()["email"].GetStringValue() != "ann@corp" {
		t.Fatalf("created %+v", created)
	}

	states := backplanetest.Events(f.h, f.dirs.StateEvent())
	if len(states) != 1 || states[0].GetBy() != scim.ByDirectory || states[0].GetState() != "inactive" ||
		states[0].GetIdentityId() != id {
		t.Fatalf("states %+v", states)
	}
}

package scim_test

import (
	"net/http"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/backplane-labs/backplane-kratos/internal/outbox/outboxtest"
	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestBrokenMapperChangesNothing(t *testing.T) {
	t.Parallel()

	h := backplanetest.New(t)
	k := newKratos()
	ref := event.Declare[scim.IdentityEvent](h.Root(), "IdentityChanged")
	f := &fixture{t: t, h: h, k: k, box: outboxtest.New()}
	f.dirs = scim.New(h.Root(),
		config.LiveOf([]scim.Directory{{ID: "corp", Provider: "entra", Mapper: `error 'broken'`}}),
		config.LiveOf(map[string]config.Secret{"corp": token}), k, f.box, ref, ref, ref)
	f.handler = f.dirs.Handler()
	h.Start()

	if code, out := f.do(http.MethodPost, "/Users", okta); code != http.StatusInternalServerError {
		t.Fatalf("create with a broken mapper: %d %v", code, out)
	}

	if len(k.identities) != 0 || len(f.box.Pending()) != 0 || len(backplanetest.Events(h, ref)) != 0 {
		t.Fatal("a broken mapper must change nothing")
	}
}

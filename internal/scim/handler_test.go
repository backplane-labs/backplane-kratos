package scim_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"
	"github.com/backplane-labs/backplane/pkg/backplane/config"
	"github.com/backplane-labs/backplane/pkg/backplane/event"

	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

const token = "directory-token"

type fixture struct {
	t                         *testing.T
	h                         *backplanetest.Harness
	k                         *kratos
	dirs                      *scim.Directories
	handler                   http.Handler
	created, updated, deleted event.Ref[scim.IdentityEvent]
}

func setup(t *testing.T, onDelete scim.OnDelete) *fixture {
	t.Helper()

	h := backplanetest.New(t)
	f := &fixture{t: t, h: h, k: newKratos()}
	f.created = event.Declare[scim.IdentityEvent](h.Root(), "IdentityCreated")
	f.updated = event.Declare[scim.IdentityEvent](h.Root(), "IdentityUpdated")
	f.deleted = event.Declare[scim.IdentityEvent](h.Root(), "IdentityDeleted")
	f.dirs = scim.New(h.Root(),
		config.LiveOf([]scim.Directory{
			{ID: "corp", Provider: "entra", OnDelete: onDelete},
			{ID: "other", Provider: "entra"},
		}),
		config.LiveOf(map[string]config.Secret{"corp": token, "other": "other-token"}),
		f.k, f.created, f.updated, f.deleted)
	f.handler = f.dirs.Handler()
	h.Start()

	return f
}

// do sends a request to the corp directory with its token.
func (f *fixture) do(method, path, body string) (int, map[string]json.RawMessage) {
	f.t.Helper()

	return f.send(method, "/scim/v2/corp"+path, body, "Bearer "+token)
}

func (f *fixture) send(method, target, body, auth string) (int, map[string]json.RawMessage) {
	f.t.Helper()

	r := httptest.NewRequestWithContext(f.t.Context(), method, target, strings.NewReader(body))
	if auth != "" {
		r.Header.Set("Authorization", auth)
	}

	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, r)

	if w.Body.Len() > 0 && w.Header().Get("Content-Type") != "application/scim+json" {
		f.t.Fatalf("%s %s: content type %q", method, target, w.Header().Get("Content-Type"))
	}

	var out map[string]json.RawMessage
	_ = json.Unmarshal(w.Body.Bytes(), &out)

	return w.Code, out
}

func (f *fixture) create(body string) string {
	f.t.Helper()

	code, out := f.do(http.MethodPost, "/Users", body)
	if code != http.StatusCreated {
		f.t.Fatalf("create: %d %s", code, out["detail"])
	}

	var id string
	_ = json.Unmarshal(out["id"], &id)

	return id
}

func (f *fixture) states() []backplanetest.Published[scim.StateChanged] {
	return backplanetest.EventsWithMeta(f.h, f.dirs.StateEvent())
}

// okta is Okta's create: a placeholder password, externalId the user id.
const okta = `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"ann@corp","externalId":"x1",` +
	`"name":{"givenName":"Ann"},"emails":[{"value":"ann@corp","type":"work","primary":true}],` +
	`"active":true,"password":"placeholder"}`

func TestAuthentication(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)

	tests := []struct {
		name, target, auth string
		want               int
	}{
		{name: "bearer", target: "/scim/v2/corp/Groups", auth: "Bearer " + token, want: http.StatusOK},
		{name: "bare token (Okta)", target: "/scim/v2/corp/Groups", auth: token, want: http.StatusOK},
		{name: "bearer in any case", target: "/scim/v2/corp/Groups", auth: "bearer " + token, want: http.StatusOK},
		{name: "missing", target: "/scim/v2/corp/Groups", want: http.StatusUnauthorized},
		{name: "wrong", target: "/scim/v2/corp/Groups", auth: "Bearer nope", want: http.StatusUnauthorized},
		{
			name: "another directory's token", target: "/scim/v2/corp/Groups", auth: "Bearer other-token",
			want: http.StatusUnauthorized,
		},
		{name: "unknown directory", target: "/scim/v2/nope/Groups", auth: "Bearer " + token, want: http.StatusNotFound},
		{name: "no token configured", target: "/scim/v2/other/Groups", auth: "Bearer ", want: http.StatusUnauthorized},
		{name: "unknown resource", target: "/scim/v2/corp/Nope", auth: "Bearer " + token, want: http.StatusNotFound},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if code, _ := f.send(http.MethodGet, tc.target, "", tc.auth); code != tc.want {
				t.Fatalf("GET %s with %q: %d, want %d", tc.target, tc.auth, code, tc.want)
			}
		})
	}
}

func TestDiscovery(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)

	for _, doc := range []string{"/ServiceProviderConfig", "/ResourceTypes", "/Schemas"} {
		if code, out := f.do(http.MethodGet, doc, ""); code != http.StatusOK || out["schemas"] == nil {
			t.Errorf("%s: %d %v", doc, code, out)
		}
	}

	if _, out := f.do(http.MethodGet, "/Groups", ""); string(out["totalResults"]) != "0" {
		t.Errorf("groups: %s", out["totalResults"])
	}
}

func TestCreate(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	id := f.create(okta)
	got := f.k.identity(id)

	if got.Credentials["oidc"].Identifiers[0] != "entra:x1" || got.ExternalID != "corp:ann@corp" ||
		got.State != "active" {
		t.Fatalf("identity %+v", got)
	}

	if strings.Contains(string(got.MetadataAdmin), "placeholder") || strings.Contains(string(got.MetadataAdmin), "pending") {
		t.Fatalf("metadata_admin %s", got.MetadataAdmin)
	}

	created := backplanetest.EventsWithMeta(f.h, f.created)
	if len(created) != 1 || created[0].Key != id || created[0].Value.GetBy() != scim.ByDirectory {
		t.Fatalf("created events %+v", created)
	}

	// The IdP retrying its create gets the same user and no second event.
	if again := f.create(okta); again != id || len(backplanetest.Events(f.h, f.created)) != 1 {
		t.Fatalf("retry: %s, %d events", again, len(backplanetest.Events(f.h, f.created)))
	}

	code, out := f.do(http.MethodGet, "/Users/"+id, "")
	if code != http.StatusOK || string(out["active"]) != "true" || string(out["userName"]) != `"ann@corp"` {
		t.Fatalf("GET: %d %v", code, out)
	}
}

func TestCreateRefusals(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	f.create(okta)

	tests := []struct {
		name, body string
		want       int
	}{
		{name: "userName taken", body: `{"userName":"ANN@corp","externalId":"x2"}`, want: http.StatusConflict},
		{name: "no externalId", body: `{"userName":"bob"}`, want: http.StatusBadRequest},
		{name: "no userName", body: `{"externalId":"x3"}`, want: http.StatusBadRequest},
		{name: "not JSON", body: `{`, want: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if code, out := f.do(http.MethodPost, "/Users", tc.body); code != tc.want || out["scimType"] == nil {
				t.Fatalf("POST %s: %d %v", tc.body, code, out)
			}
		})
	}
}

func TestCreateAnotherDirectorysUser(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	f.create(okta)

	if code, _ := f.send(http.MethodPost, "/scim/v2/other/Users", okta, "Bearer other-token"); code != http.StatusConflict {
		t.Fatalf("another directory's create: %d", code)
	}
}

func TestAdoption(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	first := f.k.signedIn("entra", "x1")

	if id := f.create(okta); id != first {
		t.Fatalf("adopted %s, want the signed-in %s", id, first)
	}

	if got := f.k.identity(first); got.ExternalID != "corp:ann@corp" ||
		len(backplanetest.Events(f.h, f.updated)) != 1 || len(backplanetest.Events(f.h, f.created)) != 0 {
		t.Fatalf("identity %+v", got)
	}
}

func TestFind(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	id := f.create(okta)
	f.k.signedIn("entra", "stranger")

	tests := []struct {
		filter string
		want   string
	}{
		{filter: `externalId eq "x1"`, want: "1"},
		{filter: `userName eq "ANN@corp"`, want: "1"},
		{filter: `userName eq ann@corp`, want: "1"},
		{filter: `emails[type eq "work"].value eq "ann@corp"`, want: "0"}, // the fake indexes OIDC identifiers only
		{filter: `externalId eq "x1" and userName eq "bob"`, want: "0"},
		{filter: `externalId eq "stranger"`, want: "0"},
		{filter: `userName eq "nobody"`, want: "0"},
		{filter: ``, want: "0"},
	}

	for _, tc := range tests {
		t.Run(tc.filter, func(t *testing.T) {
			t.Parallel()

			code, out := f.do(http.MethodGet, "/Users?filter="+urlEscape(tc.filter), "")
			if code != http.StatusOK || string(out["totalResults"]) != tc.want {
				t.Fatalf("filter %q: %d %v", tc.filter, code, out)
			}

			if tc.want == "1" && !strings.Contains(string(out["Resources"]), id) {
				t.Fatalf("filter %q: %s", tc.filter, out["Resources"])
			}
		})
	}

	if code, _ := f.do(http.MethodGet, "/Users?filter="+urlEscape(`title co "x"`), ""); code != http.StatusBadRequest {
		t.Fatalf("unsupported filter: %d", code)
	}
}

func TestDeactivateAndReactivate(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	id := f.create(okta)

	code, out := f.do(http.MethodPatch, "/Users/"+id,
		`{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"Replace","path":"active","value":"False"}]}`)
	if code != http.StatusOK || string(out["active"]) != "false" {
		t.Fatalf("deactivate: %d %v", code, out)
	}

	if f.k.identity(id).State != "inactive" || f.k.deletedSessions(id) != 1 {
		t.Fatalf("state %s, sessions deleted %d", f.k.identity(id).State, f.k.deletedSessions(id))
	}

	// Okta's path-less form reactivates.
	reactivate := `{"Operations":[{"op":"replace","value":{"active":true}}]}`
	if code, _ = f.do(http.MethodPatch, "/Users/"+id, reactivate); code != http.StatusOK {
		t.Fatalf("reactivate: %d", code)
	}

	states := f.states()
	if len(states) != 2 ||
		states[0].Value.GetReason() != scim.ReasonDeactivated || states[0].Value.GetState() != "inactive" ||
		states[1].Value.GetReason() != scim.ReasonReactivated || states[1].Value.GetDirectory() != "corp" ||
		states[0].ID == states[1].ID || states[0].Key != id {
		t.Fatalf("state events %+v", states)
	}

	// The same deactivation repeated by the IdP is one event.
	patch := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
	f.do(http.MethodPatch, "/Users/"+id, patch)
	f.do(http.MethodPatch, "/Users/"+id, patch)

	if n := len(f.states()); n != 3 {
		t.Fatalf("%d state events, want 3", n)
	}
}

func TestEventPublishedOnRetry(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	id := f.create(okta)

	backplanetest.FailPublish(f.h, errors.New("broker down"))

	patch := `{"Operations":[{"op":"replace","path":"active","value":false}]}`
	if code, _ := f.do(http.MethodPatch, "/Users/"+id, patch); code != http.StatusServiceUnavailable {
		t.Fatalf("publish failing: %d, want 503", code)
	}

	if got := f.k.identity(id); got.State != "inactive" || !strings.Contains(string(got.MetadataAdmin), "pending") {
		t.Fatalf("the change and its event must be kept: %+v", got)
	}

	backplanetest.FailPublish(f.h, nil)

	if code, _ := f.do(http.MethodPatch, "/Users/"+id, patch); code != http.StatusOK {
		t.Fatalf("retry: %d", code)
	}

	if states := f.states(); len(states) != 1 || states[0].Value.GetReason() != scim.ReasonDeactivated {
		t.Fatalf("state events %+v", states)
	}

	if strings.Contains(string(f.k.identity(id).MetadataAdmin), "pending") {
		t.Fatal("pending events not cleared")
	}
}

func TestReplace(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	id := f.create(okta)

	// Okta deactivates with a full PUT.
	put := strings.Replace(okta, `"active":true`, `"active":false`, 1)
	if code, out := f.do(http.MethodPut, "/Users/"+id, put); code != http.StatusOK || string(out["active"]) != "false" {
		t.Fatalf("PUT: %d %v", code, out)
	}

	updates := len(backplanetest.Events(f.h, f.updated))
	if code, _ := f.do(http.MethodPut, "/Users/"+id, put); code != http.StatusOK ||
		len(backplanetest.Events(f.h, f.updated)) != updates {
		t.Fatal("an unchanged PUT must change nothing")
	}

	moved := strings.Replace(okta, `"externalId":"x1"`, `"externalId":"x9"`, 1)
	if code, out := f.do(http.MethodPut, "/Users/"+id, moved); code != http.StatusBadRequest ||
		string(out["scimType"]) != `"mutability"` {
		t.Fatalf("externalId change: %d %v", code, out)
	}
}

func TestDelete(t *testing.T) {
	t.Parallel()

	keep := setup(t, scim.Deactivate)
	id := keep.create(okta)

	if code, _ := keep.do(http.MethodDelete, "/Users/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}

	if code, out := keep.do(http.MethodGet, "/Users/"+id, ""); code != http.StatusOK || string(out["active"]) != "false" {
		t.Fatalf("a deactivated user stays readable: %d %v", code, out)
	}

	if s := keep.states(); len(s) != 1 || s[0].Value.GetReason() != scim.ReasonDeleted {
		t.Fatalf("state events %+v", s)
	}

	gone := setup(t, scim.Delete)
	id = gone.create(okta)

	if code, _ := gone.do(http.MethodDelete, "/Users/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}

	if code, _ := gone.do(http.MethodGet, "/Users/"+id, ""); code != http.StatusNotFound ||
		len(backplanetest.Events(gone.h, gone.deleted)) != 1 {
		t.Fatalf("deleted: %d", code)
	}
}

func TestForeignIdentity(t *testing.T) {
	t.Parallel()

	f := setup(t, scim.Deactivate)
	id := f.k.signedIn("entra", "someone")

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		body := map[string]string{http.MethodPut: okta, http.MethodPatch: `{"Operations":[{"op":"replace","path":"active","value":false}]}`}[method]
		if code, _ := f.do(method, "/Users/"+id, body); code != http.StatusNotFound {
			t.Errorf("%s of an identity no directory owns: %d", method, code)
		}
	}
}

func urlEscape(s string) string {
	return strings.NewReplacer(" ", "%20", `"`, "%22", "[", "%5B", "]", "%5D").Replace(s)
}

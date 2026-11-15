package it_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

const (
	directoryToken = "it-directory-token"
	// subject is what the mock IdP's "returning" issuer signs every login as:
	// the directory's externalId of the person, so both name one identity.
	subject = "returning-user"
)

// testDirectories link their people to the "returning" OIDC provider of
// nativeSettings: corp keeps a deleted user inactive, gone deletes it.
func testDirectories() []scim.Directory {
	return []scim.Directory{
		{ID: "corp", Provider: "returning"},
		{ID: "gone", Provider: "returning", OnDelete: scim.Delete},
	}
}

// directory is a directory's SCIM base on its own server.
type directory struct {
	t    *testing.T
	base string
}

func (e env) directory(t *testing.T, id string) directory {
	t.Helper()

	srv := httptest.NewServer(e.directories.Handler())
	t.Cleanup(srv.Close)

	return directory{t: t, base: srv.URL + "/scim/v2/" + id}
}

func (d directory) send(method, path, body, auth string) (int, map[string]json.RawMessage) {
	d.t.Helper()

	req, err := http.NewRequestWithContext(d.t.Context(), method, d.base+path, strings.NewReader(body))
	if err != nil {
		d.t.Fatal(err)
	}

	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/scim+json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		d.t.Fatal(err)
	}
	defer res.Body.Close()

	var out map[string]json.RawMessage
	_ = json.NewDecoder(res.Body).Decode(&out)

	return res.StatusCode, out
}

func (d directory) do(method, path, body string) (int, map[string]json.RawMessage) {
	d.t.Helper()

	return d.send(method, path, body, "Bearer "+directoryToken)
}

// user is an Okta-style create of the mock IdP's person.
func user(name string) string {
	return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name + `",` +
		`"externalId":"` + subject + `","name":{"givenName":"Ret"},` +
		`"emails":[{"value":"` + name + `","type":"work","primary":true}],"active":true,"password":"placeholder"}`
}

func (d directory) create(name string) string {
	d.t.Helper()

	code, out := d.do(http.MethodPost, "/Users", user(name))
	if code != http.StatusCreated {
		d.t.Fatalf("create: %d %s", code, out["detail"])
	}

	var id string
	_ = json.Unmarshal(out["id"], &id)

	return id
}

// forget deletes whatever identity holds the mock person's credential:
// Kratos is shared by the tests.
func forget(t *testing.T, e env) {
	t.Helper()

	page, err := e.kratos.ListIdentities(t.Context(), ory.IdentityFilter{CredentialsIdentifier: "returning:" + subject})
	if err != nil {
		t.Fatal(err)
	}

	for _, id := range page.Items {
		if err := e.kratos.DeleteIdentity(t.Context(), id.ID); err != nil && !ory.IsNotFound(err) {
			t.Fatal(err)
		}
	}
}

// signIn is the mock person's native OIDC login and its session token.
func signIn(t *testing.T, e env) (string, error) {
	t.Helper()

	n, err := trySignIn(t, e, publicURL, "login", "returning", nil)
	if err != nil {
		return "", err
	}

	status, body := exchange(t, n)
	if status != http.StatusOK {
		return "", errNoCallback
	}

	token, _ := body["session_token"].(string)

	return token, nil
}

func whoami(t *testing.T, token string) (int, string) {
	t.Helper()

	status, body := callAs(t, token, http.MethodGet, "/sessions/whoami", nil)
	identity, _ := body["identity"].(map[string]any)
	id, _ := identity["id"].(string)

	return status, id
}

func patchActive(active string) string {
	return `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],` +
		`"Operations":[{"op":"Replace","path":"active","value":"` + active + `"}]}`
}

// TestDirectoryLifecycle: an IdP provisions a person, who signs in with the
// same IdP into that identity; deactivating them ends their session and
// refuses a new login, once as one event; reactivating lets them in again.
func TestDirectoryLifecycle(t *testing.T) {
	t.Parallel()

	e := startWith(t, nativeSettings, nil)
	forget(t, e)

	corp := e.directory(t, "corp")
	name := unique("ann")
	id := corp.create(name)

	got, err := e.kratos.GetIdentity(t.Context(), id, "oidc")
	if err != nil {
		t.Fatal(err)
	}

	if got.State != "active" || got.ExternalID != "corp:"+name ||
		!slices.Contains(got.Credentials["oidc"].Identifiers, "returning:"+subject) {
		t.Fatalf("identity %+v", got)
	}

	for _, filter := range []string{`externalId eq "` + subject + `"`, `userName eq "` + strings.ToUpper(name) + `"`} {
		code, out := corp.do(http.MethodGet, "/Users?filter="+escape(filter), "")
		if code != http.StatusOK || string(out["totalResults"]) != "1" {
			t.Fatalf("filter %s: %d %v", filter, code, out)
		}
	}

	token, err := signIn(t, e)
	if err != nil {
		t.Fatal(err)
	}

	if status, who := whoami(t, token); status != http.StatusOK || who != id {
		t.Fatalf("the login landed in %q (%d), want the provisioned %s", who, status, id)
	}

	// Entra ID's deactivation, twice: the IdP retries.
	for range 2 {
		if code, out := corp.do(http.MethodPatch, "/Users/"+id, patchActive("False")); code != http.StatusOK ||
			string(out["active"]) != "false" {
			t.Fatalf("deactivate: %d %v", code, out)
		}
	}

	if status, _ := whoami(t, token); status != http.StatusUnauthorized {
		t.Fatalf("whoami after deactivation: %d", status)
	}

	if _, err := signIn(t, e); !errors.Is(err, errNoCallback) {
		t.Fatalf("a deactivated person signed in: %v", err)
	}

	states := backplanetest.EventsWithMeta(e.h, e.directories.StateEvent())
	if len(states) != 1 || states[0].Value.GetReason() != scim.ReasonDeactivated || states[0].Key != id {
		t.Fatalf("state events %+v", states)
	}

	// Okta's reactivation.
	if code, _ := corp.do(http.MethodPatch, "/Users/"+id, `{"Operations":[{"op":"replace","value":{"active":true}}]}`); code != http.StatusOK {
		t.Fatalf("reactivate: %d", code)
	}

	token, err = signIn(t, e)
	if err != nil {
		t.Fatal(err)
	}

	if status, who := whoami(t, token); status != http.StatusOK || who != id {
		t.Fatalf("after reactivation: %d %s", status, who)
	}
}

// TestDirectoryAdoption: a person who signed in before the IdP provisioned
// them becomes the directory's user, not a second identity.
func TestDirectoryAdoption(t *testing.T) {
	t.Parallel()

	e := startWith(t, nativeSettings, nil)
	forget(t, e)

	if _, err := trySignIn(t, e, publicURL, "registration", "returning", nil); err != nil {
		t.Fatal(err)
	}

	page, err := e.kratos.ListIdentities(t.Context(), ory.IdentityFilter{CredentialsIdentifier: "returning:" + subject})
	if err != nil || len(page.Items) != 1 {
		t.Fatalf("the registration's identity: %v %v", page.Items, err)
	}

	if id := e.directory(t, "corp").create(unique("adopt")); id != page.Items[0].ID {
		t.Fatalf("created %s, want the signed-in %s", id, page.Items[0].ID)
	}
}

// TestDirectoryDelete: a DELETE keeps the identity inactive, or deletes it.
func TestDirectoryDelete(t *testing.T) {
	t.Parallel()

	e := startWith(t, nativeSettings, nil)

	forget(t, e)

	corp := e.directory(t, "corp")
	id := corp.create(unique("keep"))

	if code, _ := corp.do(http.MethodDelete, "/Users/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}

	if got, err := e.kratos.GetIdentity(t.Context(), id); err != nil || got.State != "inactive" {
		t.Fatalf("kept identity %+v %v", got, err)
	}

	forget(t, e)

	gone := e.directory(t, "gone")
	id = gone.create(unique("gone"))

	if code, _ := gone.do(http.MethodDelete, "/Users/"+id, ""); code != http.StatusNoContent {
		t.Fatalf("delete: %d", code)
	}

	if _, err := e.kratos.GetIdentity(context.WithoutCancel(t.Context()), id); !ory.IsNotFound(err) {
		t.Fatalf("deleted identity: %v", err)
	}

	if code, _ := corp.send(http.MethodGet, "/Users", "", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Fatalf("wrong token: %d", code)
	}
}

func escape(s string) string {
	return strings.NewReplacer(" ", "%20", `"`, "%22").Replace(s)
}

package scim_test

import (
	"errors"
	"net/http"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestParseUser(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, body string
		active     bool
		email      string
		status     int // 0: accepted
	}{
		{name: "active by default", body: `{"userName":"ann"}`, active: true},
		{name: "Entra string boolean", body: `{"userName":"ann","active":"False"}`},
		{name: "primary email", body: `{"userName":"ann","active":true,"emails":[{"value":"w@x","type":"work"},` +
			`{"value":"p@x","primary":true}]}`, active: true, email: "p@x"},
		{
			name: "work email", body: `{"userName":"ann","emails":[{"value":"h@x","type":"home"},{"value":"w@x","type":"Work"}]}`,
			active: true, email: "w@x",
		},
		{name: "first email", body: `{"userName":"ann","emails":[{"value":"h@x","type":"home"}]}`, active: true, email: "h@x"},
		{name: "no userName", body: `{"active":true}`, status: http.StatusBadRequest},
		{name: "active not a boolean", body: `{"userName":"a","active":1}`, status: http.StatusBadRequest},
		{name: "not an object", body: `[]`, status: http.StatusBadRequest},
		{name: "not JSON", body: `{`, status: http.StatusBadRequest},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u, err := scim.ParseUser([]byte(tc.body))
			if tc.status != 0 {
				var e *scim.Error
				if !errors.As(err, &e) || e.Status != tc.status {
					t.Fatalf("ParseUser(%s) error %v, want status %d", tc.body, err, tc.status)
				}

				return
			}

			if err != nil {
				t.Fatal(err)
			}

			if u.Active() != tc.active || u.Email() != tc.email {
				t.Fatalf("active %v email %q, want %v %q", u.Active(), u.Email(), tc.active, tc.email)
			}
		})
	}
}

func TestParseUserDropsServerAttributes(t *testing.T) {
	t.Parallel()

	u, err := scim.ParseUser([]byte(`{"userName":"a","ID":"forged","Meta":{},"PassWord":"placeholder",` +
		`"password":"x","id":"y"}`))
	if err != nil {
		t.Fatal(err)
	}

	for _, k := range []string{"ID", "Meta", "PassWord", "password", "id"} {
		if _, ok := u[k]; ok {
			t.Errorf("%s kept", k)
		}
	}
}

func TestUserEqual(t *testing.T) {
	t.Parallel()

	a, _ := scim.ParseUser([]byte(`{"userName":"a","name":{"givenName":"A"}}`))
	b, _ := scim.ParseUser([]byte(`{ "name": { "givenName": "A" }, "userName": "a" }`))
	c, _ := scim.ParseUser([]byte(`{"userName":"a","name":{"givenName":"B"}}`))

	if !a.Equal(b) || a.Equal(c) {
		t.Fatal("Equal must compare JSON values, not bytes")
	}
}

func TestErrorMessage(t *testing.T) {
	t.Parallel()

	_, err := scim.ParseUser([]byte(`{}`))
	if err == nil || err.Error() != "scim: userName is required" {
		t.Fatalf("error %v", err)
	}
}

func BenchmarkParseUser(b *testing.B) {
	body := []byte(base)

	for b.Loop() {
		u, _ := scim.ParseUser(body)
		_ = u.Email()
	}
}

package scim_test

import (
	"encoding/json"
	"testing"

	"github.com/backplane-labs/backplane-kratos/internal/ory"
	"github.com/backplane-labs/backplane-kratos/internal/scim"
)

func TestRecordKeepsOtherMetadata(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, metadata string
	}{
		{name: "none", metadata: ``},
		{name: "null", metadata: `null`},
		{name: "other keys", metadata: `{"crm":{"id":7}}`},
		{name: "not an object", metadata: `[1]`},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			u, _ := scim.ParseUser([]byte(`{"userName":"a"}`))

			meta, err := scim.WithRecord(json.RawMessage(tc.metadata), scim.Record{Directory: "corp", User: u})
			if err != nil {
				t.Fatal(err)
			}

			r, ok := scim.Stored(ory.Identity{MetadataAdmin: meta})
			if !ok || r.Directory != "corp" || !r.User.Equal(u) {
				t.Fatalf("record %+v from %s", r, meta)
			}

			if tc.metadata == `{"crm":{"id":7}}` && !jsonSame(t, meta,
				`{"crm":{"id":7},"scim":{"directory":"corp","user":{"active":true,"userName":"a"}}}`) {
				t.Fatalf("metadata %s", meta)
			}
		})
	}
}

func TestStoredIgnoresOthers(t *testing.T) {
	t.Parallel()

	for _, meta := range []string{``, `{}`, `{"scim":{}}`, `{"scim":{"directory":"corp"}}`, `{"scim":1}`} {
		if _, ok := scim.Stored(ory.Identity{MetadataAdmin: json.RawMessage(meta)}); ok {
			t.Errorf("%s is no directory's", meta)
		}
	}
}

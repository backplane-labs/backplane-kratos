package kratos_test

import (
	"errors"
	"testing"

	"github.com/backplane-labs/backplane/pkg/backplane/backplanetest"

	kratos "github.com/backplane-labs/backplane-kratos"
)

// The configuration loads as the binary loads it (schemapb reflection
// included): a tag schemapb does not know stops the service at start.
func TestConfigLoads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		vars    map[string]string
		wantErr error
	}{
		{name: "without events, no database", vars: map[string]string{
			"DIRECTORIES": `[{"id":"corp","provider":"entra","on_delete":"delete"}]`,
		}},
		{name: "events with a database", vars: map[string]string{
			"BACKPLANE_NATS_URL": "nats://127.0.0.1:4222", "DB_DSN": "postgres://k:k@127.0.0.1:5432/k",
		}},
		{
			name: "events without a database", vars: map[string]string{"BACKPLANE_NATS_URL": "nats://127.0.0.1:4222"},
			wantErr: kratos.ErrNoDB,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg, err := backplanetest.LoadConfig[kratos.Config](t.Context(), tc.vars)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err = %v, want %v", err, tc.wantErr)
			}

			if dirs := cfg.Directories.Get(); err == nil && len(dirs) == 1 && !dirs[0].Deletes() {
				t.Fatalf("directories %+v", dirs)
			}
		})
	}
}

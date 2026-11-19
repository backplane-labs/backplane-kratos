package tokenkeys

import (
	"context"
	"time"
)

// SetClock replaces the minted keys' clock.
func (m *Minted) SetClock(now func() time.Time) { m.now = now }

// Check runs one rotation check now.
func (m *Minted) Check(ctx context.Context) error {
	return m.tick(ctx)
}

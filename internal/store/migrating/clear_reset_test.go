package migrating

import (
	"context"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"
)

// TestClearResetTokenWithNothingOutstandingThroughTheWrapper: since core
// v0.16.0, POST /change-password clears the account's reset token on every
// change and logs a line whenever the clear fails. The wrapper is the user store
// the core holds while a migration runs, and ClearResetToken is the embedded
// store's, promoted unchanged — so a clear with nothing to clear succeeds here
// as it does there (internal/store/dynamodb
// TestClearResetTokenWithNothingOutstanding).
func TestClearResetTokenWithNothingOutstandingThroughTheWrapper(t *testing.T) {
	t.Parallel()
	m := newMigrating(t, newFakeDirectory())
	ctx := context.Background()

	var _ auth.UserPasswordStore = m
	created, err := m.CreateUser(ctx, auth.User{ID: "usr_clear" + randomHex(8), Email: uniqueEmail("clear")})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	for i := range 2 {
		if err := m.ClearResetToken(ctx, created.ID, created.TenantID); err != nil {
			t.Fatalf("clear %d with nothing outstanding, through the wrapper: %v", i, err)
		}
	}
}

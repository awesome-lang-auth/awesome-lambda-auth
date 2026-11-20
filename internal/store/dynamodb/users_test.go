package dynamodb

import (
	"context"
	"errors"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

func sampleUser(tenantID string) auth.User {
	// Fixed and safely in the past: UpdateProfile asserts the timestamp advanced
	// against the real clock.
	now := time.Date(2020, 3, 4, 5, 6, 7, 123456789, time.UTC)
	exp := now.Add(time.Hour)
	return auth.User{
		ID:                  uniqueID("usr"),
		Email:               uniqueEmail("sample"),
		PasswordHash:        "$2a$10$abcdefghijklmnopqrstuv",
		TenantID:            tenantID,
		PhoneNumber:         "+390123456789",
		FirstName:           "Ada",
		LastName:            "Lovelace",
		Role:                "admin",
		IsAdmin:             true,
		LoginProvider:       "google",
		IsEmailVerified:     true,
		Require2FA:          true,
		IsTOTPEnabled:       true,
		TOTPSecret:          "JBSWY3DPEHPK3PXP",
		ResetTokenHash:      hashOf("reset-token"),
		ResetTokenExpiresAt: &exp,
		PendingEmail:        "next@example.test",
		CreatedAt:           now,
		UpdatedAt:           now,
	}
}

func TestUserRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	want := sampleUser("acme")
	created, err := store.CreateUser(ctx, want)
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if created.ID != want.ID {
		t.Fatalf("created id = %q, want %q", created.ID, want.ID)
	}

	byID, err := store.GetUserByID(ctx, want.ID, "acme")
	if err != nil {
		t.Fatalf("get by id: %v", err)
	}
	byEmail, err := store.GetUserByEmail(ctx, want.Email, "acme")
	if err != nil {
		t.Fatalf("get by email: %v", err)
	}
	if byID.ID != byEmail.ID {
		t.Fatalf("by-id and by-email disagree: %q vs %q", byID.ID, byEmail.ID)
	}

	// Every scalar the profile item claims to carry must survive the round trip;
	// a silently dropped attribute is the failure mode this catches.
	if byID.Email != want.Email || byID.PasswordHash != want.PasswordHash ||
		byID.PhoneNumber != want.PhoneNumber || byID.FirstName != want.FirstName ||
		byID.LastName != want.LastName || byID.Role != want.Role ||
		byID.TOTPSecret != want.TOTPSecret || byID.PendingEmail != want.PendingEmail ||
		byID.ResetTokenHash != want.ResetTokenHash || byID.LoginProvider != want.LoginProvider {
		t.Fatalf("string fields lost: got %+v want %+v", byID, want)
	}
	// IsAdmin is in this list for a reason the others are not: it is the whole of
	// the admin router's 'is-admin-flag' access policy, so losing it is not a
	// cosmetic round-trip gap but a deployment in which nobody can administer
	// anything.
	if !byID.IsEmailVerified || !byID.Require2FA || !byID.IsTOTPEnabled || !byID.IsAdmin {
		t.Fatalf("bool fields lost: %+v", byID)
	}
	if !byID.CreatedAt.Equal(want.CreatedAt) {
		t.Fatalf("createdAt = %v, want %v", byID.CreatedAt, want.CreatedAt)
	}
	if byID.ResetTokenExpiresAt == nil || !byID.ResetTokenExpiresAt.Equal(*want.ResetTokenExpiresAt) {
		t.Fatalf("resetTokenExpiresAt = %v, want %v", byID.ResetTokenExpiresAt, want.ResetTokenExpiresAt)
	}
	// Nanosecond precision must survive: the fixed-width timestamp layout exists
	// so ordering works, and it must not cost resolution.
	if byID.CreatedAt.Nanosecond() != want.CreatedAt.Nanosecond() {
		t.Fatalf("nanoseconds lost: %d", byID.CreatedAt.Nanosecond())
	}
}

func TestCreateUserRejectsDuplicates(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	first := sampleUser("acme")
	if _, err := store.CreateUser(ctx, first); err != nil {
		t.Fatalf("create first: %v", err)
	}

	sameEmail := sampleUser("acme")
	sameEmail.Email = first.Email
	if _, err := store.CreateUser(ctx, sameEmail); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("duplicate email: err = %v, want ErrUserExists", err)
	}

	sameID := sampleUser("acme")
	sameID.ID = first.ID
	if _, err := store.CreateUser(ctx, sameID); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("duplicate id: err = %v, want ErrUserExists", err)
	}
}

func TestTenantIsolationIsInTheKey(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	shared := uniqueEmail("shared")
	a := sampleUser("tenant-a")
	a.Email = shared
	b := sampleUser("tenant-b")
	b.Email = shared

	if _, err := store.CreateUser(ctx, a); err != nil {
		t.Fatalf("create in tenant-a: %v", err)
	}
	// The same address in another tenant is a different key, so it must not
	// collide.
	if _, err := store.CreateUser(ctx, b); err != nil {
		t.Fatalf("same email in tenant-b must be allowed: %v", err)
	}

	got, err := store.GetUserByEmail(ctx, shared, "tenant-b")
	if err != nil {
		t.Fatalf("get by email in tenant-b: %v", err)
	}
	if got.ID != b.ID {
		t.Fatalf("tenant-b lookup returned %q, want %q", got.ID, b.ID)
	}

	// A user is invisible from the wrong tenant, exactly as in
	// memory_store.go:70 — but here because the partition key differs, not
	// because of a comparison after the read.
	if _, err := store.GetUserByID(ctx, a.ID, "tenant-b"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("cross-tenant get by id: err = %v, want ErrUserNotFound", err)
	}
	if _, err := store.GetUserByEmail(ctx, shared, "tenant-c"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown tenant: err = %v, want ErrUserNotFound", err)
	}
}

func TestEmptyTenantIsARealTenant(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	u := sampleUser("")
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create with empty tenant: %v", err)
	}
	if _, err := store.GetUserByID(ctx, u.ID, ""); err != nil {
		t.Fatalf("get with empty tenant: %v", err)
	}
	// "" must not behave as a wildcard.
	if _, err := store.GetUserByID(ctx, u.ID, "acme"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("empty tenant leaked into acme: err = %v", err)
	}
}

func TestMultiTenantRejectsEmptyTenant(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.MultiTenant = true })
	ctx := context.Background()

	if _, err := store.CreateUser(ctx, sampleUser("")); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("create with empty tenant: err = %v, want ErrTenantRequired", err)
	}
	if _, err := store.GetUserByID(ctx, uniqueID("usr"), ""); !errors.Is(err, ErrTenantRequired) {
		t.Fatalf("get with empty tenant: err = %v, want ErrTenantRequired", err)
	}
}

func TestIdentifiersThatWouldForgeAKeyAreRejected(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	// TENANT#a#b + USER#c and TENANT#a + USER#b#c are the same string. Without
	// this rejection one tenant could address another tenant's partition.
	u := sampleUser("acme#evil")
	if _, err := store.CreateUser(ctx, u); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("tenant containing '#': err = %v, want ErrInvalidIdentifier", err)
	}
	u = sampleUser("acme")
	u.ID = "usr#evil"
	if _, err := store.CreateUser(ctx, u); !errors.Is(err, ErrInvalidIdentifier) {
		t.Fatalf("user id containing '#': err = %v, want ErrInvalidIdentifier", err)
	}
	u = sampleUser("acme")
	u.Email = ""
	if _, err := store.CreateUser(ctx, u); !errors.Is(err, ErrInvalidEmail) {
		t.Fatalf("empty email: err = %v, want ErrInvalidEmail", err)
	}
}

func TestGetUserByEmailNormalizes(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	u := sampleUser("acme")
	u.Email = "MiXeD" + uniqueEmail("case")
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := store.GetUserByEmail(ctx, "  "+u.Email+" ", "acme"); err != nil {
		t.Fatalf("lookup with padding and mixed case: %v", err)
	}
}

func TestUpdateProfile(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	u := sampleUser("acme")
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}

	got, err := store.UpdateProfile(ctx, u.ID, "acme", "Grace", "Hopper")
	if err != nil {
		t.Fatalf("update profile: %v", err)
	}
	if got.FirstName != "Grace" || got.LastName != "Hopper" {
		t.Fatalf("names = %q %q", got.FirstName, got.LastName)
	}
	if !got.UpdatedAt.After(u.UpdatedAt) {
		t.Fatalf("updatedAt not advanced: %v", got.UpdatedAt)
	}
	// Untouched attributes must be untouched: this is an UpdateItem, not a Put.
	if got.PasswordHash != u.PasswordHash || got.TOTPSecret != u.TOTPSecret {
		t.Fatalf("unrelated attributes changed: %+v", got)
	}

	// An empty name removes the attribute rather than writing "".
	if _, err := store.UpdateProfile(ctx, u.ID, "acme", "", ""); err != nil {
		t.Fatalf("clear names: %v", err)
	}
	raw := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)
	if _, present := raw[attrFirstName]; present {
		t.Fatalf("firstName should have been removed, got %v", raw[attrFirstName])
	}

	if _, err := store.UpdateProfile(ctx, uniqueID("usr"), "acme", "a", "b"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("update missing user: err = %v, want ErrUserNotFound", err)
	}
}

func TestDeleteUserSweepsEverythingItWrote(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	u := sampleUser("acme")
	u.ResetTokenHash = ""
	u.ResetTokenExpiresAt = nil
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	resetHash := hashOf("to-be-deleted")
	if err := store.UpdateResetToken(ctx, u.ID, "acme", resetHash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue reset token: %v", err)
	}
	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}

	if err := store.DeleteUser(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	mustNotExist(t, client, store.table, userPK("acme", u.ID), skProfile)
	mustNotExist(t, client, store.table, emailPK("acme", u.Email), skEmail)
	mustNotExist(t, client, store.table, tenantPK("acme"), memberSK(u.ID))
	mustNotExist(t, client, store.table, familyReset.pk(resetHash), skToken)
	mustNotExist(t, client, store.table, sessionPK(sess.ID), skSession)

	if err := store.DeleteUser(ctx, u.ID, "acme"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("second delete: err = %v, want ErrUserNotFound", err)
	}
}

func TestCreateUserWritesTheMembership(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	u := sampleUser("acme")
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	member := rawItem(t, client, store.table, tenantPK("acme"), memberSK(u.ID))
	if len(member) == 0 {
		t.Fatal("membership item missing; GetTenantsForUser would have nothing to read")
	}
	if got := getS(member, attrGSI1PK); got != gsi1UserID(u.ID) {
		t.Fatalf("membership GSI1PK = %q, want %q", got, gsi1UserID(u.ID))
	}
}

// TestGetUserByIDNotFoundMatchesTheCoreSentinel: since awesome-go-auth v0.13.0
// (#31) the core tells a missing user from a store that failed by
// auth.ErrUserNotFound, so the by-id read answers an error that matches it as
// well as this package's ErrUserNotFound, with the message unchanged. The
// lookup by address keeps the bare sentinel.
func TestGetUserByIDNotFoundMatchesTheCoreSentinel(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	_, err := store.GetUserByID(ctx, uniqueID("usr"), "acme")
	if !errors.Is(err, ErrUserNotFound) || !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("GetUserByID for a missing user: err = %v, want it to match ErrUserNotFound and auth.ErrUserNotFound", err)
	}
	if err.Error() != "user not found" {
		t.Errorf("message = %q, want the unchanged %q", err.Error(), "user not found")
	}

	_, err = store.GetUserByEmail(ctx, uniqueEmail("nobody"), "acme")
	if !errors.Is(err, ErrUserNotFound) || errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("GetUserByEmail for a missing user: err = %v, want the bare ErrUserNotFound only", err)
	}
}

package dynamodb

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// TestUpdateIsAdminWritesTheFlagAndNothingElse: the writer sets the one field
// the 'is-admin-flag' policy reads, leaves every other attribute where it was,
// and adds nothing to the index — the profile's GSI entry is paid for once, at
// registration, and a flag flip must not turn it into a second index write.
func TestUpdateIsAdminWritesTheFlagAndNothingElse(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	u := sampleUser("acme")
	u.IsAdmin = false
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	before := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)

	if err := store.UpdateIsAdmin(ctx, u.ID, "acme", true); err != nil {
		t.Fatalf("UpdateIsAdmin: %v", err)
	}

	got, err := store.GetUserByID(ctx, u.ID, "acme")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if !got.IsAdmin {
		t.Fatal("IsAdmin is still false after UpdateIsAdmin(true)")
	}
	if got.Role != u.Role || got.Email != u.Email || got.PasswordHash != u.PasswordHash {
		t.Errorf("the write touched more than the flag: %+v", got)
	}

	after := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)
	for _, attr := range []string{attrGSI1PK, attrGSI1SK, attrPasswordHash, attrTOTPSecret, attrRole} {
		if !attributeEqual(before[attr], after[attr]) {
			t.Errorf("attribute %s changed across a flag write: %v -> %v", attr, before[attr], after[attr])
		}
	}
	if getS(after, attrUpdatedAt) == getS(before, attrUpdatedAt) {
		t.Error("updatedAt did not advance; every profile writer stamps it")
	}

	// And back again: a false is written, not removed, because that is what
	// registration writes for the same field (profileItem's b() has no
	// omission rule).
	if err := store.UpdateIsAdmin(ctx, u.ID, "acme", false); err != nil {
		t.Fatalf("UpdateIsAdmin(false): %v", err)
	}
	cleared := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)
	if av, ok := cleared[attrIsAdmin].(*types.AttributeValueMemberBOOL); !ok || av.Value {
		t.Errorf("isAdmin after UpdateIsAdmin(false) = %v, want a stored false", cleared[attrIsAdmin])
	}
}

// TestUpdateRequire2FAIsReadBackByTheProfile pins the second writer the same
// way, through the codec: the console's 2FA-policy tab sets the flag and the
// login path reads it off the same item.
func TestUpdateRequire2FAIsReadBackByTheProfile(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	u := sampleUser("")
	u.Require2FA = false
	if _, err := store.CreateUser(ctx, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := store.UpdateRequire2FA(ctx, u.ID, "", true); err != nil {
		t.Fatalf("UpdateRequire2FA: %v", err)
	}
	got, err := store.GetUserByID(ctx, u.ID, "")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if !got.Require2FA {
		t.Fatal("Require2FA is still false after UpdateRequire2FA(true)")
	}
}

// TestProfileFlagWritersRefuseAMissingUser: UpdateItem creates a missing item,
// so without the condition a flag set on an unregistered id would manufacture a
// profile holding nothing but a boolean. The answer is the memory store's own.
func TestProfileFlagWritersRefuseAMissingUser(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"UpdateIsAdmin":    func() error { return store.UpdateIsAdmin(ctx, "usr_nobody", "acme", true) },
		"UpdateRequire2FA": func() error { return store.UpdateRequire2FA(ctx, "usr_nobody", "acme", true) },
	} {
		if err := call(); !errors.Is(err, ErrUserNotFound) {
			t.Errorf("%s on a missing user: err = %v, want ErrUserNotFound", name, err)
		}
	}
	mustNotExist(t, client, store.table, userPK("acme", "usr_nobody"), skProfile)
}

// attributeEqual compares two scalar attribute values, treating two absences as
// equal. It is enough for the attributes these tests compare, which are strings
// and booleans.
func attributeEqual(a, b types.AttributeValue) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case *types.AttributeValueMemberS:
		y, ok := b.(*types.AttributeValueMemberS)
		return ok && x.Value == y.Value
	case *types.AttributeValueMemberBOOL:
		y, ok := b.(*types.AttributeValueMemberBOOL)
		return ok && x.Value == y.Value
	default:
		return false
	}
}

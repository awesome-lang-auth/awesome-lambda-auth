package dynamodb

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	auth "github.com/nik2208/awesome-go-auth"
)

// putLegacyUser writes a user the way createUser did before the by-id pointer
// existed: profile (with its GSI1 directory attributes, which D6 already
// wrote), email-uniqueness item and membership, and no pointer and no stamp.
// Straight through the client, because createUser would now write the pointer
// — and refuse the second half of a same-id pair, which is exactly the state a
// table written before this release can be in.
func putLegacyUser(t *testing.T, client *awsddb.Client, store *Store, u auth.User) {
	t.Helper()
	ctx := context.Background()
	profile := profileItem(u)
	delete(profile, attrUIDPointer)
	email := item{}.
		sAlways(attrPK, emailPK(u.TenantID, normalizeEmail(u.Email))).
		sAlways(attrSK, skEmail).
		stamp(typeEmail).
		sAlways(attrUserID, u.ID).
		sAlways(attrTenantID, u.TenantID)
	for _, it := range []item{profile, email, store.membershipItem(u.ID, u.TenantID)} {
		if _, err := client.PutItem(ctx, &awsddb.PutItemInput{TableName: aws.String(store.table), Item: it}); err != nil {
			t.Fatalf("put legacy item for %s/%s: %v", u.TenantID, u.ID, err)
		}
	}
}

// TestFindUserByIDSpansTenants is the interface's whole job: one id, no tenant,
// and the user comes back with its own TenantID, from whichever tenant holds it
// — the empty one included.
func TestFindUserByIDSpansTenants(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for _, tenant := range []string{"", "acme", "globex"} {
		u := newUser(t, store, tenant)
		got, err := store.FindUserByID(ctx, u.ID)
		if err != nil {
			t.Fatalf("FindUserByID(%s) under tenant %q: %v", u.ID, tenant, err)
		}
		if got.ID != u.ID || got.TenantID != tenant || got.Email != u.Email {
			t.Errorf("FindUserByID(%s) = %s/%s %q, want %q/%s %q", u.ID, got.TenantID, got.ID, got.Email, tenant, u.ID, u.Email)
		}
	}

	if _, err := store.FindUserByID(ctx, uniqueID("usr")); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown id: err = %v, want ErrUserNotFound", err)
	}
	if _, err := store.FindUserByID(ctx, "usr#forged"); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("forged id: err = %v, want ErrInvalidIdentifier", err)
	}
}

// TestFindUserByIDFilesNoMigrationMarker: the profile is read directly, not
// through GetUserByID, so the request-scoped marker the login path reads is
// never filed by a console lookup.
func TestFindUserByIDFilesNoMigrationMarker(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	u := newUser(t, store, "acme")

	ctx := WithMigrationScope(context.Background())
	if _, err := store.FindUserByID(ctx, u.ID); err != nil {
		t.Fatalf("FindUserByID: %v", err)
	}
	if _, read := TakeMigrationMarker(ctx, u.ID); read {
		t.Error("FindUserByID filed a migration marker; it must read the profile without the login path's side effect")
	}
}

// TestCreateUserRefusesAnIDAnotherTenantHolds: the precondition the interface
// rests on, enforced where MemoryUserStore enforces it.
func TestCreateUserRefusesAnIDAnotherTenantHolds(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	first := newUser(t, store, "acme")
	second := sampleUser("globex")
	second.ID = first.ID
	if _, err := store.CreateUser(ctx, second); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("same id under another tenant: err = %v, want ErrUserExists", err)
	}
	// Refused whole: nothing of the second registration is left behind, and the
	// pointer still names the first.
	mustNotExist(t, client, store.table, userPK("globex", first.ID), skProfile)
	mustNotExist(t, client, store.table, emailPK("globex", normalizeEmail(second.Email)), skEmail)
	if got := getS(rawItem(t, client, store.table, uidPK(first.ID), skUID), attrTenantID); got != "acme" {
		t.Errorf("pointer tenantId = %q after the refused registration, want acme", got)
	}
	got, err := store.FindUserByID(ctx, first.ID)
	if err != nil || got.TenantID != "acme" {
		t.Errorf("FindUserByID = %+v, %v; want the acme user", got, err)
	}
}

// TestDeleteUserRemovesThePointerAndOnlyItsOwn: DeleteUser takes the pointer
// with the profile when the pointer names that tenant, and leaves it alone when
// it names another — the same-id record a table written before this release can
// hold.
func TestDeleteUserRemovesThePointerAndOnlyItsOwn(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	owner := newUser(t, store, "acme")
	stray := sampleUser("globex")
	stray.ID = owner.ID
	putLegacyUser(t, client, store, stray)

	// The stray record goes; the pointer is acme's and survives it.
	if err := store.DeleteUser(ctx, owner.ID, "globex"); err != nil {
		t.Fatalf("delete the globex record: %v", err)
	}
	mustNotExist(t, client, store.table, userPK("globex", owner.ID), skProfile)
	if got := getS(rawItem(t, client, store.table, uidPK(owner.ID), skUID), attrTenantID); got != "acme" {
		t.Fatalf("deleting the globex record left the pointer naming %q, want acme", got)
	}
	if got, err := store.FindUserByID(ctx, owner.ID); err != nil || got.TenantID != "acme" {
		t.Fatalf("FindUserByID after the stray delete = %+v, %v; want the acme user", got, err)
	}

	// The owner goes, and the pointer with it, so the id is free again — under
	// any tenant.
	if err := store.DeleteUser(ctx, owner.ID, "acme"); err != nil {
		t.Fatalf("delete the acme record: %v", err)
	}
	mustNotExist(t, client, store.table, uidPK(owner.ID), skUID)
	if _, err := store.FindUserByID(ctx, owner.ID); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("FindUserByID after delete: err = %v, want ErrUserNotFound", err)
	}
	again := sampleUser("globex")
	again.ID = owner.ID
	if _, err := store.CreateUser(ctx, again); err != nil {
		t.Errorf("the deleted id could not be registered under another tenant: %v", err)
	}
}

// TestFindUserByIDFallsBackToTheEmptyTenantBeforeTheBackfill is the decision on
// existing tables (decisions D-22): a profile written before pointers existed is
// found if it lives under the empty tenant — what the console's detail route
// answered on core v0.11.0 — and is not found under another, until the backfill
// has run. In multi-tenant mode nobody lives under the empty tenant, so the
// fallback does not run there: the same unpointed "" profile is not found.
func TestFindUserByIDFallsBackToTheEmptyTenantBeforeTheBackfill(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	home := sampleUser("")
	tenanted := sampleUser("acme")
	putLegacyUser(t, client, store, home)
	putLegacyUser(t, client, store, tenanted)

	if got, err := store.FindUserByID(ctx, home.ID); err != nil || got.ID != home.ID {
		t.Errorf("unpointed empty-tenant user = %+v, %v; want it found, as on v0.11.0", got, err)
	}
	if _, err := store.FindUserByID(ctx, tenanted.ID); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unpointed tenanted user: err = %v, want ErrUserNotFound until the backfill", err)
	}

	// The same unpointed "" profile, asked of a multi-tenant store over the
	// same table: the fallback is what would find it, and in that mode it must
	// not run — so this, and only this, is what tells the branch apart.
	multi, err := New(client, Options{TableName: store.table, MultiTenant: true})
	if err != nil {
		t.Fatalf("new multi-tenant store: %v", err)
	}
	if got, err := multi.FindUserByID(ctx, home.ID); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("multi-tenant miss on an unpointed \"\" profile = %+v, %v; want ErrUserNotFound, not the fallback's answer", got, err)
	}

	sweep(t, client, BackfillOptions{TableName: store.table})
	if got, err := store.FindUserByID(ctx, tenanted.ID); err != nil || got.TenantID != "acme" {
		t.Errorf("after the backfill = %+v, %v; want the acme user", got, err)
	}
}

// TestBackfillWritesPointersIdempotently: unpointed profiles get their pointer
// and stamp, a second sweep matches nothing, and the pointers name the right
// tenant.
func TestBackfillWritesPointersIdempotently(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	var legacy []auth.User
	for _, tenant := range []string{"", "acme", "acme", "globex"} {
		u := sampleUser(tenant)
		putLegacyUser(t, client, store, u)
		legacy = append(legacy, u)
	}
	fresh := newUser(t, store, "acme")

	_, dry := sweep(t, client, BackfillOptions{TableName: store.table, DryRun: true})
	if dry.PointerMatched != len(legacy) || len(dry.PlannedPointers) != len(legacy) || dry.PointersWritten != 0 {
		t.Fatalf("dry run matched %d, planned %v, wrote %d; want the %d legacy profiles planned and nothing written",
			dry.PointerMatched, dry.PlannedPointers, dry.PointersWritten, len(legacy))
	}
	mustNotExist(t, client, store.table, uidPK(legacy[1].ID), skUID)

	_, first := sweep(t, client, BackfillOptions{TableName: store.table, PageSize: 2})
	if first.PointersWritten != len(legacy) || len(first.Conflicts) != 0 {
		t.Fatalf("first sweep wrote %d pointers with conflicts %v, want %d and none", first.PointersWritten, first.Conflicts, len(legacy))
	}
	// D6's half had nothing to do: these profiles already carry the index.
	if first.Matched != 0 || first.Written != 0 {
		t.Errorf("first sweep indexed %d of %d matched; the legacy profiles were already in the directory", first.Written, first.Matched)
	}
	for _, u := range append(legacy, fresh) {
		got, err := store.FindUserByID(ctx, u.ID)
		if err != nil || got.TenantID != u.TenantID {
			t.Errorf("FindUserByID(%s) = %+v, %v; want tenant %q", u.ID, got, err, u.TenantID)
		}
		if !getBool(rawItem(t, client, store.table, userPK(u.TenantID, u.ID), skProfile), attrUIDPointer) {
			t.Errorf("%s/%s: no pointer stamp after the sweep", u.TenantID, u.ID)
		}
	}

	_, second := sweep(t, client, BackfillOptions{TableName: store.table})
	if second.PointerMatched != 0 || second.PointersWritten != 0 || second.Matched != 0 {
		t.Errorf("second sweep matched %d and wrote %d pointers; a swept table must match nothing", second.PointerMatched, second.PointersWritten)
	}
}

// TestBackfillConflictLeavesTheIDAnsweringAnError: two legacy profiles share an
// id. The sweep points the id at the first it meets and, meeting the second,
// does not overwrite — it marks the pointer ambiguous, and from then on
// FindUserByID answers an error rather than either record, CreateUser refuses
// the id, DeleteUser of one half leaves the mark, and every later sweep reports
// the conflict again without writing.
func TestBackfillConflictLeavesTheIDAnsweringAnError(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	a := sampleUser("t1")
	b := sampleUser("t2")
	b.ID = a.ID
	putLegacyUser(t, client, store, a)
	putLegacyUser(t, client, store, b)

	_, dry := sweep(t, client, BackfillOptions{TableName: store.table, DryRun: true})
	if dry.PointersWritten != 0 {
		t.Fatalf("dry run wrote %d pointers", dry.PointersWritten)
	}
	mustNotExist(t, client, store.table, uidPK(a.ID), skUID)

	_, first := sweep(t, client, BackfillOptions{TableName: store.table})
	if first.PointersWritten != 1 || len(first.Conflicts) != 1 {
		t.Fatalf("first sweep wrote %d pointers and found conflicts %v; want one pointer and one conflict", first.PointersWritten, first.Conflicts)
	}
	if c := first.Conflicts[0]; c.UserID != a.ID || c.AlreadyAmbiguous || c.TenantID == c.PointerTenantID {
		t.Errorf("conflict = %+v, want both tenants of %s named", c, a.ID)
	}
	if !getBool(rawItem(t, client, store.table, uidPK(a.ID), skUID), attrAmbiguous) {
		t.Fatal("the pointer is not marked ambiguous")
	}

	if _, err := store.FindUserByID(ctx, a.ID); !errors.Is(err, ErrUserIDAmbiguous) {
		t.Fatalf("FindUserByID of a conflicted id: err = %v, want ErrUserIDAmbiguous", err)
	}
	third := sampleUser("t3")
	third.ID = a.ID
	if _, err := store.CreateUser(ctx, third); !errors.Is(err, auth.ErrUserExists) {
		t.Errorf("registering a conflicted id: err = %v, want ErrUserExists", err)
	}

	// Both halves are unstamped, so every later run reports both and writes
	// nothing.
	_, second := sweep(t, client, BackfillOptions{TableName: store.table})
	if second.PointersWritten != 0 || len(second.Conflicts) != 2 {
		t.Fatalf("second sweep wrote %d and reported %v; want nothing written and both halves reported", second.PointersWritten, second.Conflicts)
	}
	for _, c := range second.Conflicts {
		if !c.AlreadyAmbiguous {
			t.Errorf("second-run conflict %+v is not reported as already marked", c)
		}
	}

	// Deleting one half does not say the other is the right one: the mark
	// stays, and the survivor still answers the error.
	if err := store.DeleteUser(ctx, a.ID, "t2"); err != nil {
		t.Fatalf("delete one half: %v", err)
	}
	if _, err := store.FindUserByID(ctx, a.ID); !errors.Is(err, ErrUserIDAmbiguous) {
		t.Errorf("after deleting one half: err = %v, want ErrUserIDAmbiguous until an operator clears the mark", err)
	}

	// The operator's step (config-reference §16.6): delete the pointer, sweep
	// again, and the survivor is pointed.
	if _, err := client.DeleteItem(ctx, &awsddb.DeleteItemInput{TableName: aws.String(store.table), Key: key(uidPK(a.ID), skUID)}); err != nil {
		t.Fatalf("delete the pointer: %v", err)
	}
	_, healed := sweep(t, client, BackfillOptions{TableName: store.table})
	if healed.PointersWritten != 1 || len(healed.Conflicts) != 0 {
		t.Fatalf("resolving sweep wrote %d and reported %v; want the survivor pointed", healed.PointersWritten, healed.Conflicts)
	}
	if got, err := store.FindUserByID(ctx, a.ID); err != nil || got.TenantID != "t1" {
		t.Errorf("after resolution = %+v, %v; want the t1 survivor", got, err)
	}
}

// TestBackfillDoesNotStrandAPointerForAProfileDeletedMeanwhile: the pointer is
// written in one transaction with the profile's stamp, guarded by the profile
// existing, so a delete between the scan and the write leaves nothing behind.
func TestBackfillDoesNotStrandAPointerForAProfileDeletedMeanwhile(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)

	u := sampleUser("acme")
	putLegacyUser(t, client, store, u)

	racing := &deletingAPI{Client: client, store: store, user: u}
	_, total := sweep(t, racing, BackfillOptions{TableName: store.table})
	if total.PointerMatched != 1 || total.PointersSkipped != 1 || total.PointersWritten != 0 {
		t.Fatalf("matched %d, skipped %d, written %d; want the deleted profile skipped", total.PointerMatched, total.PointersSkipped, total.PointersWritten)
	}
	mustNotExist(t, client, store.table, uidPK(u.ID), skUID)
}

// deletingAPI deletes the scanned user right after the first Scan, the state a
// concurrent DELETE /account would leave.
type deletingAPI struct {
	*awsddb.Client
	store *Store
	user  auth.User
	done  bool
}

func (d *deletingAPI) Scan(ctx context.Context, in *awsddb.ScanInput, optFns ...func(*awsddb.Options)) (*awsddb.ScanOutput, error) {
	out, err := d.Client.Scan(ctx, in, optFns...)
	if err != nil || d.done {
		return out, err
	}
	d.done = true
	if err := d.store.DeleteUser(ctx, d.user.ID, d.user.TenantID); err != nil {
		return nil, err
	}
	return out, nil
}

// afterPointerRead runs hook once, right after the first strongly-consistent
// read of one id's pointer has returned — the window between a read and the
// transaction that re-asserts it, which is what the races below live in.
type afterPointerRead struct {
	*awsddb.Client
	userID string
	hook   func(ctx context.Context)
	done   bool
}

func (a *afterPointerRead) GetItem(ctx context.Context, in *awsddb.GetItemInput, optFns ...func(*awsddb.Options)) (*awsddb.GetItemOutput, error) {
	out, err := a.Client.GetItem(ctx, in, optFns...)
	if err != nil || a.done || getS(in.Key, attrPK) != uidPK(a.userID) {
		return out, err
	}
	a.done = true
	a.hook(ctx)
	return out, nil
}

// TestBackfillDoesNotMarkAnIDWhoseSweptProfileWasDeleted: the sweep reads a
// pointer naming another tenant — a conflict, as read — and the swept profile
// is deleted before the mark lands, by a DeleteUser or simply because the
// eventually-consistent Scan returned it after it was gone. One record holds
// the id, so marking it would answer an error for the one user who is not in
// conflict; the mark's transaction asserts the swept profile and is cancelled.
func TestBackfillDoesNotMarkAnIDWhoseSweptProfileWasDeleted(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	owner := newUser(t, store, "t1")
	stray := sampleUser("t2")
	stray.ID = owner.ID
	putLegacyUser(t, client, store, stray)

	racing := &afterPointerRead{Client: client, userID: owner.ID, hook: func(ctx context.Context) {
		if err := store.DeleteUser(ctx, stray.ID, "t2"); err != nil {
			t.Errorf("delete the stray record mid-sweep: %v", err)
		}
	}}
	_, total := sweep(t, racing, BackfillOptions{TableName: store.table})
	if !racing.done {
		t.Fatal("the sweep never read the pointer; the race was not staged")
	}
	if len(total.Conflicts) != 0 || total.PointersSkipped != 1 {
		t.Fatalf("conflicts %v, pointers skipped %d; want no conflict and the deleted profile skipped", total.Conflicts, total.PointersSkipped)
	}
	ptr := rawItem(t, client, store.table, uidPK(owner.ID), skUID)
	if getBool(ptr, attrAmbiguous) || getS(ptr, attrTenantID) != "t1" {
		t.Fatalf("pointer = %v; want it naming t1 and not marked", ptr)
	}
	if got, err := store.FindUserByID(ctx, owner.ID); err != nil || got.TenantID != "t1" {
		t.Errorf("FindUserByID = %+v, %v; want the t1 user", got, err)
	}
}

// TestDeleteUserDoesNotStrandAPointerThatMovedToItsRecord: DeleteUser of one
// half of a same-id pair reads the pointer naming the other half, and before
// its transaction lands the other half is deleted (freeing the id) and the
// sweep points the id at this very record. Left unasserted, the profile delete
// would strand that pointer — naming nothing, refusing the id to every tenant,
// and invisible to a sweep that scans profiles. The no-op Update on the pointer
// cancels the transaction, the retry sees the pointer is now this record's, and
// both go together.
func TestDeleteUserDoesNotStrandAPointerThatMovedToItsRecord(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	owner := newUser(t, store, "t1")
	stray := sampleUser("t2")
	stray.ID = owner.ID
	putLegacyUser(t, client, store, stray)

	api := &afterPointerRead{Client: client, userID: owner.ID, hook: func(ctx context.Context) {
		if err := store.DeleteUser(ctx, owner.ID, "t1"); err != nil {
			t.Errorf("delete the t1 record mid-delete: %v", err)
			return
		}
		_, total := sweep(t, client, BackfillOptions{TableName: store.table})
		if total.PointersWritten != 1 {
			t.Errorf("the mid-delete sweep wrote %d pointers, want the t2 record pointed", total.PointersWritten)
		}
	}}
	racing, err := New(api, Options{TableName: store.table})
	if err != nil {
		t.Fatalf("new racing store: %v", err)
	}
	if err := racing.DeleteUser(ctx, stray.ID, "t2"); err != nil {
		t.Fatalf("delete the t2 record: %v", err)
	}
	if !api.done {
		t.Fatal("DeleteUser never read the pointer; the race was not staged")
	}
	mustNotExist(t, client, store.table, userPK("t2", stray.ID), skProfile)
	mustNotExist(t, client, store.table, uidPK(stray.ID), skUID)
	again := sampleUser("globex")
	again.ID = owner.ID
	if _, err := store.CreateUser(ctx, again); err != nil {
		t.Errorf("the id is not free after both records went: %v", err)
	}
}

// TestDeleteUserOfAnUnpointedProfileLeavesNoPointer: the pre-backfill path —
// no pointer to own — deletes the profile and asserts the pointer still absent
// with a conditional Delete, which is what the function's role can authorise
// (TestUserTransactionsUseOnlyGrantedActions). A pointer the sweep writes in
// between cancels it, and the retry takes the pointer with the profile.
func TestDeleteUserOfAnUnpointedProfileLeavesNoPointer(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	u := sampleUser("acme")
	putLegacyUser(t, client, store, u)

	api := &afterPointerRead{Client: client, userID: u.ID, hook: func(context.Context) {
		if _, total := sweep(t, client, BackfillOptions{TableName: store.table}); total.PointersWritten != 1 {
			t.Errorf("the mid-delete sweep wrote %d pointers, want the profile pointed", total.PointersWritten)
		}
	}}
	racing, err := New(api, Options{TableName: store.table})
	if err != nil {
		t.Fatalf("new racing store: %v", err)
	}
	if err := racing.DeleteUser(ctx, u.ID, "acme"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	mustNotExist(t, client, store.table, userPK("acme", u.ID), skProfile)
	mustNotExist(t, client, store.table, uidPK(u.ID), skUID)
}

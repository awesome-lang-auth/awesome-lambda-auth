package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The three v0.8.0 admin listers share a contract that is easy to implement
// almost-right, so these tests assert the parts a caller actually depends on
// rather than the happy path: the total order, the paging rules stated once in
// the core's store.go and binding on all three, and the one order that could not
// be reproduced and is registered instead.

// newAdminUser mints a profile with a deterministic id, so a test can assert an
// order rather than discover one. The prefix keeps ids inside idPattern. The
// tenant is in the id because one id names one user across every tenant
// (CreateUser refuses a second, user_lookup.go), so two tenants seeded with
// the same n would otherwise collide.
func newAdminUser(tenantID string, n int) auth.User {
	tag := ""
	if tenantID != "" {
		tag = tenantID + "_"
	}
	return auth.User{
		ID:       fmt.Sprintf("usr_%s%04d", tag, n),
		Email:    uniqueEmail("admin"),
		TenantID: tenantID,
	}
}

func seedUsers(t *testing.T, store *Store, tenantID string, n int) []auth.User {
	t.Helper()
	ctx := context.Background()
	out := make([]auth.User, 0, n)
	for i := range n {
		u := newAdminUser(tenantID, i)
		if _, err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("create user %s: %v", u.ID, err)
		}
		out = append(out, u)
	}
	return out
}

func userIDs(users []auth.User) []string {
	out := make([]string, 0, len(users))
	for _, u := range users {
		out = append(out, u.ID)
	}
	return out
}

// TestListUsersScopedIsIDAscending pins the order inside one tenant, which is
// the core's normative order exactly — the deviation below applies only to the
// unscoped form.
func TestListUsersScopedIsIDAscending(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	seedUsers(t, store, "acme", 5)
	seedUsers(t, store, "globex", 3)

	got, err := store.ListUsers(ctx, "acme", 100, 0)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	want := []string{"usr_acme_0000", "usr_acme_0001", "usr_acme_0002", "usr_acme_0003", "usr_acme_0004"}
	if fmt.Sprint(userIDs(got)) != fmt.Sprint(want) {
		t.Fatalf("scoped listing = %v, want %v", userIDs(got), want)
	}
	for _, u := range got {
		if u.TenantID != "acme" {
			t.Fatalf("tenant %q leaked into the acme listing: %+v", u.TenantID, u)
		}
	}
}

// TestListUsersScopeCannotReachAPrefixedTenant is the reason tenant ids may not
// contain '#': begins_with("acme#") must not reach "acmecorp".
func TestListUsersScopeCannotReachAPrefixedTenant(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	seedUsers(t, store, "acme", 2)
	seedUsers(t, store, "acmecorp", 2)

	got, err := store.ListUsers(ctx, "acme", 100, 0)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("acme listing returned %d users, want 2: %v", len(got), userIDs(got))
	}
	for _, u := range got {
		if u.TenantID != "acme" {
			t.Fatalf("acmecorp leaked into the acme listing: %+v", u)
		}
	}
}

// TestListUsersUnscopedIsTenantThenID pins the registered deviation. The
// reference's order is ID ascending; a <tenantID>#<id> sort key cannot produce
// it across tenants, the upstream author predicted that, and CompatibilityNotes
// carries it. This test exists so the day the order changes, the register and
// the behaviour are made to disagree loudly.
func TestListUsersUnscopedIsTenantThenID(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	// Interleaved on purpose: ID-ascending and (tenant, ID)-ascending give
	// different answers for this set, which is what makes the assertion mean
	// something.
	for _, u := range []auth.User{
		{ID: "usr_0003", TenantID: "acme", Email: uniqueEmail("a")},
		{ID: "usr_0001", TenantID: "globex", Email: uniqueEmail("b")},
		{ID: "usr_0004", TenantID: "acme", Email: uniqueEmail("c")},
		{ID: "usr_0002", TenantID: "globex", Email: uniqueEmail("d")},
	} {
		if _, err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("create %s: %v", u.ID, err)
		}
	}

	got, err := store.ListUsers(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	want := []string{"usr_0003", "usr_0004", "usr_0001", "usr_0002"}
	if fmt.Sprint(userIDs(got)) != fmt.Sprint(want) {
		t.Fatalf("unscoped listing = %v, want (tenant, id) order %v", userIDs(got), want)
	}
}

// TestListUsersEmptyTenantIsAWildcardNotALiteral is the one place in this
// package where an empty tenant means "no filter". Every other method treats ""
// as an ordinary tenant value addressing its own partition.
func TestListUsersEmptyTenantIsAWildcardNotALiteral(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	seedUsers(t, store, "", 2)
	seedUsers(t, store, "acme", 2)

	got, err := store.ListUsers(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("wildcard listing returned %d users, want every one of the 4: %v", len(got), userIDs(got))
	}
}

// TestListUsersMultiTenantDoesNotRefuseTheWildcard: checkTenant refuses an empty
// tenant when multi-tenancy is on, and this method deliberately does not go
// through it — refusing here would make the admin user list unusable in exactly
// the deployment that has more than one tenant.
func TestListUsersMultiTenantDoesNotRefuseTheWildcard(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.MultiTenant = true })
	ctx := context.Background()

	seedUsers(t, store, "acme", 2)

	got, err := store.ListUsers(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("wildcard listing refused under multi-tenancy: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("wildcard listing returned %d users, want 2", len(got))
	}
}

// TestAdminListerPagingRules covers the rules the core states once and binds to
// all three listers. They are asserted together because the failure they guard
// against is shared: the reference's 2fa-policy walk steps in pages of 100 until
// a page comes back short, so a store that answers a non-positive limit with
// "everything", or shortens a page for any reason but the end of the list, turns
// that walk into a full-table update or a silent skip.
func TestAdminListerPagingRules(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	seedUsers(t, store, "acme", 7)

	t.Run("non-positive limit is an empty page and no error", func(t *testing.T) {
		for _, limit := range []int{0, -1} {
			got, err := store.ListUsers(ctx, "acme", limit, 0)
			if err != nil {
				t.Fatalf("limit %d: %v", limit, err)
			}
			if len(got) != 0 {
				t.Fatalf("limit %d returned %d users, want none", limit, len(got))
			}
		}
	})

	t.Run("negative offset reads as zero", func(t *testing.T) {
		got, err := store.ListUsers(ctx, "acme", 2, -5)
		if err != nil {
			t.Fatalf("negative offset: %v", err)
		}
		if fmt.Sprint(userIDs(got)) != fmt.Sprint([]string{"usr_acme_0000", "usr_acme_0001"}) {
			t.Fatalf("negative offset returned %v, want the first page", userIDs(got))
		}
	})

	t.Run("offset past the end is empty, not an error", func(t *testing.T) {
		got, err := store.ListUsers(ctx, "acme", 10, 50)
		if err != nil {
			t.Fatalf("offset past end: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("offset past end returned %d users, want none", len(got))
		}
	})

	t.Run("paging covers every user exactly once", func(t *testing.T) {
		seen := map[string]int{}
		for offset := 0; ; offset += 3 {
			page, err := store.ListUsers(ctx, "acme", 3, offset)
			if err != nil {
				t.Fatalf("page at offset %d: %v", offset, err)
			}
			for _, u := range page {
				seen[u.ID]++
			}
			// The walk's own termination condition, asserted as the walk uses it.
			if len(page) < 3 {
				break
			}
		}
		if len(seen) != 7 {
			t.Fatalf("walk saw %d distinct users, want 7: %v", len(seen), seen)
		}
		for id, n := range seen {
			if n != 1 {
				t.Fatalf("walk saw %s %d times, want once", id, n)
			}
		}
	})

	t.Run("the paging window has a ceiling", func(t *testing.T) {
		_, err := store.ListUsers(ctx, "acme", 100, DefaultMaxPageWindow)
		if !errors.Is(err, ErrPageWindowTooLarge) {
			t.Fatalf("offset past the window = %v, want ErrPageWindowTooLarge", err)
		}
	})
}

// TestGetAllSessionsIsIDAscending pins SessionLister's order, which the session
// directory reproduces exactly — its sort key is the session id — so unlike
// ListUsers there is no deviation to register here.
func TestGetAllSessionsIsIDAscending(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	user := sampleUser("acme")
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	var want []string
	// Created out of order, so an implementation that answered in creation order
	// would fail.
	for _, n := range []int{4, 1, 3, 2, 0} {
		id := fmt.Sprintf("ses_%04d", n)
		if _, err := store.CreateSession(ctx, auth.Session{
			ID:               id,
			UserID:           user.ID,
			TenantID:         "acme",
			RefreshTokenHash: hashOf(id),
			CreatedAt:        time.Now().UTC(),
			ExpiresAt:        time.Now().UTC().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create session %s: %v", id, err)
		}
		want = append(want, id)
	}
	sort.Strings(want)

	got, err := store.GetAllSessions(ctx, 100, 0)
	if err != nil {
		t.Fatalf("get all sessions: %v", err)
	}
	var ids []string
	for _, s := range got {
		ids = append(ids, s.ID)
	}
	if fmt.Sprint(ids) != fmt.Sprint(want) {
		t.Fatalf("GetAllSessions = %v, want id-ascending %v", ids, want)
	}
}

// TestGetAllSessionsCrossesUsersAndTenants is the property that makes this
// interface worth a second item per session: ListSessionsForUser can only answer
// for a user the caller already names.
func TestGetAllSessionsCrossesUsersAndTenants(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	for i, tenant := range []string{"acme", "globex"} {
		u := newAdminUser(tenant, i)
		if _, err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("create user: %v", err)
		}
		id := fmt.Sprintf("ses_%s", tenant)
		if _, err := store.CreateSession(ctx, auth.Session{
			ID:               id,
			UserID:           u.ID,
			TenantID:         tenant,
			RefreshTokenHash: hashOf(id),
			CreatedAt:        time.Now().UTC(),
			ExpiresAt:        time.Now().UTC().Add(time.Hour),
		}); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}

	got, err := store.GetAllSessions(ctx, 100, 0)
	if err != nil {
		t.Fatalf("get all sessions: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("GetAllSessions returned %d sessions, want both tenants' 2", len(got))
	}
}

// TestGetAllSessionsKeepsRevokedOnes. The core's interface says nothing is
// filtered, and this port tombstones rather than deletes, so a revoked session
// is a row an admin screen must still be able to see.
func TestGetAllSessionsKeepsRevokedOnes(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	user := sampleUser("acme")
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	sess := auth.Session{
		ID:               uniqueID("ses"),
		UserID:           user.ID,
		TenantID:         "acme",
		RefreshTokenHash: hashOf("revoked"),
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(time.Hour),
	}
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := store.RevokeSessionByID(ctx, sess.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	got, err := store.GetAllSessions(ctx, 100, 0)
	if err != nil {
		t.Fatalf("get all sessions: %v", err)
	}
	if len(got) != 1 || got[0].RevokedAt == nil {
		t.Fatalf("GetAllSessions dropped or un-revoked the tombstone: %+v", got)
	}
}

// TestDeleteUserTakesTheSessionDirectoryWithIt. The directory entry is a base
// item of its own, so nothing deletes it implicitly.
func TestDeleteUserTakesTheSessionDirectoryWithIt(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	user := sampleUser("acme")
	if _, err := store.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	sess := auth.Session{
		ID:               uniqueID("ses"),
		UserID:           user.ID,
		TenantID:         "acme",
		RefreshTokenHash: hashOf("swept"),
		CreatedAt:        time.Now().UTC(),
		ExpiresAt:        time.Now().UTC().Add(time.Hour),
	}
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if m := rawItem(t, client, store.table, sessionPK(sess.ID), skSessionIndex); len(m) == 0 {
		t.Fatal("no session directory entry was written")
	}

	if err := store.DeleteUser(ctx, user.ID, "acme"); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	mustNotExist(t, client, store.table, sessionPK(sess.ID), skSessionIndex)
}

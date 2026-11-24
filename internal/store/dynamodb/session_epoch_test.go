package dynamodb

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	auth "github.com/nik2208/awesome-go-auth"
)

// hookedAPI is the store's API with a hook in front of every call: it records
// what the store asked DynamoDB for, and lets a test run something between two
// of the store's own requests — the interleavings a revocation can meet. The
// hook runs on the caller's goroutine, before the call is delegated.
type hookedAPI struct {
	API

	mu     sync.Mutex
	ops    []string
	before func(op string, in any) error
}

func (h *hookedAPI) note(op string, in any) error {
	h.mu.Lock()
	h.ops = append(h.ops, op)
	before := h.before
	h.mu.Unlock()
	if before != nil {
		return before(op, in)
	}
	return nil
}

func (h *hookedAPI) setBefore(f func(op string, in any) error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.before = f
}

func (h *hookedAPI) take() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	ops := h.ops
	h.ops = nil
	return ops
}

func (h *hookedAPI) GetItem(ctx context.Context, in *awsddb.GetItemInput, o ...func(*awsddb.Options)) (*awsddb.GetItemOutput, error) {
	if err := h.note("GetItem", in); err != nil {
		return nil, err
	}
	return h.API.GetItem(ctx, in, o...)
}

func (h *hookedAPI) PutItem(ctx context.Context, in *awsddb.PutItemInput, o ...func(*awsddb.Options)) (*awsddb.PutItemOutput, error) {
	if err := h.note("PutItem", in); err != nil {
		return nil, err
	}
	return h.API.PutItem(ctx, in, o...)
}

func (h *hookedAPI) UpdateItem(ctx context.Context, in *awsddb.UpdateItemInput, o ...func(*awsddb.Options)) (*awsddb.UpdateItemOutput, error) {
	if err := h.note("UpdateItem", in); err != nil {
		return nil, err
	}
	return h.API.UpdateItem(ctx, in, o...)
}

func (h *hookedAPI) DeleteItem(ctx context.Context, in *awsddb.DeleteItemInput, o ...func(*awsddb.Options)) (*awsddb.DeleteItemOutput, error) {
	if err := h.note("DeleteItem", in); err != nil {
		return nil, err
	}
	return h.API.DeleteItem(ctx, in, o...)
}

func (h *hookedAPI) Query(ctx context.Context, in *awsddb.QueryInput, o ...func(*awsddb.Options)) (*awsddb.QueryOutput, error) {
	if err := h.note("Query", in); err != nil {
		return nil, err
	}
	return h.API.Query(ctx, in, o...)
}

func (h *hookedAPI) TransactWriteItems(ctx context.Context, in *awsddb.TransactWriteItemsInput, o ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error) {
	if err := h.note("TransactWriteItems", in); err != nil {
		return nil, err
	}
	return h.API.TransactWriteItems(ctx, in, o...)
}

func (h *hookedAPI) BatchGetItem(ctx context.Context, in *awsddb.BatchGetItemInput, o ...func(*awsddb.Options)) (*awsddb.BatchGetItemOutput, error) {
	if err := h.note("BatchGetItem", in); err != nil {
		return nil, err
	}
	return h.API.BatchGetItem(ctx, in, o...)
}

func (h *hookedAPI) BatchWriteItem(ctx context.Context, in *awsddb.BatchWriteItemInput, o ...func(*awsddb.Options)) (*awsddb.BatchWriteItemOutput, error) {
	if err := h.note("BatchWriteItem", in); err != nil {
		return nil, err
	}
	return h.API.BatchWriteItem(ctx, in, o...)
}

// newHookedStore is newStore over a hookedAPI, on the same table.
func newHookedStore(t *testing.T, mutate ...func(*Options)) (*Store, *hookedAPI, *awsddb.Client) {
	t.Helper()
	plain, client := newStore(t, mutate...)
	hooked := &hookedAPI{API: client}
	opts := Options{TableName: plain.table, Logger: plain.log}
	for _, m := range mutate {
		m(&opts)
	}
	opts.TableName = plain.table
	store, err := New(hooked, opts)
	if err != nil {
		t.Fatalf("new hooked store: %v", err)
	}
	return store, hooked, client
}

// revokedEverywhere asserts that every read of sess the core makes reports it
// revoked: the refresh, the lookup by id, the account's listing and the
// deployment's.
func revokedEverywhere(t *testing.T, store *Store, sess auth.Session, want bool) {
	t.Helper()
	ctx := context.Background()
	byHash, err := store.GetSessionByRefreshTokenHash(ctx, sess.RefreshTokenHash)
	if err != nil {
		t.Fatalf("GetSessionByRefreshTokenHash: %v", err)
	}
	byID, err := store.GetSessionByID(ctx, sess.ID)
	if err != nil {
		t.Fatalf("GetSessionByID: %v", err)
	}
	listed, err := store.ListSessionsForUser(ctx, sess.UserID, sess.TenantID)
	if err != nil {
		t.Fatalf("ListSessionsForUser: %v", err)
	}
	all, err := store.GetAllSessions(ctx, 1000, 0)
	if err != nil {
		t.Fatalf("GetAllSessions: %v", err)
	}
	find := func(list []auth.Session) *auth.Session {
		for i := range list {
			if list[i].ID == sess.ID {
				return &list[i]
			}
		}
		t.Fatalf("session %s is missing from a listing", sess.ID)
		return nil
	}
	for name, got := range map[string]auth.Session{
		"refresh": byHash, "by id": byID,
		"account listing": *find(listed), "deployment listing": *find(all),
	} {
		if (got.RevokedAt != nil) != want {
			t.Errorf("%s: session %s revokedAt = %v, want revoked %v", name, sess.ID, got.RevokedAt, want)
		}
	}
}

// TestRevokeSessionsForUserEndsEverySession is the contract: every session of
// the account whose creation had returned is revoked wherever it is read, a
// session of another account or tenant is not, and one created afterwards
// lives. The marker is one item in the account's partition, upserted with the
// two attributes every item carries and no TTL.
func TestRevokeSessionsForUserEndsEverySession(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	other := newUser(t, store, "acme")
	elsewhere := newUser(t, store, "globex")

	var mine []auth.Session
	for range 3 {
		sess := sampleSession(u)
		if _, err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create session: %v", err)
		}
		mine = append(mine, sess)
	}
	theirs := sampleSession(other)
	far := sampleSession(elsewhere)
	for _, sess := range []auth.Session{theirs, far} {
		if _, err := store.CreateSession(ctx, sess); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}

	if err := store.RevokeSessionsForUser(ctx, u.ID, u.TenantID); err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	for _, sess := range mine {
		revokedEverywhere(t, store, sess, true)
	}
	revokedEverywhere(t, store, theirs, false)
	revokedEverywhere(t, store, far, false)

	after := sampleSession(u)
	if _, err := store.CreateSession(ctx, after); err != nil {
		t.Fatalf("create session after the revocation: %v", err)
	}
	revokedEverywhere(t, store, after, false)

	m := rawItem(t, client, store.table, userPK(u.TenantID, u.ID), skSessionEpoch)
	if got := getS(m, attrType); got != typeSessionEpoch {
		t.Errorf("_t = %q, want %q", got, typeSessionEpoch)
	}
	if got := getN(m, attrVer); got != schemaVersion {
		t.Errorf("_v = %d, want %d", got, schemaVersion)
	}
	if got := getN(m, attrEpoch); got != 1 {
		t.Errorf("epoch = %d, want 1", got)
	}
	if got := getS(m, attrRevokedReason); got != reasonPasswordReset {
		t.Errorf("revokedReason = %q, want %q", got, reasonPasswordReset)
	}
	for _, absent := range []string{attrTTL, attrGSI1PK, attrGSI1SK} {
		if _, ok := m[absent]; ok {
			t.Errorf("the epoch item carries %s; it must neither expire nor be listed", absent)
		}
	}

	// A second revocation ends the session opened in between, and the first
	// three stay revoked.
	if err := store.RevokeSessionsForUser(ctx, u.ID, u.TenantID); err != nil {
		t.Fatalf("second RevokeSessionsForUser: %v", err)
	}
	revokedEverywhere(t, store, after, true)
	revokedEverywhere(t, store, mine[0], true)
	if got := getN(rawItem(t, client, store.table, userPK(u.TenantID, u.ID), skSessionEpoch), attrEpoch); got != 2 {
		t.Errorf("epoch after two revocations = %d, want 2", got)
	}
}

// TestRevokeSessionsForUserReadsNoIndex: the revocation is one write and reads
// nothing — no GSI query that could miss a session, no listing that could
// refuse past the cap.
func TestRevokeSessionsForUserReadsNoIndex(t *testing.T) {
	t.Parallel()
	store, hooked, _ := newHookedStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	for range 3 {
		if _, err := store.CreateSession(ctx, sampleSession(u)); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}
	hooked.take()
	if err := store.RevokeSessionsForUser(ctx, u.ID, u.TenantID); err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	if ops := hooked.take(); !reflect.DeepEqual(ops, []string{"UpdateItem"}) {
		t.Errorf("RevokeSessionsForUser made %v, want one UpdateItem and nothing else", ops)
	}
}

// TestResetThroughTheCoreRevokesPastTheCap runs the core's own reset over this
// store with sessions.revokeOnPasswordReset's option on and the listing capped
// below the account's sessions. The listing refuses, as it always has; the reset
// succeeds and every session is refused at its next refresh — which is only
// possible if the core took the one-call path, UserSessionRevoker, and not the
// listing. The new password then opens a session that works.
func TestResetThroughTheCoreRevokesPastTheCap(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.MaxSessionsPerUser = 2 })
	ctx := context.Background()
	core, err := auth.New(
		auth.WithSecret("a-test-signing-secret-of-at-least-32-bytes"),
		auth.WithUserStore(store),
		auth.WithSessionStore(store),
		auth.WithRevokeSessionsOnPasswordReset(true),
	)
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	svc := core.Service()
	email := uniqueEmail("cap")
	const oldPassword, newPassword = "correct-horse-battery-1", "correct-horse-battery-2"
	user, _, err := svc.Register(ctx, auth.RegisterInput{Email: email, Password: oldPassword})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	var refresh []string
	for range 3 {
		_, tokens, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: oldPassword})
		if err != nil {
			t.Fatalf("Login: %v", err)
		}
		refresh = append(refresh, tokens.RefreshToken)
	}
	if _, err := store.ListSessionsForUser(ctx, user.ID, user.TenantID); !errors.Is(err, ErrResultTooLarge) {
		t.Fatalf("ListSessionsForUser past its cap = %v, want ErrResultTooLarge: the test needs the listing to refuse", err)
	}

	token, err := svc.ForgotPassword(ctx, auth.ForgotPasswordInput{Email: email})
	if err != nil || token == "" {
		t.Fatalf("ForgotPassword = %q, %v", token, err)
	}
	if err := svc.ResetPassword(ctx, auth.ResetPasswordInput{Token: token, NewPassword: newPassword}); err != nil {
		t.Fatalf("ResetPassword past the listing's cap: %v", err)
	}
	for i, rt := range refresh {
		if _, err := svc.Refresh(ctx, rt); !errors.Is(err, auth.ErrSessionRevoked) {
			t.Errorf("session %d opened before the reset: Refresh = %v, want ErrSessionRevoked", i, err)
		}
	}
	_, tokens, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: newPassword})
	if err != nil {
		t.Fatalf("Login with the new password: %v", err)
	}
	if _, err := svc.Refresh(ctx, tokens.RefreshToken); err != nil {
		t.Errorf("the session the new password opened does not refresh: %v", err)
	}
}

// TestARevocationDuringCreateSessionEndsTheSession: a raise that lands between
// CreateSession's read of the epoch and its write leaves the session stamped
// below the new epoch — revoked with the ones before it. Over-revocation, the
// side the contract allows.
func TestARevocationDuringCreateSessionEndsTheSession(t *testing.T) {
	t.Parallel()
	store, hooked, _ := newHookedStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	var once sync.Once
	hooked.setBefore(func(op string, _ any) error {
		if op != "TransactWriteItems" {
			return nil
		}
		var err error
		once.Do(func() { err = store.RevokeSessionsForUser(ctx, u.ID, u.TenantID) })
		return err
	})
	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	hooked.setBefore(nil)
	revokedEverywhere(t, store, sess, true)
}

// TestARevocationBetweenTheRefreshReadAndTheRotationRefusesTheRefresh: a refresh
// that read the session before the raise and rotates it after is answered
// ErrSessionRevoked, so the tokens it minted are never handed out — with the
// rotation scope's precondition, and without it.
func TestARevocationBetweenTheRefreshReadAndTheRotationRefusesTheRefresh(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	u := newUser(t, store, "acme")

	for _, scoped := range []bool{true, false} {
		sess := sampleSession(u)
		if _, err := store.CreateSession(context.Background(), sess); err != nil {
			t.Fatalf("create session: %v", err)
		}
		ctx := context.Background()
		if scoped {
			ctx = WithRotationScope(ctx)
		}
		if _, err := store.GetSessionByRefreshTokenHash(ctx, sess.RefreshTokenHash); err != nil {
			t.Fatalf("read: %v", err)
		}
		if err := store.RevokeSessionsForUser(context.Background(), u.ID, u.TenantID); err != nil {
			t.Fatalf("RevokeSessionsForUser: %v", err)
		}
		next := sess
		next.RefreshTokenHash = hashOf(uniqueID("refresh"))
		if err := store.UpdateSession(ctx, next); !errors.Is(err, auth.ErrSessionRevoked) {
			t.Errorf("scoped=%v: the rotation that outlived the revocation = %v, want ErrSessionRevoked", scoped, err)
		}
		if got, err := store.GetSessionByRefreshTokenHash(context.Background(), next.RefreshTokenHash); err != nil || got.RevokedAt == nil {
			t.Errorf("scoped=%v: the rotated session reads %+v, %v; want it revoked", scoped, got, err)
		}
	}
}

// TestARotationWhoseEpochReadFailsStands: the check after a committed rotation
// fails open. The tokens are minted and the write is done; the epoch still ends
// the session at its next read.
func TestARotationWhoseEpochReadFailsStands(t *testing.T) {
	t.Parallel()
	store, hooked, _ := newHookedStore(t)
	u := newUser(t, store, "acme")
	sess := sampleSession(u)
	if _, err := store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	ctx := WithRotationScope(context.Background())
	if _, err := store.GetSessionByRefreshTokenHash(ctx, sess.RefreshTokenHash); err != nil {
		t.Fatalf("read: %v", err)
	}
	if err := store.RevokeSessionsForUser(context.Background(), u.ID, u.TenantID); err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	committed := false
	hooked.setBefore(func(op string, in any) error {
		if op == "TransactWriteItems" {
			committed = true
			return nil
		}
		if get, ok := in.(*awsddb.GetItemInput); ok && committed && getS(get.Key, attrSK) == skSessionEpoch {
			return errors.New("injected: the epoch cannot be read")
		}
		return nil
	})
	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.UpdateSession(ctx, next); err != nil {
		t.Errorf("a rotation whose epoch check could not read = %v, want nil (fail open)", err)
	}
	hooked.setBefore(nil)
	if got, err := store.GetSessionByRefreshTokenHash(context.Background(), next.RefreshTokenHash); err != nil || got.RevokedAt == nil {
		t.Errorf("the rotated session reads %+v, %v; the epoch must still end it", got, err)
	}
}

// TestAnUnstampedSessionIsEndedByTheFirstRevocation: a session written before
// the epoch existed carries no stamp, which reads as 0 — alive until the first
// raise, ended by it.
func TestAnUnstampedSessionIsEndedByTheFirstRevocation(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	if _, err := client.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(store.table),
		Key:                      key(sessionPK(sess.ID), skSession),
		UpdateExpression:         aws.String("REMOVE #epoch"),
		ExpressionAttributeNames: exprNames(attrEpoch),
	}); err != nil {
		t.Fatalf("strip the stamp: %v", err)
	}
	revokedEverywhere(t, store, sess, false)
	if err := store.RevokeSessionsForUser(ctx, u.ID, u.TenantID); err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	revokedEverywhere(t, store, sess, true)
}

// TestALostRotationOfAnEndedSessionIsNotAReplay: a rotation that loses its
// precondition on a session the epoch has ended is answered ErrSessionRevoked
// and revokes no family — relabelling the reset as a replay would bury it in
// the audit trail.
func TestALostRotationOfAnEndedSessionIsNotAReplay(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	u := newUser(t, store, "acme")
	sess := sampleSession(u)
	if _, err := store.CreateSession(context.Background(), sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	stale := WithRotationScope(context.Background())
	if _, err := store.GetSessionByRefreshTokenHash(stale, sess.RefreshTokenHash); err != nil {
		t.Fatalf("read: %v", err)
	}
	// Another refresh rotates first, then the reset raises the epoch.
	first := sess
	first.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.RotateSession(context.Background(), sess.ID, sess.RefreshTokenHash, first); err != nil {
		t.Fatalf("first rotation: %v", err)
	}
	if err := store.RevokeSessionsForUser(context.Background(), u.ID, u.TenantID); err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	second := sess
	second.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.UpdateSession(stale, second); !errors.Is(err, auth.ErrSessionRevoked) {
		t.Errorf("the losing rotation of an ended session = %v, want ErrSessionRevoked", err)
	}
	if got := getS(rawItem(t, client, store.table, sessionPK(sess.ID), skSession), attrRevokedReason); got != "" {
		t.Errorf("the session was relabelled %q; an ended session is not a replay", got)
	}
}

// TestDeleteUserTakesTheEpochWithIt: the epoch item lives in the account's
// partition and DeleteUser's sweep of that partition removes it.
func TestDeleteUserTakesTheEpochWithIt(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	if err := store.RevokeSessionsForUser(ctx, u.ID, u.TenantID); err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	if len(rawItem(t, client, store.table, userPK(u.TenantID, u.ID), skSessionEpoch)) == 0 {
		t.Fatal("no epoch item to delete")
	}
	if err := store.DeleteUser(ctx, u.ID, u.TenantID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	mustNotExist(t, client, store.table, userPK(u.TenantID, u.ID), skSessionEpoch)
}

// TestRevokeSessionsForUserValidatesItsKeys: a malformed id or a missing tenant
// in multi-tenant mode is refused before anything is written, as every other
// method of this store refuses them.
func TestRevokeSessionsForUserValidatesItsKeys(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t, func(o *Options) { o.MultiTenant = true })
	ctx := context.Background()
	if err := store.RevokeSessionsForUser(ctx, "bad#id", "acme"); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("a malformed user id = %v, want ErrInvalidIdentifier", err)
	}
	if err := store.RevokeSessionsForUser(ctx, uniqueID("usr"), ""); !errors.Is(err, ErrTenantRequired) {
		t.Errorf("no tenant in multi-tenant mode = %v, want ErrTenantRequired", err)
	}
}

// TestClearResetTokenWithNothingOutstanding: since core v0.16.0,
// POST /change-password clears the account's reset token on every change, and
// the core logs a line whenever the clear fails — so a clear with nothing to
// clear must succeed, and leave the profile as it was.
func TestClearResetTokenWithNothingOutstanding(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	before := rawItem(t, client, store.table, userPK(u.TenantID, u.ID), skProfile)
	for i := range 2 {
		if err := store.ClearResetToken(ctx, u.ID, u.TenantID); err != nil {
			t.Fatalf("clear %d with nothing outstanding: %v", i, err)
		}
	}
	after := rawItem(t, client, store.table, userPK(u.TenantID, u.ID), skProfile)
	if !reflect.DeepEqual(before, after) {
		t.Errorf("a clear with nothing to clear changed the profile:\nbefore %v\nafter  %v", before, after)
	}
	// A spent token leaves nothing to clear either.
	hash := hashOf(uniqueID("reset"))
	if err := store.UpdateResetToken(ctx, u.ID, u.TenantID, hash, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("UpdateResetToken: %v", err)
	}
	if _, err := store.GetUserByResetTokenHash(ctx, hash); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if err := store.ClearResetToken(ctx, u.ID, u.TenantID); err != nil {
		t.Errorf("clear after the token was spent: %v", err)
	}
	if _, ok := rawItem(t, client, store.table, userPK(u.TenantID, u.ID), skProfile)[familyReset.hashAttr]; ok {
		t.Error("a reset hash survived the clear")
	}
}

// TestSessionItemsCarryTheirStamp: the stamp is an attribute of the session
// item, written at creation and left alone by rotation and revocation.
func TestSessionItemsCarryTheirStamp(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	if err := store.RevokeSessionsForUser(ctx, u.ID, u.TenantID); err != nil {
		t.Fatalf("RevokeSessionsForUser: %v", err)
	}
	sess := sampleSession(u)
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	stamp := func() (int64, bool) {
		m := rawItem(t, client, store.table, sessionPK(sess.ID), skSession)
		_, ok := m[attrEpoch]
		return getN(m, attrEpoch), ok
	}
	if got, ok := stamp(); !ok || got != 1 {
		t.Fatalf("a session created at epoch 1 is stamped %d (present %v)", got, ok)
	}
	next := sess
	next.RefreshTokenHash = hashOf(uniqueID("refresh"))
	if err := store.RotateSession(ctx, sess.ID, sess.RefreshTokenHash, next); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got, _ := stamp(); got != 1 {
		t.Errorf("rotation moved the stamp to %d", got)
	}
	now := time.Now().UTC()
	next.RevokedAt = &now
	if err := store.UpdateSession(ctx, next); err != nil {
		t.Fatalf("logout: %v", err)
	}
	if got, _ := stamp(); got != 1 {
		t.Errorf("revocation moved the stamp to %d", got)
	}
	if m := rawItem(t, client, store.table, sessionPK(sess.ID), skSession); getS(m, attrRevokedReason) != reasonLogout {
		t.Errorf("the logout's own revocation was not kept: %v", m[attrRevokedReason])
	}
}

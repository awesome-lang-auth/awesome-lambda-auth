package dynamodb

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// Session and refresh-pointer attributes.
const (
	attrSessionID     = "sessionId"
	attrRefreshHash   = "refreshHash"
	attrGen           = "gen"
	attrExpiresAt     = "expiresAt"
	attrRevokedAt     = "revokedAt"
	attrRevokedReason = "revokedReason"
	attrRevokedGen    = "revokedGen"
)

// Revocation reasons. They are stored, not derived, because the reason a session
// died is the difference between an audit line and a security incident.
const (
	reasonLogout = "logout"
	reasonAdmin  = "admin_revoke"
	reasonReplay = "refresh_replay"
)

// firstGen is the generation a freshly created session starts at. It counts
// rotations, and is pinned in the rotation condition so a replay cannot land on
// a generation that has already moved.
const firstGen int64 = 1

// sessionItem encodes an auth.Session. Device metadata the HTTP layer may have
// attached (userAgent, ipAddress, lastActiveAt) has no home on auth.Session, so
// rotation must never PutItem over a session — see rotate, which uses UpdateItem
// with an explicit attribute list precisely so those extras survive (§5).
//
// epoch is the account's session epoch as CreateSession read it: the stamp a
// later RevokeSessionsForUser ends the session by (session_epoch.go). Neither
// rotation nor revocation touches it.
func (s *Store) sessionItem(sess auth.Session, gen, epoch int64) item {
	createdAt := formatTime(sess.CreatedAt)
	it := item{}.
		sAlways(attrPK, sessionPK(sess.ID)).
		sAlways(attrSK, skSession).
		stamp(typeSession).
		sAlways(attrSessionID, sess.ID).
		sAlways(attrUserID, sess.UserID).
		sAlways(attrTenantID, sess.TenantID).
		sAlways(attrRefreshHash, sess.RefreshTokenHash).
		n(attrGen, gen).
		n(attrEpoch, epoch).
		sAlways(attrCreatedAt, createdAt).
		sAlways(attrExpiresAt, formatTime(sess.ExpiresAt)).
		sAlways(attrGSI1PK, userPK(sess.TenantID, sess.UserID)).
		sAlways(attrGSI1SK, sessionGSI1SK(createdAt, sess.ID)).
		ttl(sess.ExpiresAt.Add(s.ttlGrace))
	it.tp(attrRevokedAt, sess.RevokedAt)
	return it
}

// sessionIndexItem is the session's directory entry: a second, tiny item in the
// session's own partition, carrying a constant GSI1 partition key so that
// SessionLister.GetAllSessions can be a Query.
//
// # Why a second item at all
//
// The session item's own GSI1 key pair is already spent: GSI1PK is
// USER#<t>#<u>, which is what makes ListSessionsForUser a fan-out rather than a
// scan of the user's history (§2.3). One item has one key pair per index, and
// this table has one index, so a cross-user listing needs either a second index
// — a template.yaml change and a table update on a live stack — or a second
// item. A second item is the cheaper of the two and the one that does not need
// infrastructure to move: it costs one write in the transaction that already
// creates the session, and nothing thereafter.
//
// **Nothing thereafter** is the load-bearing half. Rotation is an UpdateItem on
// the session item with an explicit attribute list, revocation likewise, and
// neither touches this item — it carries nothing that changes. So the highest
// -churn entity in the table pays for this once per session, not once per
// refresh.
//
// # What it costs, honestly
//
// One extra item of roughly eighty bytes per session, one extra GSI entry, and
// one extra operation inside CreateSession's transaction (which is billed at 2×
// WCU, §6.3). The GSI partition it writes to is a single constant one, so the
// ceiling on logins per second is a single GSI partition's write throughput —
// the hot-key cost the upstream author refused to paper over, here in its
// sharpest form because sessions are created more often than anything else this
// table indexes. §6.2 carries the number and the escape hatch, which is
// sharding SESSION#0..SESSION#n at the price of an n-way merge on every read.
//
// # TTL
//
// It carries the session's own TTL, so the two expire together and a directory
// that outlived its sessions is not a state this store can reach. TTL deletion
// is best-effort within roughly 48 hours and the two items are reaped
// independently, so a directory entry can briefly outlive its session; that is
// exactly the case pagedIndexQuery fills past rather than truncating on.
func (s *Store) sessionIndexItem(sess auth.Session) item {
	return item{}.
		sAlways(attrPK, sessionPK(sess.ID)).
		sAlways(attrSK, skSessionIndex).
		stamp(typeSessionIndex).
		sAlways(attrGSI1PK, gsi1AllSessionsPK).
		// The session id alone, so the directory's order is Session.ID
		// ascending — which is the core's normative order for SessionLister
		// exactly, and therefore needs no deviation. A creation timestamp here
		// would have been more useful to look at and would have had to be
		// registered.
		sAlways(attrGSI1SK, sess.ID).
		ttl(sess.ExpiresAt.Add(s.ttlGrace))
}

func sessionFromItem(m map[string]types.AttributeValue) (auth.Session, error) {
	if err := checkVersion(m, typeSession); err != nil {
		return auth.Session{}, err
	}
	sess := auth.Session{
		ID:               getS(m, attrSessionID),
		UserID:           getS(m, attrUserID),
		TenantID:         getS(m, attrTenantID),
		RefreshTokenHash: getS(m, attrRefreshHash),
	}
	var err error
	if sess.CreatedAt, err = getTime(m, attrCreatedAt); err != nil {
		return auth.Session{}, err
	}
	if sess.ExpiresAt, err = getTime(m, attrExpiresAt); err != nil {
		return auth.Session{}, err
	}
	if sess.RevokedAt, err = getTimePtr(m, attrRevokedAt); err != nil {
		return auth.Session{}, err
	}
	return sess, nil
}

// refreshPointer maps a refresh-token hash back to its session. The hash is a
// capability: possession of the 256-bit value is the authorisation, so the item
// is global and carries the tenant id for the next access to key on (§3).
func (s *Store) refreshPointer(sess auth.Session, gen int64) item {
	return item{}.
		sAlways(attrPK, refreshPK(sess.RefreshTokenHash)).
		sAlways(attrSK, skRefresh).
		stamp(typeRefresh).
		sAlways(attrSessionID, sess.ID).
		sAlways(attrUserID, sess.UserID).
		sAlways(attrTenantID, sess.TenantID).
		n(attrGen, gen).
		ttl(sess.ExpiresAt.Add(s.ttlGrace))
}

func (s *Store) checkSession(sess auth.Session) error {
	if err := s.checkTenant(sess.TenantID); err != nil {
		return err
	}
	if err := checkID("session id", sess.ID); err != nil {
		return err
	}
	if err := checkID("user id", sess.UserID); err != nil {
		return err
	}
	return checkHash("refresh token hash", sess.RefreshTokenHash)
}

// The session interfaces. SessionStore is handed to the core by name
// (auth.WithSessionStore); the other two are discovered by type assertion, so a
// drifted signature there is a GET /sessions or a POST /sessions/cleanup that
// answers 501 from a binary that built cleanly. See interfaces.go for the
// convention.
var (
	_ auth.SessionStore       = (*Store)(nil)
	_ auth.SessionLookupStore = (*Store)(nil)
	_ auth.SessionAdminStore  = (*Store)(nil)
)

// CreateSession writes the session and its first refresh pointer in one
// transaction (data-model.md #10), so a session can never exist without a way to
// resolve it from the token that was already handed to the client.
//
// The account's session epoch is read first, consistently, and stamped on the
// session (session_epoch.go). Read before the write and not with it, which is
// the read-then-write this store otherwise avoids, and deliberately: what the
// read can race is a revocation, and losing that race stamps the session below
// the new epoch — the session is revoked with the ones before it, which is the
// over-revocation the contract allows and never the reverse. A read that fails
// fails the create, since a session with no trustworthy stamp is one the next
// reset might not end.
func (s *Store) CreateSession(ctx context.Context, sess auth.Session) (auth.Session, error) {
	if err := s.checkSession(sess); err != nil {
		return auth.Session{}, err
	}
	epoch, err := s.readSessionEpoch(ctx, sess.TenantID, sess.UserID)
	if err != nil {
		return auth.Session{}, err
	}
	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			// Unconditional, matching MemorySessionStore.CreateSession
			// (memory_store.go:414-420). Session ids are 128 bits of randomness,
			// so an overwrite is not a case that arises.
			{Put: &types.Put{TableName: aws.String(s.table), Item: s.sessionItem(sess, firstGen, epoch.epoch)}},
			// The directory entry, in the same transaction and unconditional for
			// the same reason: a session that existed without one would be
			// invisible to GetAllSessions for its whole life, and there is no
			// later moment at which this store would notice and repair it.
			{Put: &types.Put{TableName: aws.String(s.table), Item: s.sessionIndexItem(sess)}},
			{Put: &types.Put{
				TableName: aws.String(s.table),
				Item:      s.refreshPointer(sess, firstGen),
				// Tolerating the same session reclaiming its own pointer keeps a
				// retried login idempotent; a different session behind the same
				// hash would be a sha256 collision and stays loud.
				ConditionExpression:       aws.String("attribute_not_exists(#PK) OR #sessionId = :sid"),
				ExpressionAttributeNames:  exprNames(attrPK, attrSessionID),
				ExpressionAttributeValues: map[string]types.AttributeValue{":sid": avS(sess.ID)},
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			// Index 2: the refresh pointer is the third operation, after the
			// session item and its directory entry. It is also the only one of
			// the three that carries a condition, so it is the only index worth
			// asking about.
			if _, failed := txFailedAt(reasons, 2); failed {
				return auth.Session{}, errors.New("dynamodb: refresh token hash already bound to another session")
			}
		}
		return auth.Session{}, wrap("create session", err)
	}
	return sess, nil
}

// GetSessionByRefreshTokenHash resolves the pointer, then the session, and
// decides whether the token presented is the current generation.
//
// A hash that resolves to a live session whose refreshHash has moved on can only
// be a generation that was already exchanged — a replay. The answer is immediate
// revocation of the whole family (the family *is* the session: Service.Refresh
// keeps session.ID across rotations and only replaces the hash, service.go:122-162).
// Writing inside a nominally read-only method is a deliberate deviation:
// deferring the response until the next request leaves the attacker a valid
// window.
//
// A session that is already revoked is returned rather than turned into an
// error, because Service.Refresh maps any error from this method to
// ErrSessionNotFound (service.go:129-131) and would therefore swallow
// ErrSessionRevoked; returning the populated struct is what puts the right status
// on the wire.
//
// That includes a session the account's epoch has ended (session_epoch.go),
// which is decided before the replay check: the pointer names the account, so
// the session and the epoch are read in one consistent BatchGetItem — one item
// more than the GetItem it replaces, and no round trip more.
func (s *Store) GetSessionByRefreshTokenHash(ctx context.Context, tokenHash string) (auth.Session, error) {
	if err := checkHash("refresh token hash", tokenHash); err != nil {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	ptr, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(refreshPK(tokenHash), skRefresh),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.Session{}, wrap("get refresh pointer", err)
	}
	if len(ptr.Item) == 0 {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	if err := checkVersion(ptr.Item, typeRefresh); err != nil {
		return auth.Session{}, err
	}
	pointerGen := getN(ptr.Item, attrGen)

	current, epoch, err := s.sessionWithEpoch(ctx, getS(ptr.Item, attrSessionID),
		getS(ptr.Item, attrTenantID), getS(ptr.Item, attrUserID))
	if err != nil {
		return auth.Session{}, err
	}
	sess, err := sessionFromItem(current)
	if err != nil {
		return auth.Session{}, err
	}
	epoch.honour(&sess, current)
	if sess.RevokedAt != nil {
		return sess, nil
	}
	if getS(current, attrRefreshHash) != tokenHash {
		if err := s.revokeFamily(ctx, sess.ID, reasonReplay, pointerGen); err != nil {
			return auth.Session{}, err
		}
		return auth.Session{}, auth.ErrSessionNotFound
	}

	// Hand the precondition to UpdateSession, which the interface leaves no room
	// to pass it to. See rotation.go.
	if scope := rotationScopeFrom(ctx); scope != nil {
		scope.record(sess.ID, rotationPrecondition{
			oldHash:  tokenHash,
			gen:      getN(current, attrGen),
			hasGen:   true,
			epoch:    getN(current, attrEpoch),
			hasEpoch: true,
		})
	}
	return sess, nil
}

// sessionWithEpoch reads a session item and its account's session epoch in one
// consistent BatchGetItem, the account named by the caller — the refresh
// pointer carries it. A session item whose owner is not the account named is
// not one this store wrote; its own account's epoch is read for it then, so a
// mismatch cannot honour the wrong marker.
func (s *Store) sessionWithEpoch(ctx context.Context, sessionID, tenantID, userID string) (map[string]types.AttributeValue, sessionEpoch, error) {
	items, err := s.batchGet(ctx, []map[string]types.AttributeValue{
		key(sessionPK(sessionID), skSession),
		sessionEpochKey(tenantID, userID),
	})
	if err != nil {
		return nil, sessionEpoch{}, wrap("get session", err)
	}
	var (
		current   map[string]types.AttributeValue
		epochItem map[string]types.AttributeValue
	)
	for _, m := range items {
		switch getS(m, attrSK) {
		case skSession:
			current = m
		case skSessionEpoch:
			epochItem = m
		}
	}
	if current == nil {
		return nil, sessionEpoch{}, auth.ErrSessionNotFound
	}
	if getS(current, attrTenantID) != tenantID || getS(current, attrUserID) != userID {
		e, err := s.readSessionEpoch(ctx, getS(current, attrTenantID), getS(current, attrUserID))
		return current, e, err
	}
	e, err := epochFromItem(epochItem)
	return current, e, err
}

// GetSessionByID implements SessionLookupStore. An expired-but-not-yet-reaped
// item is returned as-is: TTL is best effort, and the core owns the expiry
// decision (service.go:136).
//
// A session the account's epoch has ended is reported revoked (session_epoch.go):
// this is the read sessions.checkOn: allcalls makes on every request, so it is
// what refuses an access token at once after a revoking reset. The epoch is a
// second GetItem, after the session's, since only the session names the
// account; a session already revoked skips it.
func (s *Store) GetSessionByID(ctx context.Context, sessionID string) (auth.Session, error) {
	if err := checkID("session id", sessionID); err != nil {
		return auth.Session{}, auth.ErrSessionNotFound
	}
	m, err := s.getSessionItem(ctx, sessionID)
	if err != nil {
		return auth.Session{}, err
	}
	sess, err := sessionFromItem(m)
	if err != nil || sess.RevokedAt != nil {
		return sess, err
	}
	epoch, err := s.readSessionEpoch(ctx, sess.TenantID, sess.UserID)
	if err != nil {
		return auth.Session{}, err
	}
	epoch.honour(&sess, m)
	return sess, nil
}

func (s *Store) getSessionItem(ctx context.Context, sessionID string) (map[string]types.AttributeValue, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(sessionPK(sessionID), skSession),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrap("get session", err)
	}
	if len(out.Item) == 0 {
		return nil, auth.ErrSessionNotFound
	}
	return out.Item, nil
}

// UpdateSession is the one interface method that means two different things. The
// core calls it to revoke (Logout sets RevokedAt, service.go:178-180) and to
// rotate (Refresh replaces the hash and expiry, service.go:157-159), and the two
// need opposite conditions, so they are split here on the only signal available.
func (s *Store) UpdateSession(ctx context.Context, sess auth.Session) error {
	if err := s.checkSession(sess); err != nil {
		return err
	}
	if sess.RevokedAt != nil {
		return s.revoke(ctx, sess)
	}
	pre, ok := rotationPreFor(ctx, sess.ID)
	if !ok {
		s.warnDegradedRotation()
	}
	return s.rotate(ctx, sess, pre, ok)
}

// RotateSession is the shape the upstream optional interface should have
// (data-model.md §4.3, resolution 1):
//
//	SessionRotationStore { RotateSession(ctx, sessionID, oldRefreshHash string, next Session) error }
//
// It is implemented from day one so that adopting the interface upstream is a
// no-op here, and so callers that hold the old hash can rotate correctly without
// the context-carried interim.
func (s *Store) RotateSession(ctx context.Context, sessionID, oldRefreshHash string, next auth.Session) error {
	next.ID = sessionID
	if err := s.checkSession(next); err != nil {
		return err
	}
	if err := checkHash("previous refresh token hash", oldRefreshHash); err != nil {
		return err
	}
	return s.rotate(ctx, next, rotationPrecondition{oldHash: oldRefreshHash}, true)
}

func rotationPreFor(ctx context.Context, sessionID string) (rotationPrecondition, bool) {
	scope := rotationScopeFrom(ctx)
	if scope == nil {
		return rotationPrecondition{}, false
	}
	return scope.take(sessionID)
}

// rotate writes the new refresh pointer and advances the session in one
// transaction (data-model.md #12).
//
// The condition on the session item is what makes concurrent refreshes resolve
// to exactly one winner: both callers read the same refreshHash, both attempt to
// replace it, and "#refreshHash = :old" can only hold for whichever transaction
// commits first. The loser learns that its token is now a rotated-out generation
// and revokes the family, which is the same conclusion replay detection reaches
// on the read path — just reached a request earlier.
//
// Without a precondition (havePre false) the condition degrades to
// attribute_not_exists(revokedAt), both callers succeed, and the loser's token
// becomes a stale generation that the next use will catch. That is the residual
// documented in §4.3.3, and it is why WithRotationScope exists.
//
// A committed rotation is then checked against the account's session epoch
// (rotationOutlivedARevocation): a refresh that read the session before a
// revoking reset and rotated it after is answered ErrSessionRevoked, as one
// that lost to a revocation by id is. The transaction cannot check the epoch
// itself — that would be a ConditionCheck on a second item, an action the
// function's role does not grant — so it is one GetItem after the commit.
func (s *Store) rotate(ctx context.Context, sess auth.Session, pre rotationPrecondition, havePre bool) error {
	cond := "attribute_exists(#PK) AND attribute_not_exists(#revokedAt)"
	names := map[string]string{
		"#PK":          attrPK,
		"#revokedAt":   attrRevokedAt,
		"#refreshHash": attrRefreshHash,
		"#expiresAt":   attrExpiresAt,
		"#updatedAt":   attrUpdatedAt,
		"#gen":         attrGen,
		"#ttl":         attrTTL,
	}
	values := map[string]types.AttributeValue{
		":new": avS(sess.RefreshTokenHash),
		":exp": avS(formatTime(sess.ExpiresAt)),
		":now": avS(formatTime(s.nowUTC())),
		":ttl": avN(sess.ExpiresAt.Add(s.ttlGrace).Unix()),
		":one": avN(1),
	}
	if havePre {
		cond += " AND #refreshHash = :old"
		values[":old"] = avS(pre.oldHash)
		if pre.hasGen {
			cond += " AND #gen = :gen"
			values[":gen"] = avN(pre.gen)
		}
	}

	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:                 aws.String(s.table),
				Item:                      s.refreshPointer(sess, pre.gen+1),
				ConditionExpression:       aws.String("attribute_not_exists(#PK) OR #sessionId = :sid"),
				ExpressionAttributeNames:  exprNames(attrPK, attrSessionID),
				ExpressionAttributeValues: map[string]types.AttributeValue{":sid": avS(sess.ID)},
			}},
			{Update: &types.Update{
				TableName: aws.String(s.table),
				Key:       key(sessionPK(sess.ID), skSession),
				// An explicit attribute list, not a Put: whatever device metadata
				// the HTTP layer stored is not on auth.Session and must survive.
				// ADD on #gen avoids needing to know the current generation.
				UpdateExpression:                    aws.String("SET #refreshHash = :new, #expiresAt = :exp, #updatedAt = :now, #ttl = :ttl ADD #gen :one"),
				ConditionExpression:                 aws.String(cond),
				ExpressionAttributeNames:            names,
				ExpressionAttributeValues:           values,
				ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
			}},
		},
	})
	if err == nil {
		return s.rotationOutlivedARevocation(ctx, sess, pre)
	}
	reasons, cancelled := txConditionFailures(err)
	if !cancelled {
		return wrap("rotate session", err)
	}
	if _, failed := txFailedAt(reasons, 0); failed {
		return errors.New("dynamodb: refresh token hash already bound to another session")
	}
	preImage, failed := txFailedAt(reasons, 1)
	if !failed {
		return wrap("rotate session", err)
	}
	return s.classifyRotationLoss(ctx, sess.ID, pre, havePre, preImage)
}

// classifyRotationLoss turns a failed rotation condition into the right answer.
// It may read the session again: DynamoDB only returns a pre-image when
// ReturnValuesOnConditionCheckFailure is honoured, and a read *after* a write has
// already been refused is not the read-then-write this store forbids.
func (s *Store) classifyRotationLoss(ctx context.Context, sessionID string, pre rotationPrecondition, havePre bool, preImage map[string]types.AttributeValue) error {
	if len(preImage) == 0 {
		out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
			TableName:      aws.String(s.table),
			Key:            key(sessionPK(sessionID), skSession),
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return wrap("classify rotation failure", err)
		}
		if len(out.Item) == 0 {
			return auth.ErrSessionNotFound
		}
		preImage = out.Item
	}
	if getS(preImage, attrRevokedAt) != "" {
		return auth.ErrSessionRevoked
	}
	// A session the account's epoch has ended is revoked too, and is answered
	// as one: it is not a replay to revoke a family for, and relabelling it
	// one would bury the reset in the audit trail.
	epoch, err := s.readSessionEpoch(ctx, getS(preImage, attrTenantID), getS(preImage, attrUserID))
	if err != nil {
		return wrap("classify rotation failure", err)
	}
	if epoch.ends(getN(preImage, attrEpoch)) {
		return auth.ErrSessionRevoked
	}
	if !havePre {
		// No precondition was pinned, so the only condition that could have
		// failed was already handled above. Report the raw situation instead of
		// inventing a cause.
		return errors.New("dynamodb: session rotation refused with no revocation and no precondition")
	}
	// Someone else rotated first: this caller's token is a rotated-out
	// generation, which is exactly a replay. Kill the family.
	if err := s.revokeFamily(ctx, sessionID, reasonReplay, pre.gen); err != nil {
		return err
	}
	return auth.ErrSessionNotFound
}

// revoke is the logout path. It is idempotent by design: an already-revoked
// session is a successful logout, and the first revocation's timestamp and reason
// are kept, because overwriting them would erase the record of a replay with a
// routine logout.
func (s *Store) revoke(ctx context.Context, sess auth.Session) error {
	at := sess.RevokedAt
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(sessionPK(sess.ID), skSession),
		UpdateExpression:         aws.String("SET #revokedAt = :at, #revokedReason = :reason, #updatedAt = :at"),
		ConditionExpression:      aws.String("attribute_exists(#PK) AND attribute_not_exists(#revokedAt)"),
		ExpressionAttributeNames: exprNames(attrPK, attrRevokedAt, attrRevokedReason, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":at":     avS(formatTime(*at)),
			":reason": avS(reasonLogout),
		},
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return nil
	}
	if !isConditionFailed(err) {
		return wrap("revoke session", err)
	}
	// The condition covers two cases at once. An empty pre-image means the item
	// does not exist; anything else means it was already revoked.
	preImage, _ := conditionFailedItem(err)
	if len(preImage) > 0 {
		return nil
	}
	if _, err := s.getSessionItem(ctx, sess.ID); err != nil {
		return err
	}
	return nil
}

// revokeFamily kills every generation of a session at once. No pointer
// enumeration is needed: every refresh read resolves through the session item,
// so revoking it invalidates all outstanding generations.
func (s *Store) revokeFamily(ctx context.Context, sessionID, reason string, gen int64) error {
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(sessionPK(sessionID), skSession),
		UpdateExpression:         aws.String("SET #revokedAt = :now, #revokedReason = :reason, #revokedGen = :gen, #updatedAt = :now"),
		ConditionExpression:      aws.String("attribute_exists(#PK) AND attribute_not_exists(#revokedAt)"),
		ExpressionAttributeNames: exprNames(attrPK, attrRevokedAt, attrRevokedReason, attrRevokedGen, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":    avS(formatTime(s.nowUTC())),
			":reason": avS(reason),
			":gen":    avN(gen),
		},
	})
	if err != nil && !isConditionFailed(err) {
		return wrap("revoke session family", err)
	}
	// A failed condition means someone already revoked it, which is the desired
	// end state.
	return nil
}

// ListSessionsForUser implements SessionAdminStore. It reads the sparse GSI —
// eventual consistency is acceptable for an admin/UI listing, and is the price
// of not indexing sessions under the user partition, where they would turn the
// hottest read in the system into a paginated scan of the user's history (§2.3).
//
// Results come back oldest-first, because GSI1SK embeds the creation timestamp.
// The reference iterates a map and returns them in no order at all.
//
// A session the account's session epoch has ended is listed revoked
// (session_epoch.go); the epoch item rides in the same BatchGetItem. The core
// does not revoke from this listing on this store — RevokeSessionsForUser is
// the reset's path — so the listing is what an account and an administrator
// see, and it has to agree with what a refresh would answer.
func (s *Store) ListSessionsForUser(ctx context.Context, userID, tenantID string) ([]auth.Session, error) {
	keys, err := s.sessionKeysForUser(ctx, userID, tenantID)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return []auth.Session{}, nil
	}
	// GSI1 projects three attributes on purpose — no secret is ever in a second
	// physical copy (§5) — so the full items come from the main table.
	items, err := s.batchGet(ctx, append(keys, sessionEpochKey(tenantID, userID)))
	if err != nil {
		return nil, wrap("list sessions", err)
	}
	var epoch sessionEpoch
	sessions := make([]map[string]types.AttributeValue, 0, len(items))
	for _, m := range items {
		if getS(m, attrSK) == skSessionEpoch {
			if epoch, err = epochFromItem(m); err != nil {
				return nil, err
			}
			continue
		}
		sessions = append(sessions, m)
	}
	out := make([]auth.Session, 0, len(sessions))
	for _, m := range sessions {
		sess, err := sessionFromItem(m)
		if err != nil {
			return nil, err
		}
		epoch.honour(&sess, m)
		out = append(out, sess)
	}
	// BatchGetItem does not preserve request order, so the ordering the index
	// gave us has to be restored here.
	slices.SortFunc(out, func(a, b auth.Session) int {
		if c := a.CreatedAt.Compare(b.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.ID, b.ID)
	})
	return out, nil
}

// SessionLister is discovered by type assertion on the session store
// (Service.ListAllSessions), so a drift here is M8's GET /admin/api/sessions
// answering the reference's 501 from a binary that built. See interfaces.go for
// the convention.
var _ auth.SessionLister = (*Store)(nil)

// GetAllSessions implements auth.SessionLister: one page of every session in the
// deployment, across all users and all tenants.
//
// It reads the session directory — one entry per session at
// GSI1PK = "SESSION", GSI1SK = <sessionID> — and resolves each entry to its
// session item. See sessionIndexItem for why that directory is a second item
// rather than a second index, and what it costs.
//
// # Ordering
//
// Session.ID ascending, which is the core's normative order exactly: the
// directory's sort key *is* the session id. No deviation, and nothing to
// restore after the BatchGetItem — pagedIndexQuery puts the items back in index
// order, which is the whole reason it does that work.
//
// # What is not filtered
//
// Nothing. Revoked and expired sessions both come back, matching
// ListSessionsForUser and for the same reason: this port tombstones a revoked
// session rather than deleting it, because /refresh needs the tombstone to
// answer SESSION_REVOKED instead of "not found". Dropping the dead ones is the
// presentation layer's job. The core's interface doc says "all active sessions"
// and gets that for free only because its own revokeSession deletes the row.
//
// # Tenancy
//
// There is none, deliberately, and the asymmetry with ListUsers is the core's:
// a tenant parameter on the user lister buys reachability, where here every
// session is already listable and Session.TenantID rides on each record
// returned, so a tenant parameter would buy a predicate the caller can apply
// itself at the price of a signature the reference does not have.
func (s *Store) GetAllSessions(ctx context.Context, limit, offset int) ([]auth.Session, error) {
	items, err := s.pagedIndexQuery(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :pk"),
		ExpressionAttributeNames: exprNames(attrGSI1PK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(gsi1AllSessionsPK),
		},
		// The directory entry shares the session's partition, so the session
		// itself is one sort key away and needs no lookup to address.
	}, limit, offset, canonicalKeyInSamePartition(skSession))
	if err != nil {
		if errors.Is(err, ErrPageWindowTooLarge) {
			return nil, err
		}
		return nil, wrap("list all sessions", err)
	}
	// The page spans accounts, so their session epochs are read in one batch
	// and each session is held to its own account's (session_epoch.go).
	epochs, err := s.sessionEpochs(ctx, items)
	if err != nil {
		return nil, err
	}
	out := make([]auth.Session, 0, len(items))
	for _, m := range items {
		sess, err := sessionFromItem(m)
		if err != nil {
			return nil, err
		}
		epochs[userPK(sess.TenantID, sess.UserID)].honour(&sess, m)
		out = append(out, sess)
	}
	return out, nil
}

// sessionKeysForUser returns the main-table keys of a user's sessions.
func (s *Store) sessionKeysForUser(ctx context.Context, userID, tenantID string) ([]map[string]types.AttributeValue, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return nil, err
	}
	if err := checkID("user id", userID); err != nil {
		return nil, err
	}
	// No ConsistentRead: a GSI does not support it.
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :owner AND begins_with(#GSI1SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrGSI1PK, attrGSI1SK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":owner":  avS(userPK(tenantID, userID)),
			":prefix": avS(skSession + keySep),
		},
	}, s.maxSessions)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap("query sessions for user", err)
	}
	keys := make([]map[string]types.AttributeValue, 0, len(items))
	for _, m := range items {
		keys = append(keys, key(getS(m, attrPK), getS(m, attrSK)))
	}
	return keys, nil
}

// RevokeSessionByID implements SessionAdminStore.
func (s *Store) RevokeSessionByID(ctx context.Context, sessionID string) error {
	if err := checkID("session id", sessionID); err != nil {
		return auth.ErrSessionNotFound
	}
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key:       key(sessionPK(sessionID), skSession),
		// if_not_exists keeps an earlier revocation — a replay, say — from being
		// relabelled as an administrative one.
		UpdateExpression:         aws.String("SET #revokedAt = if_not_exists(#revokedAt, :now), #revokedReason = if_not_exists(#revokedReason, :reason), #updatedAt = :now"),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: exprNames(attrPK, attrRevokedAt, attrRevokedReason, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":now":    avS(formatTime(s.nowUTC())),
			":reason": avS(reasonAdmin),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return auth.ErrSessionNotFound
		}
		return wrap("revoke session by id", err)
	}
	return nil
}

// DeleteExpiredSessions implements SessionAdminStore as a no-op.
//
// Expiry is DynamoDB TTL (§4.5), so there is nothing for a cron to delete and no
// count to report. Producing a real number would need an EXPIRES#<bucket> index
// — an extra GSI plus a write on every session — to reproduce a figure whose only
// documented consumer is the cron job itself. POST /sessions/cleanup therefore
// answers deleted:0; see CompatibilityNotes.
func (s *Store) DeleteExpiredSessions(_ context.Context, _ time.Time) (int, error) {
	return 0, nil
}

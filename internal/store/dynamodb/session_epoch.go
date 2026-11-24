package dynamodb

import (
	"context"
	"log/slog"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// auth.UserSessionRevoker (core v0.16.0): end every session of an account in
// one call. Under sessions.revokeOnPasswordReset the core's ResetPassword calls
// it once the new password is stored, and prefers it to listing the account's
// sessions and revoking them one by one.
//
// ── why not the listing ─────────────────────────────────────────────────────
//
// This store cannot list an account's sessions exactly. A session lives in its
// own partition, SESSION#<sid>, because three of the five session methods carry
// neither user nor tenant (data-model.md §2.3), and the by-user listing is the
// sparse GSI1, which is eventually consistent — a session created just before a
// reset may not be in it yet — and which ListSessionsForUser refuses past
// MaxSessionsPerUser. Revoking from it would miss exactly the session the
// contract names (one whose creation had returned when the call began), and
// would fail every reset of an account over the cap with nothing revoked. A
// complete paged revocation needs a consistent per-account listing, which means
// writing every session a second time into the user's partition and revoking
// them one UpdateItem each: as many writes as sessions, any of which can fail
// half-way through a reset that has already changed the password.
//
// ── the account's session epoch ─────────────────────────────────────────────
//
// So the revocation is one write, and every read honours it. Each account has
// an epoch: a counter on one item in its own partition,
//
//	USER#<t>#<u> / EPOCH   epoch, revokedAt, revokedReason
//
// that RevokeSessionsForUser raises by one (UpdateItem ADD, which creates the
// item the first time). CreateSession reads the epoch before it writes the
// session, consistently, and stamps the session with it; and wherever a
// session is read — the refresh, the lookup by id, both listings — a session
// stamped below the account's current epoch is reported revoked, with
// RevokedAt the time of the latest raise. Missing values are 0: a session
// written before this existed carries no stamp, an account never revoked has
// no item, so nothing changes until the first revocation, which ends every
// earlier session at once.
//
// Why that meets the contract exactly. A session whose CreateSession had
// returned when the call began read the epoch before its write, so before the
// call, and a consistent read sees every raise that has returned: its stamp is
// at most the epoch the call raises from, and below the epoch the call leaves.
// It is ordered by a counter of the store's own, not by Session.CreatedAt, so
// no clock is compared with another (the core's UserSessionRevoker doc names
// the skew a time-based record is exposed to). A session whose creation
// overlaps the call may read the epoch before the raise and be revoked with
// the rest: over-revocation, never under. One created after it reads the new
// epoch and lives. No index is read, nothing is capped, and the cost of a reset
// does not grow with the account's sessions.
//
// What it costs everyone else, because it is paid whether or not the option is
// on — a marker that stopped being honoured when the option was turned off
// would bring every session a reset had ended back to life: one consistent
// GetItem per CreateSession, one more item in the BatchGetItem every refresh
// already makes (the pointer names the account, so the session and the epoch
// are read together), one GetItem after each rotation (rotate), and one per
// lookup by id, which is every request under sessions.checkOn: allcalls.
// docs/cost-model.md prices it.
//
// Rolling back to a build that predates this ignores the epoch: a session a
// reset ended works again, until it expires, on the build that does not read
// the marker. The item and the stamp are added attributes (data-model.md §7
// rule 2), so the old build reads the rest without complaint.

// Attributes of the epoch item; the session item carries attrEpoch too, as its
// stamp. attrRevokedAt and attrRevokedReason are the session item's names, on
// purpose: the epoch item records the same fact about every session below it.
const (
	attrEpoch = "epoch"
)

// reasonPasswordReset labels the account-wide revocation. The core calls
// RevokeSessionsForUser from ResetPassword alone (v0.16.0); a pin that adds a
// caller revisits the label.
const reasonPasswordReset = "password_reset"

// The core finds the revoker by type assertion on the session store, so a
// drifted signature would be a reset that falls back to the capped listing
// from a binary that built cleanly. See interfaces.go for the convention.
var _ auth.UserSessionRevoker = (*Store)(nil)

func sessionEpochKey(tenantID, userID string) map[string]types.AttributeValue {
	return key(userPK(tenantID, userID), skSessionEpoch)
}

// sessionEpoch is what an account's epoch item says: the epoch, and when it
// was last raised. The zero value is an account never revoked.
type sessionEpoch struct {
	epoch     int64
	revokedAt *time.Time
}

func epochFromItem(m map[string]types.AttributeValue) (sessionEpoch, error) {
	if len(m) == 0 {
		return sessionEpoch{}, nil
	}
	if err := checkVersion(m, typeSessionEpoch); err != nil {
		return sessionEpoch{}, err
	}
	at, err := getTimePtr(m, attrRevokedAt)
	if err != nil {
		return sessionEpoch{}, err
	}
	return sessionEpoch{epoch: getN(m, attrEpoch), revokedAt: at}, nil
}

// ends reports whether the epoch ends a session stamped stamp.
func (e sessionEpoch) ends(stamp int64) bool { return stamp < e.epoch }

// honour reports the session read from item as revoked when the account's
// epoch has moved past its stamp. A session already revoked keeps its own
// revocation, which is what the core's contract allows and what the store
// register promises for every second revocation.
func (e sessionEpoch) honour(sess *auth.Session, item map[string]types.AttributeValue) {
	if sess.RevokedAt != nil || !e.ends(getN(item, attrEpoch)) {
		return
	}
	// The raise always writes revokedAt; the zero time is for an item written
	// by hand without one, which is still a revocation.
	at := time.Time{}
	if e.revokedAt != nil {
		at = *e.revokedAt
	}
	sess.RevokedAt = &at
}

// readSessionEpoch reads an account's epoch, consistently: a read that missed a
// raise that had returned would stamp a new session below it, revoking a
// session opened after the reset, or honour a stale epoch and let one opened
// before it through.
func (s *Store) readSessionEpoch(ctx context.Context, tenantID, userID string) (sessionEpoch, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            sessionEpochKey(tenantID, userID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return sessionEpoch{}, wrap("read session epoch", err)
	}
	return epochFromItem(out.Item)
}

// RevokeSessionsForUser implements auth.UserSessionRevoker: it raises the
// account's epoch, which ends every session stamped below the new value — every
// session of userID under tenantID whose creation had returned when the call
// began. One UpdateItem, unconditional: it creates the item the first time, and
// a second call raises it again, which ends nothing the first did not but the
// sessions opened in between.
//
// It is not conditioned on the account existing, because nothing here can
// check another item in the same write — the function's role grants no
// ConditionCheckItem — and because the core calls it right after it has
// written the account's password. An item for an id with no account ends
// sessions nobody can refresh, and DeleteUser removes it with the rest of the
// account's partition.
func (s *Store) RevokeSessionsForUser(ctx context.Context, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}
	now := formatTime(s.nowUTC())
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              sessionEpochKey(tenantID, userID),
		UpdateExpression: aws.String("SET #_t = :t, #_v = :v, #revokedAt = :now, #revokedReason = :reason, #updatedAt = :now ADD #epoch :one"),
		ExpressionAttributeNames: exprNames(attrType, attrVer, attrRevokedAt, attrRevokedReason,
			attrUpdatedAt, attrEpoch),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":t":      avS(typeSessionEpoch),
			":v":      avN(schemaVersion),
			":now":    avS(now),
			":reason": avS(reasonPasswordReset),
			":one":    avN(1),
		},
	})
	if err != nil {
		return wrap("revoke sessions for user", err)
	}
	return nil
}

// sessionEpochs reads the epochs of the accounts that own items, in one batch,
// keyed by the account's partition key. GetAllSessions spans accounts, so its
// page names several.
func (s *Store) sessionEpochs(ctx context.Context, items []map[string]types.AttributeValue) (map[string]sessionEpoch, error) {
	seen := make(map[string]bool, len(items))
	keys := make([]map[string]types.AttributeValue, 0, len(items))
	for _, m := range items {
		pk := userPK(getS(m, attrTenantID), getS(m, attrUserID))
		if seen[pk] {
			continue
		}
		seen[pk] = true
		keys = append(keys, key(pk, skSessionEpoch))
	}
	out := make(map[string]sessionEpoch, len(keys))
	if len(keys) == 0 {
		return out, nil
	}
	got, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, wrap("read session epochs", err)
	}
	for _, m := range got {
		e, err := epochFromItem(m)
		if err != nil {
			return nil, err
		}
		out[getS(m, attrPK)] = e
	}
	return out, nil
}

// rotationOutlivedARevocation is the check rotate makes once its transaction
// has committed: a refresh that read the session before the account's epoch was
// raised and rotated it after is answered auth.ErrSessionRevoked, as a
// rotation of a session revoked by id is, so its tokens are never handed out.
// The rotated session is stamped below the epoch either way and refuses its
// next refresh; this ends the one in flight.
//
// stamp is the session's own, from the precondition GetSessionByRefreshTokenHash
// recorded when there is one; without it the session item is read beside the
// epoch. A read that fails is logged and the rotation stands — fail open,
// because the tokens are minted and the write is done, and the epoch still ends
// the session at its next read.
func (s *Store) rotationOutlivedARevocation(ctx context.Context, sess auth.Session, pre rotationPrecondition) error {
	var (
		e     sessionEpoch
		stamp = pre.epoch
		err   error
	)
	if pre.hasEpoch {
		e, err = s.readSessionEpoch(ctx, sess.TenantID, sess.UserID)
	} else {
		e, stamp, err = s.sessionAndEpoch(ctx, sess)
	}
	if err != nil {
		s.log.Warn("dynamodb: a refresh rotated its session but could not read the account's session epoch afterwards; "+
			"the rotation stands, and a revocation it raced is enforced at the session's next read",
			slog.String("error", err.Error()))
		return nil
	}
	if e.ends(stamp) {
		return auth.ErrSessionRevoked
	}
	return nil
}

// sessionAndEpoch reads a session's stamp and its account's epoch in one
// consistent batch, for a rotation that was not handed the stamp.
func (s *Store) sessionAndEpoch(ctx context.Context, sess auth.Session) (sessionEpoch, int64, error) {
	items, err := s.batchGet(ctx, []map[string]types.AttributeValue{
		key(sessionPK(sess.ID), skSession),
		sessionEpochKey(sess.TenantID, sess.UserID),
	})
	if err != nil {
		return sessionEpoch{}, 0, err
	}
	var (
		e     sessionEpoch
		stamp int64
	)
	for _, m := range items {
		switch getS(m, attrSK) {
		case skSession:
			stamp = getN(m, attrEpoch)
		case skSessionEpoch:
			if e, err = epochFromItem(m); err != nil {
				return sessionEpoch{}, 0, err
			}
		}
	}
	return e, stamp, nil
}

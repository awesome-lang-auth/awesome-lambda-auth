package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// auth.InvitationStore (awesome-go-auth v0.15.0): the staff invitations an
// administrator — or a back office through admin.machineAccess — creates, and
// an invitee redeems once at POST <prefix>/invitations/accept.
//
// The core's default is MemoryInvitationStore, which its own comment calls
// "correct only while every request is served by the same process". Under
// Lambda that is never, so this is the shared implementation the interface's
// doc comment asks for, and it follows the layout that comment sketches for
// DynamoDB, in this table's key conventions.
//
// ── three items per invitation ──────────────────────────────────────────────
//
//	INV#<id>             / INV       the record: every Invitation field, the
//	                                 token's SHA-256 (never the token), and —
//	                                 while pending — GSI1PK=INVITATION,
//	                                 GSI1SK=<id>, the listing's sparse entry.
//	INVTOKEN#<tokenHash> / INVTOKEN  the pointer ConsumeInvitation finds the id
//	                                 by, while the invitation is pending; it
//	                                 carries the id and nothing else.
//	INVUSER#<userId>     / INV#<id>  one membership item per *pending*
//	                                 invitation, in the user's own partition.
//
// All three are written by one transaction, each Put conditioned on
// attribute_not_exists(PK), and none of them carries a ttl (see retention).
//
// The membership item is the per-user access pattern, and it is an item rather
// than an index on purpose: PendingInvitationsForUser must be a consistent read
// ("it reflects every create, consume and revoke that returned before it was
// called"), a GSI cannot be read consistently, and the membership item leaves
// its partition in the very transaction that ends the invitation. The user's
// partition is keyed by the user id alone, as USERMETA#<u> is, because the
// method carries no tenant (keys.go, pkUserMetaPrefix, argues why that is
// exactly as isolating).
//
// The listing (ListPendingInvitations) is the one eventually consistent read,
// a Query of the constant GSI1 partition INVITATION, sorted by id as the
// contract wants. Each entry is re-read from the record, consistently, and a
// record that has left the pending state since the index was written is
// dropped without shortening the page (pagedIndexQueryKeeping).
//
// ── single use ──────────────────────────────────────────────────────────────
//
// Consume, revoke and release are each one TransactWriteItems whose Update of
// the record carries the whole state condition; nothing is decided by a read
// that a write does not re-assert:
//
//   - consume: attribute_not_exists(acceptedAt) AND attribute_not_exists(
//     revokedAt) AND expiresAt > :now AND tokenHash = :hash, SET acceptedAt
//     and the record's ttl, REMOVE the GSI1 pair; and Delete of the
//     membership item and of the token pointer.
//   - revoke: the same with the expiry clause dropped, SET revokedAt.
//   - release: acceptedAt = :acceptedAt AND attribute_not_exists(revokedAt),
//     REMOVE acceptedAt and the ttl, SET the GSI1 pair again; and Put of the
//     membership item and of the token pointer.
//
// Timestamps use this table's fixed-width tsLayout (item.go), so the string
// comparison expiresAt > :now is chronological and acceptedAt = :acceptedAt
// tells instants apart to the nanosecond: the release names the consume it
// undoes by that instant, and a release that arrives twice, or late, finds a
// different one. The expiry is decided against the now the call is given, never
// left to TTL.
//
// Every call is a GetItem, Query, BatchGetItem or a transaction of
// Put/Update/Delete — no bare ConditionCheck — so the function role's existing
// AuthTableItems and AuthTableIndexQuery grants cover all of it, and
// iam_test.go pins that.
//
// ── retention ───────────────────────────────────────────────────────────────
//
// A pending invitation carries no ttl, on any of its three items, expired or
// not. The core keeps a pending record listed, revocable and reserving its
// account until it is revoked (invitation.go, Invitation), and the account it
// created carries no ttl: a sweep that reaped the invitation would leave a
// passwordless account that nothing lists or revokes, that a re-invitation
// answers 409 for, and that /forgot-password reaches — a reset there leaves a
// password on an unverified address, which neither the login nor an
// invitation accepts. An offer that is meant to lapse is revoked, through the
// core, which also removes the untouched account; never by TTL.
//
// The transaction that ends an invitation — the consume or the revoke — sets
// the record's ttl to Options.InvitationRetention (30 days by default) past
// its expiry or its end, whichever is later, and deletes the other two items;
// a release removes the ttl and puts them back. DynamoDB deletes the ended
// record some time after its ttl — best effort, within about 48 hours — and a
// second revocation then answers ErrInvitationNotFound where it answered
// ErrInvitationNotPending, as the core's memory store does once it forgets an
// ended record a day after its end. Nothing reads ttl: an expired token is
// refused by the consume's condition, never by the sweep.

var _ auth.InvitationStore = (*Store)(nil)

// Invitations returns the auth.InvitationStore view of this store. The core
// does not discover it — it is handed over through auth.WithInvitationStore by
// the composition root, behind invitations.enabled — so this is an accessor in
// the shape of AuthCodes().
func (s *Store) Invitations() auth.InvitationStore { return s }

// DefaultInvitationRetention is how long an accepted or revoked invitation's
// record is kept — past its expiry or its end, whichever is later — before TTL
// may delete it. A pending invitation is never given a ttl.
const DefaultInvitationRetention = 30 * 24 * time.Hour

// maxPendingInvitationsPerUser caps PendingInvitationsForUser, which takes no
// cursor. A re-invitation retires the earlier tokens once it is delivered, so
// a user with more than a handful outstanding is a race or a fault, and a
// thousand is an incident rather than a page.
const maxPendingInvitationsPerUser = 1000

// maxTokenHashLen bounds the hash segment of INVTOKEN#<hash>. The core's hash
// is 64 hex digits; the bound is generous and only refuses a value DynamoDB
// would.
const maxTokenHashLen = 256

const (
	typeInvitation       = "invitation"
	typeInvitationToken  = "invtoken"
	typeInvitationMember = "invuser"

	pkInvitationPrefix      = "INV" + keySep
	pkInvitationTokenPrefix = "INVTOKEN" + keySep
	pkInvitationUserPrefix  = "INVUSER" + keySep

	skInvitation             = "INV"
	skInvitationToken        = "INVTOKEN"
	skInvitationMemberPrefix = "INV" + keySep

	// gsi1PendingInvitationsPK is the constant GSI1 partition of the pending
	// listing, like gsi1AllUsersPK. A partition key is matched by equality
	// only, so it cannot meet the prefixed values other items write.
	gsi1PendingInvitationsPK = "INVITATION"
)

const (
	attrInvitationID   = "invitationId"
	attrTokenHash      = "tokenHash"
	attrInvitationMeta = "metadata"
	attrInvitedBy      = "invitedBy"
	attrInvitedByKind  = "invitedByKind"
	attrAcceptedAt     = "acceptedAt"
)

func invitationPK(id string) string         { return pkInvitationPrefix + id }
func invitationTokenPK(hash string) string  { return pkInvitationTokenPrefix + hash }
func invitationUserPK(userID string) string { return pkInvitationUserPrefix + userID }
func invitationMemberSK(id string) string   { return skInvitationMemberPrefix + id }
func invitationRecordKey(id string) itemKey { return key(invitationPK(id), skInvitation) }
func invitationMemberKey(userID, id string) itemKey {
	return key(invitationUserPK(userID), invitationMemberSK(id))
}

// itemKey is a main-table primary key.
type itemKey = map[string]types.AttributeValue

// endedTTL is the ttl the transaction that ends inv at ended gives its record:
// the retention past its expiry or its end, whichever is later. The ttl is an
// attribute of an ended record only; see retention in the file comment.
func (s *Store) endedTTL(inv auth.Invitation, ended time.Time) types.AttributeValue {
	from := inv.ExpiresAt
	if ended.After(from) {
		from = ended
	}
	return avN(from.Add(s.invitationRetention).Unix())
}

// CreateInvitation writes the record, the token pointer and — for a pending
// record, which is every record the core creates — the membership item, in one
// transaction, none of them with a ttl. An id or a token hash already held is
// auth.ErrAlreadyExists, as MemoryInvitationStore answers; both are random, so
// it is a caller's bug.
func (s *Store) CreateInvitation(ctx context.Context, inv auth.Invitation) error {
	if inv.ID == "" || inv.TokenHash == "" {
		return errors.New("dynamodb: invitation needs an id and a token hash")
	}
	if err := checkID("invitation id", inv.ID); err != nil {
		return err
	}
	if err := checkOpaque("invitation token hash", inv.TokenHash, maxTokenHashLen); err != nil {
		return err
	}
	if err := checkID("user id", inv.UserID); err != nil {
		return err
	}
	if err := s.checkTenant(inv.TenantID); err != nil {
		return err
	}

	record, err := invitationItem(inv)
	if err != nil {
		return err
	}

	notThere := aws.String("attribute_not_exists(#PK)")
	names := exprNames(attrPK)
	items := []types.TransactWriteItem{
		{Put: &types.Put{TableName: aws.String(s.table), Item: record, ConditionExpression: notThere, ExpressionAttributeNames: names}},
		{Put: &types.Put{TableName: aws.String(s.table), Item: invitationPointerItem(inv), ConditionExpression: notThere, ExpressionAttributeNames: names}},
	}
	if inv.Pending() {
		member := invitationMemberItem(inv)
		items = append(items, types.TransactWriteItem{
			Put: &types.Put{TableName: aws.String(s.table), Item: member, ConditionExpression: notThere, ExpressionAttributeNames: names},
		})
	}
	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{TransactItems: items})
	if reasons, cancelled := txConditionFailures(err); cancelled && anyConditionFailed(reasons) {
		return auth.ErrAlreadyExists
	}
	return wrap("create invitation", err)
}

// ConsumeInvitation accepts the pending, unexpired invitation stored under
// tokenHash, once. See the file comment for the transaction; every way it can
// be refused — an unknown or malformed hash, a missing record, an expired,
// accepted or revoked one, the loser of a race — is auth.ErrInvitationNotFound
// with no record, and nothing tells them apart.
//
// The record returned is the one read before the transaction with AcceptedAt
// set to now, not a read after it: the transaction's condition is the proof
// that the pre-read record was the pending one it updated, and a read after the
// commit that failed would leave a spent token the caller had no record to
// release.
//
// A transaction cancelled by contention alone — no condition was evaluated —
// after transactWrite's retries is an ordinary error, not ErrInvitationNotFound:
// nothing was written, so the token is still good and the caller's 500 is the
// honest answer.
func (s *Store) ConsumeInvitation(ctx context.Context, tokenHash string, now time.Time) (auth.Invitation, error) {
	if checkOpaque("invitation token hash", tokenHash, maxTokenHashLen) != nil {
		return auth.Invitation{}, auth.ErrInvitationNotFound
	}
	pointer, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(invitationTokenPK(tokenHash), skInvitationToken),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.Invitation{}, wrap("get invitation token", err)
	}
	id := getS(pointer.Item, attrInvitationID)
	if len(pointer.Item) == 0 || checkID("invitation id", id) != nil {
		return auth.Invitation{}, auth.ErrInvitationNotFound
	}
	inv, found, err := s.readInvitation(ctx, id)
	if err != nil {
		return auth.Invitation{}, err
	}
	if !found || !inv.Pending() || inv.Expired(now) || inv.TokenHash != tokenHash || checkID("user id", inv.UserID) != nil {
		return auth.Invitation{}, auth.ErrInvitationNotFound
	}

	accepted := now.UTC()
	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName: aws.String(s.table),
			Key:       invitationRecordKey(id),
			ConditionExpression: aws.String("attribute_exists(#PK) AND attribute_not_exists(#acceptedAt) AND " +
				"attribute_not_exists(#revokedAt) AND #expiresAt > :now AND #tokenHash = :hash"),
			UpdateExpression:         aws.String("SET #acceptedAt = :now, #ttl = :ttl REMOVE #GSI1PK, #GSI1SK"),
			ExpressionAttributeNames: exprNames(attrPK, attrAcceptedAt, attrRevokedAt, attrExpiresAt, attrTokenHash, attrTTL, attrGSI1PK, attrGSI1SK),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":now":  avS(formatTime(accepted)),
				":hash": avS(tokenHash),
				":ttl":  s.endedTTL(inv, accepted),
			},
		}},
		{Delete: &types.Delete{
			TableName: aws.String(s.table),
			Key:       invitationMemberKey(inv.UserID, id),
		}},
		// The pointer lives exactly as long as the pending state: a replay
		// finds nothing, and ReleaseInvitation puts it back.
		{Delete: &types.Delete{
			TableName: aws.String(s.table),
			Key:       key(invitationTokenPK(tokenHash), skInvitationToken),
		}},
	}})
	if reasons, cancelled := txConditionFailures(err); cancelled && anyConditionFailed(reasons) {
		return auth.Invitation{}, auth.ErrInvitationNotFound
	}
	if err != nil {
		return auth.Invitation{}, wrap("consume invitation", err)
	}
	inv.AcceptedAt = &accepted
	return inv, nil
}

// RevokeInvitation revokes the pending invitation id, expired or not, and
// returns it. An accepted or already revoked one is returned unchanged with
// auth.ErrInvitationNotPending; an unknown or malformed id is
// auth.ErrInvitationNotFound — the admin route's 404, where a malformed id
// reported as ErrInvalidIdentifier would be its 500.
func (s *Store) RevokeInvitation(ctx context.Context, id string, now time.Time) (auth.Invitation, error) {
	if checkID("invitation id", id) != nil {
		return auth.Invitation{}, auth.ErrInvitationNotFound
	}
	inv, found, err := s.readInvitation(ctx, id)
	if err != nil {
		return auth.Invitation{}, err
	}
	if !found {
		return auth.Invitation{}, auth.ErrInvitationNotFound
	}
	if !inv.Pending() {
		return inv, auth.ErrInvitationNotPending
	}

	revoked := now.UTC()
	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                aws.String(s.table),
			Key:                      invitationRecordKey(id),
			ConditionExpression:      aws.String("attribute_exists(#PK) AND attribute_not_exists(#acceptedAt) AND attribute_not_exists(#revokedAt)"),
			UpdateExpression:         aws.String("SET #revokedAt = :now, #ttl = :ttl REMOVE #GSI1PK, #GSI1SK"),
			ExpressionAttributeNames: exprNames(attrPK, attrAcceptedAt, attrRevokedAt, attrTTL, attrGSI1PK, attrGSI1SK),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":now": avS(formatTime(revoked)),
				":ttl": s.endedTTL(inv, revoked),
			},
			ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
		}},
		// Both unconditioned: the record's condition is the only one, so a
		// cancellation below is always the record's (index 0).
		{Delete: &types.Delete{
			TableName: aws.String(s.table),
			Key:       invitationMemberKey(inv.UserID, id),
		}},
		{Delete: &types.Delete{
			TableName: aws.String(s.table),
			Key:       key(invitationTokenPK(inv.TokenHash), skInvitationToken),
		}},
	}})
	if reasons, cancelled := txConditionFailures(err); cancelled && anyConditionFailed(reasons) {
		// The record changed between the read and the write: a consume or
		// another revoke landed first. Its pre-image says which; without one,
		// a consistent re-read does.
		current, ok := txFailedAt(reasons, 0)
		if ok && len(current) > 0 {
			if decoded, decodeErr := invitationFromItem(current); decodeErr == nil {
				return decoded, auth.ErrInvitationNotPending
			}
		}
		again, found, readErr := s.readInvitation(ctx, id)
		switch {
		case readErr != nil:
			return auth.Invitation{}, readErr
		case !found:
			return auth.Invitation{}, auth.ErrInvitationNotFound
		default:
			return again, auth.ErrInvitationNotPending
		}
	}
	if err != nil {
		return auth.Invitation{}, wrap("revoke invitation", err)
	}
	inv.RevokedAt = &revoked
	return inv, nil
}

// ReleaseInvitation hands back the consume that accepted invitation id at
// acceptedAt, when the acceptance that made it could not be completed: the
// record is pending again, listed, with no ttl, and its membership item and
// token pointer are back. Anything else — an unknown id, a pending or revoked
// record, one accepted at another instant — is auth.ErrInvitationNotFound and
// changes nothing.
func (s *Store) ReleaseInvitation(ctx context.Context, id string, acceptedAt time.Time) error {
	if checkID("invitation id", id) != nil {
		return auth.ErrInvitationNotFound
	}
	inv, found, err := s.readInvitation(ctx, id)
	if err != nil {
		return err
	}
	if !found || inv.AcceptedAt == nil || inv.RevokedAt != nil || !inv.AcceptedAt.Equal(acceptedAt) ||
		checkID("user id", inv.UserID) != nil || checkOpaque("invitation token hash", inv.TokenHash, maxTokenHashLen) != nil {
		return auth.ErrInvitationNotFound
	}

	pending := inv
	pending.AcceptedAt = nil
	err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{TransactItems: []types.TransactWriteItem{
		{Update: &types.Update{
			TableName:                aws.String(s.table),
			Key:                      invitationRecordKey(id),
			ConditionExpression:      aws.String("#acceptedAt = :acceptedAt AND attribute_not_exists(#revokedAt)"),
			UpdateExpression:         aws.String("SET #GSI1PK = :gsi1pk, #GSI1SK = :id REMOVE #acceptedAt, #ttl"),
			ExpressionAttributeNames: exprNames(attrAcceptedAt, attrRevokedAt, attrTTL, attrGSI1PK, attrGSI1SK),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":acceptedAt": avS(formatTime(acceptedAt)),
				":gsi1pk":     avS(gsi1PendingInvitationsPK),
				":id":         avS(id),
			},
		}},
		{Put: &types.Put{
			TableName: aws.String(s.table),
			Item:      invitationMemberItem(pending),
		}},
		{Put: &types.Put{
			TableName: aws.String(s.table),
			Item:      invitationPointerItem(pending),
		}},
	}})
	if reasons, cancelled := txConditionFailures(err); cancelled && anyConditionFailed(reasons) {
		return auth.ErrInvitationNotFound
	}
	return wrap("release invitation", err)
}

// ListPendingInvitations pages the invitations neither accepted nor revoked,
// expired ones included, by id ascending, under pageWindow's rules. It reads
// GSI1, which lags writes: an invitation created a moment ago may be missing,
// and one ended a moment ago is dropped when its record is re-read.
func (s *Store) ListPendingInvitations(ctx context.Context, limit, offset int) ([]auth.Invitation, error) {
	items, err := s.pagedIndexQueryKeeping(ctx, &awsddb.QueryInput{
		TableName:                 aws.String(s.table),
		IndexName:                 aws.String(s.index),
		KeyConditionExpression:    aws.String("#GSI1PK = :pk"),
		ExpressionAttributeNames:  exprNames(attrGSI1PK),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(gsi1PendingInvitationsPK)},
	}, limit, offset, canonicalKeyOfEntry, func(m map[string]types.AttributeValue) bool {
		_, accepted := m[attrAcceptedAt]
		_, revoked := m[attrRevokedAt]
		return getS(m, attrType) == typeInvitation && !accepted && !revoked
	})
	if err != nil {
		return nil, wrap("list pending invitations", err)
	}
	out := make([]auth.Invitation, 0, len(items))
	for _, m := range items {
		inv, err := invitationFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, inv)
	}
	return out, nil
}

// PendingInvitationsForUser returns userID's pending invitations, expired ones
// included, by id ascending, from a consistent Query of the user's membership
// partition and a consistent BatchGetItem of the records it names. A malformed
// user id cannot own an invitation, so it has none.
func (s *Store) PendingInvitationsForUser(ctx context.Context, userID string) ([]auth.Invitation, error) {
	if checkID("user id", userID) != nil {
		return []auth.Invitation{}, nil
	}
	members, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                 aws.String(s.table),
		KeyConditionExpression:    aws.String("#PK = :pk"),
		ExpressionAttributeNames:  exprNames(attrPK),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(invitationUserPK(userID))},
		ConsistentRead:            aws.Bool(true),
	}, maxPendingInvitationsPerUser)
	if err != nil {
		return nil, wrap("query user invitations", err)
	}
	keys := make([]map[string]types.AttributeValue, 0, len(members))
	for _, m := range members {
		if id := getS(m, attrInvitationID); checkID("invitation id", id) == nil {
			keys = append(keys, invitationRecordKey(id))
		}
	}
	records, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, wrap("get user invitations", err)
	}
	out := make([]auth.Invitation, 0, len(records))
	for _, m := range records {
		inv, err := invitationFromItem(m)
		if err != nil {
			return nil, err
		}
		// The membership item and the record change in one transaction, so a
		// mismatch is a hand-edited table; the record is the authority.
		if inv.Pending() && inv.UserID == userID {
			out = append(out, inv)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// readInvitation is a consistent read of the record.
func (s *Store) readInvitation(ctx context.Context, id string) (auth.Invitation, bool, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            invitationRecordKey(id),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.Invitation{}, false, wrap("get invitation", err)
	}
	if len(out.Item) == 0 {
		return auth.Invitation{}, false, nil
	}
	inv, err := invitationFromItem(out.Item)
	if err != nil {
		return auth.Invitation{}, false, err
	}
	return inv, true, nil
}

// invitationItem encodes the record. The GSI1 pair is written only while the
// record is pending: the listing's index is sparse, and its membership is the
// pending state.
func invitationItem(inv auth.Invitation) (item, error) {
	it := item{}.
		sAlways(attrPK, invitationPK(inv.ID)).
		sAlways(attrSK, skInvitation).
		stamp(typeInvitation).
		sAlways(attrTokenHash, inv.TokenHash).
		s(attrUserID, inv.UserID).
		s(attrTenantID, inv.TenantID).
		s(attrEmail, inv.Email).
		s(attrRole, inv.Role).
		s(attrInvitedBy, inv.InvitedBy).
		s(attrInvitedByKind, inv.InvitedByKind).
		t(attrCreatedAt, inv.CreatedAt).
		t(attrExpiresAt, inv.ExpiresAt).
		tp(attrAcceptedAt, inv.AcceptedAt).
		tp(attrRevokedAt, inv.RevokedAt)
	if inv.Metadata != nil {
		meta, err := anyMapAV(inv.Metadata)
		if err != nil {
			return nil, fmt.Errorf("dynamodb: invitation metadata: %w", err)
		}
		it = it.av(attrInvitationMeta, meta)
	}
	if inv.Pending() {
		it = it.sAlways(attrGSI1PK, gsi1PendingInvitationsPK).sAlways(attrGSI1SK, inv.ID)
	}
	return it, nil
}

// invitationMemberItem is the membership item of a pending invitation. It
// carries no ttl: it exists only while the invitation is pending.
func invitationMemberItem(inv auth.Invitation) item {
	return item{}.
		sAlways(attrPK, invitationUserPK(inv.UserID)).
		sAlways(attrSK, invitationMemberSK(inv.ID)).
		stamp(typeInvitationMember).
		sAlways(attrInvitationID, inv.ID)
}

// invitationPointerItem is the token pointer of a pending invitation. Like the
// membership item it carries no ttl and exists only while the invitation is
// pending.
func invitationPointerItem(inv auth.Invitation) item {
	return item{}.
		sAlways(attrPK, invitationTokenPK(inv.TokenHash)).
		sAlways(attrSK, skInvitationToken).
		stamp(typeInvitationToken).
		sAlways(attrInvitationID, inv.ID)
}

func invitationFromItem(m map[string]types.AttributeValue) (auth.Invitation, error) {
	if err := checkVersion(m, typeInvitation); err != nil {
		return auth.Invitation{}, err
	}
	pk, ok := m[attrPK].(*types.AttributeValueMemberS)
	if !ok || len(pk.Value) <= len(pkInvitationPrefix) {
		return auth.Invitation{}, fmt.Errorf("dynamodb: invitation item has no key")
	}
	inv := auth.Invitation{
		ID:            pk.Value[len(pkInvitationPrefix):],
		TokenHash:     getS(m, attrTokenHash),
		UserID:        getS(m, attrUserID),
		TenantID:      getS(m, attrTenantID),
		Email:         getS(m, attrEmail),
		Role:          getS(m, attrRole),
		InvitedBy:     getS(m, attrInvitedBy),
		InvitedByKind: getS(m, attrInvitedByKind),
		Metadata:      anyMapFromAV(m[attrInvitationMeta]),
	}
	var err error
	if inv.CreatedAt, err = getTime(m, attrCreatedAt); err != nil {
		return auth.Invitation{}, err
	}
	if inv.ExpiresAt, err = getTime(m, attrExpiresAt); err != nil {
		return auth.Invitation{}, err
	}
	if inv.AcceptedAt, err = getTimePtr(m, attrAcceptedAt); err != nil {
		return auth.Invitation{}, err
	}
	if inv.RevokedAt, err = getTimePtr(m, attrRevokedAt); err != nil {
		return auth.Invitation{}, err
	}
	return inv, nil
}

// anyConditionFailed reports whether a cancelled transaction lost a condition,
// as opposed to contention alone, which transactWrite already retried.
func anyConditionFailed(reasons []types.CancellationReason) bool {
	for i := range reasons {
		if _, failed := txFailedAt(reasons, i); failed {
			return true
		}
	}
	return false
}

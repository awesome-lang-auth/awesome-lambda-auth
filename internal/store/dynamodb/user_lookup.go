package dynamodb

import (
	"context"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// The by-id user pointer: what makes auth.UserLookupStore (core v0.12.0) one
// GetItem on a table whose every user item has the tenant in its key.
//
// # Why a pointer, and not the membership index
//
// The core's interface doc names the two ways a key-value store can have an
// item keyed on the id alone: a pointer written beside the profile, the way
// EMAIL#<t>#<email> already is for GetUserByEmail, or an index entry the store
// already writes for another reason. This store has one of the second kind —
// the membership item's GSI1PK = USERID#<u>, which GetTenantsForUser reads — and
// it would cost no new write. It is not used, for the lifecycle hazard the same
// doc warns about: DisassociateUserFromTenant drops that membership and leaves
// the profile where it is (tenants.go), so a lookup through it would lose a user
// the console's listing still shows, which is the very mismatch the interface
// exists to remove. It would also be eventually consistent, and the profile read
// it leads to is not.
//
// So UID#<u> / UID is a pointer of its own (keys.go, pkUIDPrefix), carrying the
// tenant the profile lives under, and its lifecycle is the profile's exactly:
//
//   - createUser writes it in the profile's own transaction, conditioned on
//     attribute_not_exists — which is also what enforces the precondition the
//     whole interface rests on, that one id names at most one user across every
//     tenant. MemoryUserStore enforces it the same way, at CreateUser; this
//     store did not until now, because nothing needed it.
//   - DeleteUser removes it in the profile's own transaction, conditioned on the
//     pointer naming the tenant being deleted, so a delete under one tenant
//     cannot take away the pointer of a same-id record under another.
//   - Nothing else creates or removes a profile. CreateMigratedUser is
//     createUser with a marker; DeleteTenant removes memberships and never a
//     user; DisassociateUserFromTenant removes one membership; every other
//     profile write is an UpdateItem guarded by attribute_exists(PK).
//   - Profiles written before this release have no pointer, and the operator
//     backfill writes them (backfill.go), with the conflict rule below.
//
// # The profile stamp
//
// The profile carries uidPointer = true once its pointer exists. It is what lets
// the backfill find "profiles without a pointer" with a Scan filter on the
// profile alone — the pointer is another item, and a filter cannot see across
// items — so that a swept table, like a freshly written one, matches nothing.
// It is written by profileItem (so by createUser, in the same transaction as the
// pointer) and by the backfill (again in one transaction with the pointer), and
// read by nothing else. It is not projected into GSI1, so it costs the profile no
// index write.
//
// # Two records, one id
//
// A table written before this release can hold one id under two tenants:
// nothing refused it. The interface's one rule a store can get wrong is that it
// must never choose between them, so when the backfill meets a profile whose id
// the pointer already gives to another tenant it does not overwrite the pointer
// — it marks it ambiguous, and FindUserByID answers ErrUserIDAmbiguous for that
// id until an operator resolves it. createUser refuses an ambiguous pointer like
// any other (ErrUserExists), and DeleteUser leaves one alone: deleting one of the
// two records does not tell the store the other is the right one, so clearing
// the mark is an operator act (config-reference §16.6 says how).
const (
	// attrUIDPointer is the profile stamp; see above.
	attrUIDPointer = "uidPointer"

	// attrAmbiguous marks a pointer the backfill found two profiles for.
	attrAmbiguous = "ambiguous"
)

// ErrUserIDAmbiguous is FindUserByID's answer for an id the backfill found under
// two tenants. The core's admin route answers 404 for it, as it does for any
// error (admin_read.go adminGetUser): showing an operator one of two accounts,
// picked by the store, is the answer the interface forbids.
var ErrUserIDAmbiguous = errors.New("dynamodb: user id is held under more than one tenant")

// The by-id read the admin console's detail route reaches for. See the core's
// UserLookupStore doc for the contract; a drifted signature here would not fail
// a build anywhere else — the core would quietly fall back to
// GetUserByID(id, "") and GET <admin>/api/users/{id} would answer 404 again for
// every user the listing shows under a tenant.
var _ auth.UserLookupStore = (*Store)(nil)

// uidItem is the pointer: the id it is keyed on, and the tenant the profile
// lives under. Nothing else — it is a key, not a copy of the user.
func uidItem(userID, tenantID string) item {
	return item{}.
		sAlways(attrPK, uidPK(userID)).
		sAlways(attrSK, skUID).
		stamp(typeUserID).
		sAlways(attrUserID, userID).
		sAlways(attrTenantID, tenantID)
}

// uidClaimCondition is the condition every pointer write carries, createUser's
// and the backfill's: the id is free, or the pointer already names this very
// tenant and is not marked ambiguous.
//
// The second half is not a loosening. createUser's profile Put in the same
// transaction requires that no profile exists under (tenant, id), so a pointer
// naming that tenant is one whose profile is gone — a pointer the store would
// otherwise strand — and rewriting it with the same content is the only
// correct thing to do with it. For the backfill it is what makes a repeated
// write of the same pointer a no-op rather than a conflict.
const uidClaimCondition = "attribute_not_exists(#PK) OR (#tenantId = :tenant AND attribute_not_exists(#ambiguous))"

func uidClaimNames() map[string]string {
	return exprNames(attrPK, attrTenantID, attrAmbiguous)
}

// FindUserByID implements auth.UserLookupStore: the user with this id, whatever
// tenant holds it.
//
// Two strongly-consistent GetItems, the pointer and then the profile it names,
// for the reason GetUserByEmail gives for its two. The profile is read directly
// rather than through GetUserByID, because GetUserByID files the migration
// marker on the request context for the login path (migration.go) and this is
// not the login path.
//
// A pointer that names a profile which is not there answers ErrUserNotFound, as
// GetUserByID would: both are written and removed in one transaction, so that
// state is one nothing in this package produces, and the honest answer to it is
// the one the route turns into 404.
func (s *Store) FindUserByID(ctx context.Context, id string) (auth.User, error) {
	if err := checkID("user id", id); err != nil {
		return auth.User{}, err
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(uidPK(id), skUID),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get user id pointer", err)
	}
	if len(out.Item) == 0 {
		return s.findUnpointedUser(ctx, id)
	}
	if err := checkVersion(out.Item, typeUserID); err != nil {
		return auth.User{}, err
	}
	if getBool(out.Item, attrAmbiguous) {
		return auth.User{}, fmt.Errorf("%w: %q", ErrUserIDAmbiguous, id)
	}
	return s.readProfile(ctx, getS(out.Item, attrTenantID), id)
}

// findUnpointedUser is FindUserByID's answer when there is no pointer: the
// profile under the empty tenant, if there is one, which is exactly what the
// admin detail route answered on core v0.11.0 (GetUserByID(id, "")).
//
// The pointer is missing for one reason in practice — a profile written before
// this release on a table the backfill has not swept yet — and for that table
// this is never worse than the release before, and is right for every
// single-tenant deployment, which is every deployment this binary creates: the
// product never turns multi-tenant mode on, so its users all live under "". The
// backfill is what makes the detail route span tenants on an older table, and
// the upgrade notes say so (config-reference §16.6, decisions D-22).
//
// It reads the profile directly rather than calling GetUserByID(id, ""), for two
// reasons that change nothing observable: GetUserByID files the migration
// marker (see FindUserByID), and in multi-tenant mode its checkTenant turns ""
// into ErrTenantRequired, where the true answer is that no user can be stored
// under "" there at all.
//
// The fallback never runs after the pointer *named* a tenant whose profile is
// gone. The core makes the same rule for its own fallback (adminFindUser): a
// lookup that has answered must not be asked again somewhere else, because the
// second answer could only disagree with the first.
func (s *Store) findUnpointedUser(ctx context.Context, id string) (auth.User, error) {
	if s.multiTenant {
		return auth.User{}, ErrUserNotFound
	}
	return s.readProfile(ctx, "", id)
}

// readProfile is one strongly-consistent profile GetItem, decoded, with no side
// effect on the request context.
func (s *Store) readProfile(ctx context.Context, tenantID, id string) (auth.User, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(userPK(tenantID, id), skProfile),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get user", err)
	}
	if len(out.Item) == 0 {
		return auth.User{}, ErrUserNotFound
	}
	return userFromItem(out.Item)
}

// uidDeleteAttempts bounds deleteProfileAndPointer's retry. The only thing that
// can move the pointer under a delete is the backfill — writing one where there
// was none, or marking it ambiguous — and each of those happens once per id, so
// a third attempt seeing a third state would be a bug, not contention.
const uidDeleteAttempts = 3

// deleteProfileAndPointer is DeleteUser's last write: the profile and, when the
// pointer names this tenant, the pointer, in one transaction.
//
// Last, and the profile with it, so that a DeleteUser which fails halfway
// leaves a profile to find on retry: everything the user owned that the batch
// already removed is idempotent to remove again, and the profile is the commit
// point. Atomic with the pointer, so neither can outlive the other — a pointer
// without a profile would refuse the id to every other tenant for ever, and a
// profile without a pointer is the pre-backfill state this release exists to
// leave behind.
//
// The pointer is read first, because whether this delete owns it depends on
// what it says, and the transaction re-asserts what was read:
//
//   - naming this tenant, not ambiguous: deleted, conditioned on still saying so;
//   - absent: the profile is deleted with a ConditionCheck that it is still
//     absent, because a concurrent backfill may write one between the read and
//     the delete, and that pointer would be stranded;
//   - naming another tenant, or ambiguous: left alone. It is not this record's —
//     the other tenant's same-id record, or a conflict for an operator — and
//     nothing can turn it into this record's while this profile exists, because
//     every pointer write requires the id to be free or this tenant's already.
//
// A cancelled transaction re-reads and tries again; anything else is an error.
func (s *Store) deleteProfileAndPointer(ctx context.Context, userID, tenantID string) error {
	profileKey := key(userPK(tenantID, userID), skProfile)
	for attempt := 0; ; attempt++ {
		out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
			TableName:      aws.String(s.table),
			Key:            key(uidPK(userID), skUID),
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return wrap("get user id pointer", err)
		}
		ops := []types.TransactWriteItem{
			{Delete: &types.Delete{TableName: aws.String(s.table), Key: profileKey}},
		}
		switch ptr := out.Item; {
		case len(ptr) == 0:
			ops = append(ops, types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
				TableName:                aws.String(s.table),
				Key:                      key(uidPK(userID), skUID),
				ConditionExpression:      aws.String("attribute_not_exists(#PK)"),
				ExpressionAttributeNames: exprNames(attrPK),
			}})
		case getS(ptr, attrTenantID) == tenantID && !getBool(ptr, attrAmbiguous):
			ops = append(ops, types.TransactWriteItem{Delete: &types.Delete{
				TableName:                aws.String(s.table),
				Key:                      key(uidPK(userID), skUID),
				ConditionExpression:      aws.String("#tenantId = :tenant AND attribute_not_exists(#ambiguous)"),
				ExpressionAttributeNames: exprNames(attrTenantID, attrAmbiguous),
				ExpressionAttributeValues: map[string]types.AttributeValue{
					":tenant": avS(tenantID),
				},
			}})
		}

		err = s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{TransactItems: ops})
		if err == nil {
			return nil
		}
		// transactWrite has already retried a bare TransactionConflict; what
		// is left to retry here is the pointer having moved since the read.
		if _, failed := txFailedAtAny(err, 1); failed && attempt < uidDeleteAttempts-1 {
			continue
		}
		return err
	}
}

// txFailedAtAny is txFailedAt for a caller holding the raw error.
func txFailedAtAny(err error, i int) (map[string]types.AttributeValue, bool) {
	reasons, ok := txConditionFailures(err)
	if !ok {
		return nil, false
	}
	return txFailedAt(reasons, i)
}

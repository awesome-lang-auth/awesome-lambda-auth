package dynamodb

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The user-directory backfill: the one-time sweep D6 declared it owed and
// nothing ran.
//
// # Why a table that was never re-keyed still needs a migration
//
// D6 made AdminUserStore.ListUsers a Query over GSI1 by giving every profile a
// constant partition key, GSI1PK = "USER", and a <tenantID>#<id> sort key
// (users.go, profileItem; data-model.md §1.4 #47). The two attributes are
// written by CreateUser and by nothing else, which is what keeps the busiest
// item in the table from paying an index write on every login — and it is also
// why a profile written before that release carries neither. GSI1 is sparse: an
// item without the key attributes is simply not in the index. Such a profile is
// found by every other method, because every other method reads the main
// table, and is invisible to exactly two consumers: GET <admin>/api/users and
// the 'first-user' access policy, which asks for ListUsers(1, 0) and compares
// the first id (core admin.go, AdminPolicyFirstUser). On a table with pre-D6
// rows the console's user tab under-reports and the first-user policy elects
// the wrong person, and neither failure looks like one from outside.
//
// # Why it is a job and not a store method
//
// "Every profile that lacks the two attributes" is the definition of a sparse
// index's complement, and no index can answer it — that is what sparse means.
// The only way to find them is a Scan, which reads the whole table; the store
// never scans (store.go, the API interface has no Scan, and the function's IAM
// policy grants none), and a method that did would be a method a route could
// reach. So this is an operator job run from a workstation with the operator's
// own credentials, through `migrate backfill-users` (cmd/migrate), paged so that
// an interruption costs one page, and it lives in this package only because the
// attribute names and the sort-key derivation are this package's and copying
// them into cmd/migrate would be a second definition free to drift.
//
// # Safe while serving, and what makes it so
//
// Every write the sweep makes is conditional, and it makes two kinds: the
// index half below, and the by-id pointer half, which has its own argument
// further down ("The second debt").
//
// The index half's write is a conditional UpdateItem that names the two index
// attributes and nothing else, guarded by attribute_exists(PK) AND
// attribute_not_exists(GSI1PK). Three interleavings are possible with a live
// store and each is refused rather than reasoned about:
//
//   - a profile CreateUser wrote after the page was scanned already carries the
//     attributes, so the condition fails and the item is counted as skipped;
//   - a profile DeleteUser removed after the page was scanned no longer exists,
//     so attribute_exists(PK) fails — and without that half UpdateItem would
//     have created a key-only ghost, listed by the console and resolvable by
//     nobody;
//   - a concurrent run of this same job over the same page loses the race on
//     the same condition, so two operators cannot double-write.
//
// Nothing else on the profile is read or written by this half: a login
// updating updatedAt or a password change rewriting passwordHash on the same
// item is unaffected, because an UpdateItem is atomic per item and this one
// names two attributes the login path never touches (the pointer half's
// profile writes name only its own stamp, for the same reason). The sweep is
// therefore idempotent — a second run scans the same table and writes nothing —
// and resumable from any page boundary, which is what the encoded key below is
// for.
//
// # What it costs
//
// One Scan pass over the whole table, filtered server-side: every item is read
// once whether or not it is a profile, at 0.5 RRU per 4 KB eventually
// consistent, and a filtered-out item is still billed for the read. Plus one
// write unit per profile actually indexed, and the GSI write that follows it —
// the same index write CreateUser would have paid. On the live table that is a
// few thousand items and cents; on a large one it is the number of items divided
// by eight per 4 KB, in read units, once.
//
// # The second debt: the by-id pointer
//
// The v0.12.0 release added a second item a profile written earlier lacks: the
// by-id pointer UID#<u> that FindUserByID reads (user_lookup.go), which is what
// lets GET <admin>/api/users/{id} find a user the listing shows under a tenant.
// It is the same shape of debt — written by createUser and by nothing else, so a
// profile that predates it has none — and the same sweep pays it, because the
// candidate set is the same Scan over the same profiles and a second job would
// read the whole table a second time to find it.
//
// The pointer is a different item, so the Scan filter cannot see whether it
// exists. It sees the profile's stamp instead, uidPointer, which createUser
// writes in the same transaction as the pointer and this sweep writes in the
// same transaction as its own: a profile with the stamp has a pointer, and a
// swept table matches nothing, as it did before.
//
// Per profile without the stamp, the sweep reads the pointer and acts on what it
// says, and every write re-asserts what was read:
//
//   - absent, or naming this profile's tenant: one transaction writes the
//     pointer — attribute_not_exists, or still this tenant's and not ambiguous —
//     and the stamp, guarded by attribute_exists(PK). A profile deleted since the
//     scan cancels it, so the sweep cannot strand a pointer; a pointer written
//     meanwhile cancels it too, and the pointer is read again and the decision
//     re-made.
//   - naming another tenant, not ambiguous: two profiles hold one id, which
//     nothing refused before this release. The sweep does not overwrite — it
//     marks the pointer ambiguous and removes the other profile's stamp, in one
//     transaction that also asserts the swept profile still exists, so
//     FindUserByID answers ErrUserIDAmbiguous for that id rather than either
//     record, createUser refuses the id, and every later run reports both
//     profiles again until an operator resolves it. A swept profile deleted
//     since the scan cancels the mark: that is one record, not two.
//   - already ambiguous: reported, nothing written.
//
// A conflict is the one outcome that needs an operator, and BackfillPage carries
// each one so `migrate backfill-users` can say so. A dry run reads the pointer
// too, so it reports a conflict with a pointer that already exists without
// writing anything; two profiles that both predate pointers become a conflict
// only when the real run has pointed the first of them.
//
// The read is one strongly-consistent GetItem per unstamped profile — 1 RRU for
// an item this small — and the write a two-item transaction, 4 WCU at 2 per
// item (a conflict's mark is a three-item one, 6 WCU), once.

// BackfillAPI is the slice of the DynamoDB client the sweep uses. Scan is
// deliberately absent from the store's own API interface (store.go): the store
// never scans and the function's role grants no Scan, so this interface is
// separate to keep that statement true rather than widening it for a job that
// runs elsewhere. GetItem and TransactWriteItems are the pointer half's.
type BackfillAPI interface {
	Scan(ctx context.Context, in *awsddb.ScanInput, optFns ...func(*awsddb.Options)) (*awsddb.ScanOutput, error)
	UpdateItem(ctx context.Context, in *awsddb.UpdateItemInput, optFns ...func(*awsddb.Options)) (*awsddb.UpdateItemOutput, error)
	GetItem(ctx context.Context, in *awsddb.GetItemInput, optFns ...func(*awsddb.Options)) (*awsddb.GetItemOutput, error)
	TransactWriteItems(ctx context.Context, in *awsddb.TransactWriteItemsInput, optFns ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error)
}

// BackfillOptions configures one page of the sweep.
type BackfillOptions struct {
	// TableName is the single table, i.e. stores.connection.tableName.
	TableName string

	// PageSize bounds the Scan's Limit: the number of items *evaluated* per
	// page, not the number matched, so a page over a table where most items
	// are sessions can index far fewer profiles than this. Defaults to
	// DefaultBackfillPageSize.
	PageSize int32

	// StartKey resumes from the key a previous page returned as NextKey. Empty
	// starts from the beginning of the table.
	StartKey string

	// DryRun scans and reports and writes nothing. Every decision above the
	// write — which items match, what their sort key would be — is exercised
	// exactly as in a real run, which is what makes the report worth reading.
	DryRun bool
}

// DefaultBackfillPageSize is the Scan Limit when BackfillOptions.PageSize is
// zero. It bounds how much work one page represents — and therefore how much a
// resume repeats — rather than throughput; DynamoDB returns at most 1 MB per
// Scan call regardless.
const DefaultBackfillPageSize = 100

// BackfillPage is what one page of the sweep did.
type BackfillPage struct {
	// Evaluated is the number of items the Scan read on this page, profiles or
	// not. It is what the read bill is proportional to.
	Evaluated int

	// Matched is the number of profiles on this page that lacked the index
	// attributes when scanned.
	Matched int

	// Written is the number of those profiles this page indexed. Zero on a dry
	// run.
	Written int

	// Skipped is the number of matched profiles whose conditional write was
	// refused — indexed by a concurrent CreateUser or a concurrent run, or
	// deleted since the scan — or that carry no usable userId and are not
	// written at all. Never a failure. On a dry run only the last kind is
	// counted, so Matched - Skipped is what a real run would index.
	Skipped int

	// Planned lists the user ids this page would index — on a dry run — or did
	// index. It is what the operator reads to see that the sweep is touching
	// what they expect.
	Planned []string

	// PointerMatched is the number of profiles on this page that lacked the
	// by-id pointer stamp when scanned, whether or not they also lacked the
	// index attributes.
	PointerMatched int

	// PointersWritten is the number of pointers this page wrote. Zero on a dry
	// run.
	PointersWritten int

	// PointersSkipped is the number of unstamped profiles that got no pointer
	// and no conflict mark: deleted since the scan, or carrying no usable
	// userId. Never a failure.
	PointersSkipped int

	// PlannedPointers lists the user ids this page would write a pointer for —
	// on a dry run — or did.
	PlannedPointers []string

	// Conflicts lists the ids this page found under two tenants. Unlike every
	// other outcome, each one needs an operator; see BackfillConflict.
	Conflicts []BackfillConflict

	// NextKey resumes the sweep at the next page. Empty means the table has
	// been swept to the end.
	NextKey string
}

// BackfillConflict is one id the sweep found under two tenants: the profile it
// was sweeping, and the tenant the existing pointer named.
type BackfillConflict struct {
	UserID string

	// TenantID is the tenant of the profile the sweep was on.
	TenantID string

	// PointerTenantID is the tenant the pointer named when it was read. Empty
	// together with AlreadyAmbiguous when an earlier run had marked it.
	PointerTenantID string

	// AlreadyAmbiguous is true when the pointer was marked before this page
	// reached it: a later run reporting a conflict that is still unresolved.
	AlreadyAmbiguous bool
}

// BackfillUsersPage sweeps one page of the table, indexes every pre-D6 profile
// it finds and writes the by-id pointer of every profile that predates it. Call
// it until NextKey comes back empty.
func BackfillUsersPage(ctx context.Context, api BackfillAPI, opts BackfillOptions) (BackfillPage, error) {
	if api == nil {
		return BackfillPage{}, errors.New("dynamodb: backfill: api client is required")
	}
	if opts.TableName == "" {
		return BackfillPage{}, errors.New("dynamodb: backfill: table name is required")
	}
	limit := opts.PageSize
	if limit <= 0 {
		limit = DefaultBackfillPageSize
	}

	in := &awsddb.ScanInput{
		TableName: aws.String(opts.TableName),
		Limit:     aws.Int32(limit),
		// Profiles only, and only the ones that owe something: the index
		// attributes or the pointer stamp. _t exists so a sweep can select by
		// type without inferring it from the key prefix (keys.go); the sort key
		// check is belt and braces, because a profile is the only item under its
		// partition that carries _t="user".
		FilterExpression: aws.String("#_t = :user AND #SK = :profile AND " +
			"(attribute_not_exists(#GSI1PK) OR attribute_not_exists(#GSI1SK) OR attribute_not_exists(#uidPointer))"),
		// The two segments of the sort key, the key to write back, and which of
		// the two debts this profile owes. Nothing secret is projected: not the
		// password hash, not a token hash.
		ProjectionExpression: aws.String("#PK, #SK, #tenantId, #userId, #GSI1PK, #GSI1SK, #uidPointer"),
		ExpressionAttributeNames: exprNames(attrType, attrSK, attrGSI1PK, attrGSI1SK,
			attrPK, attrTenantID, attrUserID, attrUIDPointer),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":user":    avS(typeUser),
			":profile": avS(skProfile),
		},
	}
	if opts.StartKey != "" {
		start, err := decodeBackfillKey(opts.StartKey)
		if err != nil {
			return BackfillPage{}, err
		}
		in.ExclusiveStartKey = start
	}

	out, err := api.Scan(ctx, in)
	if err != nil {
		return BackfillPage{}, wrap("backfill scan", err)
	}

	page := BackfillPage{Evaluated: int(out.ScannedCount)}
	for _, m := range out.Items {
		userID, tenantID := getS(m, attrUserID), getS(m, attrTenantID)
		needsIndex := getS(m, attrGSI1PK) == "" || getS(m, attrGSI1SK) == ""
		needsPointer := !getBool(m, attrUIDPointer)
		if needsIndex {
			page.Matched++
		}
		if needsPointer {
			page.PointerMatched++
		}
		if userID == "" || checkID("user id", userID) != nil {
			// A profile with no userId attribute is not a profile this store
			// ever wrote (sAlways writes it at creation), and guessing an id
			// from the partition key would be indexing a row this package does
			// not understand. Reported as skipped, with the key, rather than
			// written — under each half it was matched by, so that every
			// matched profile lands in exactly one outcome of its half.
			if needsIndex {
				page.Skipped++
			}
			if needsPointer {
				page.PointersSkipped++
			}
			page.Planned = append(page.Planned, "skipped (no userId): "+getS(m, attrPK))
			continue
		}

		if needsIndex {
			page.Planned = append(page.Planned, userID)
			if !opts.DryRun {
				written, err := backfillIndex(ctx, api, opts.TableName, m, userID, tenantID)
				if err != nil {
					// Stop at the first failed write rather than press on: the
					// page is re-runnable from its own start key, and a partial
					// page is exactly what the conditional write makes harmless
					// to repeat. The key returned is this page's start, not the
					// next one's.
					page.NextKey = opts.StartKey
					return page, err
				}
				if written {
					page.Written++
				} else {
					page.Skipped++
				}
			}
		}

		if needsPointer {
			outcome, conflict, err := backfillPointer(ctx, api, opts.TableName, userID, tenantID, opts.DryRun)
			if err != nil {
				page.NextKey = opts.StartKey
				return page, err
			}
			switch outcome {
			case pointerWritten:
				page.PlannedPointers = append(page.PlannedPointers, userID)
				if !opts.DryRun {
					page.PointersWritten++
				}
			case pointerSkipped:
				page.PointersSkipped++
			case pointerConflict:
				page.Conflicts = append(page.Conflicts, conflict)
			}
		}
	}

	if len(out.LastEvaluatedKey) > 0 {
		next, err := encodeBackfillKey(out.LastEvaluatedKey)
		if err != nil {
			return page, err
		}
		page.NextKey = next
	}
	return page, nil
}

// backfillIndex writes the two GSI1 attributes onto one pre-D6 profile, and
// reports false when the condition refused it.
func backfillIndex(ctx context.Context, api BackfillAPI, table string, m map[string]types.AttributeValue, userID, tenantID string) (bool, error) {
	_, err := api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:        aws.String(table),
		Key:              key(getS(m, attrPK), getS(m, attrSK)),
		UpdateExpression: aws.String("SET #GSI1PK = :pk, #GSI1SK = :sk"),
		// The index half's whole safety argument is this line; see the file
		// header.
		ConditionExpression:      aws.String("attribute_exists(#PK) AND attribute_not_exists(#GSI1PK)"),
		ExpressionAttributeNames: exprNames(attrPK, attrGSI1PK, attrGSI1SK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(gsi1AllUsersPK),
			":sk": avS(userGSI1SK(tenantID, userID)),
		},
	})
	switch {
	case err == nil:
		return true, nil
	case isConditionFailed(err):
		return false, nil
	default:
		return false, wrap("backfill index "+userID, err)
	}
}

// pointerOutcome is what backfillPointer did for one profile.
type pointerOutcome int

const (
	// pointerWritten: the pointer and the stamp were written, or on a dry run
	// would have been.
	pointerWritten pointerOutcome = iota
	// pointerSkipped: the profile is gone; there is nothing to point at.
	pointerSkipped
	// pointerConflict: the id is held under another tenant too.
	pointerConflict
)

// backfillPointerAttempts bounds the read-decide-write loop. Each retry follows
// a write that moved the pointer or the profile between the read and the
// transaction — a registration, a delete, a concurrent run — and none of those
// can happen to one id more than once or twice in the life of a sweep.
const backfillPointerAttempts = 4

// backfillPointer gives one unstamped profile its by-id pointer, or records why
// it cannot have one. See the file header for the three cases.
func backfillPointer(ctx context.Context, api BackfillAPI, table, userID, tenantID string, dryRun bool) (pointerOutcome, BackfillConflict, error) {
	profileKey := key(userPK(tenantID, userID), skProfile)
	for attempt := 0; attempt < backfillPointerAttempts; attempt++ {
		got, err := api.GetItem(ctx, &awsddb.GetItemInput{
			TableName:      aws.String(table),
			Key:            key(uidPK(userID), skUID),
			ConsistentRead: aws.Bool(true),
		})
		if err != nil {
			return 0, BackfillConflict{}, wrap("backfill read pointer "+userID, err)
		}
		ptr := got.Item
		named := getS(ptr, attrTenantID)

		switch {
		case len(ptr) > 0 && getBool(ptr, attrAmbiguous):
			return pointerConflict, BackfillConflict{UserID: userID, TenantID: tenantID, AlreadyAmbiguous: true}, nil

		case len(ptr) > 0 && named != tenantID:
			conflict := BackfillConflict{UserID: userID, TenantID: tenantID, PointerTenantID: named}
			if dryRun {
				return pointerConflict, conflict, nil
			}
			// Mark it, and take the other profile's stamp away so that every
			// later run reports both halves until the conflict is resolved. The
			// mark is conditioned on the pointer still naming what was read; the
			// stamp removal on the other profile still existing, because an
			// UpdateItem on a missing key would create one. The third item is
			// the swept profile itself, asserted still there: the Scan is
			// eventually consistent and a DeleteUser can land after it, and a
			// conflict with a profile that is gone is no conflict — marking it
			// would answer an error for the one record that really holds the
			// id. Its REMOVE is a no-op (an unstamped profile is why the sweep
			// is here), and it is an Update rather than a ConditionCheck so that
			// the sweep needs no ConditionCheckItem from the operator either.
			err := transactBackfill(ctx, api, []types.TransactWriteItem{
				{Update: markAmbiguousUpdate(table, userID, named)},
				{Update: &types.Update{
					TableName:                aws.String(table),
					Key:                      key(userPK(named, userID), skProfile),
					UpdateExpression:         aws.String("REMOVE #uidPointer"),
					ConditionExpression:      aws.String("attribute_exists(#PK)"),
					ExpressionAttributeNames: exprNames(attrPK, attrUIDPointer),
				}},
				{Update: assertProfileUpdate(table, profileKey)},
			})
			if err == nil {
				return pointerConflict, conflict, nil
			}
			if _, failed := txFailedAtAny(err, 2); failed {
				// The swept profile is gone: nothing to point, nothing to mark.
				return pointerSkipped, BackfillConflict{}, nil
			}
			if _, failed := txFailedAtAny(err, 0); failed || isTransactionConflict(err) {
				// The pointer moved since it was read; decide again.
				continue
			}
			if _, failed := txFailedAtAny(err, 1); failed {
				// The other profile is gone: the pointer names nothing. Marking
				// it alone is still the safe answer — this package's two
				// transactions that remove a profile remove its pointer with it,
				// so only a hand edit or a pre-v0.12.0 binary's DeleteUser (in a
				// rollout or after a rollback, config-reference §16.6) leaves
				// one, and an operator should see it.
				err := transactBackfill(ctx, api, []types.TransactWriteItem{
					{Update: markAmbiguousUpdate(table, userID, named)},
					{Update: assertProfileUpdate(table, profileKey)},
				})
				if err == nil {
					return pointerConflict, conflict, nil
				}
				if _, failed := txFailedAtAny(err, 1); failed {
					return pointerSkipped, BackfillConflict{}, nil
				}
				if _, failed := txFailedAtAny(err, 0); failed || isTransactionConflict(err) {
					continue
				}
				return 0, BackfillConflict{}, wrap("backfill mark pointer "+userID, err)
			}
			return 0, BackfillConflict{}, wrap("backfill mark pointer "+userID, err)

		default:
			// Absent, or already this tenant's.
			if dryRun {
				return pointerWritten, BackfillConflict{}, nil
			}
			err := transactBackfill(ctx, api, []types.TransactWriteItem{
				{Update: &types.Update{
					TableName:                aws.String(table),
					Key:                      profileKey,
					UpdateExpression:         aws.String("SET #uidPointer = :true"),
					ConditionExpression:      aws.String("attribute_exists(#PK)"),
					ExpressionAttributeNames: exprNames(attrPK, attrUIDPointer),
					ExpressionAttributeValues: map[string]types.AttributeValue{
						":true": &types.AttributeValueMemberBOOL{Value: true},
					},
				}},
				{Put: &types.Put{
					TableName:                 aws.String(table),
					Item:                      uidItem(userID, tenantID),
					ConditionExpression:       aws.String(uidClaimCondition),
					ExpressionAttributeNames:  uidClaimNames(),
					ExpressionAttributeValues: map[string]types.AttributeValue{":tenant": avS(tenantID)},
				}},
			})
			if err == nil {
				return pointerWritten, BackfillConflict{}, nil
			}
			if _, failed := txFailedAtAny(err, 0); failed {
				return pointerSkipped, BackfillConflict{}, nil
			}
			if _, failed := txFailedAtAny(err, 1); failed || isTransactionConflict(err) {
				// A pointer was written or changed since the read; decide again.
				continue
			}
			return 0, BackfillConflict{}, wrap("backfill write pointer "+userID, err)
		}
	}
	return 0, BackfillConflict{}, fmt.Errorf("dynamodb: backfill: the pointer for %q kept changing under the sweep; re-run from this page", userID)
}

// markAmbiguousUpdate is the conflict mark: the pointer, still naming the tenant
// it was read naming and not yet marked, set ambiguous.
func markAmbiguousUpdate(table, userID, named string) *types.Update {
	return &types.Update{
		TableName:                aws.String(table),
		Key:                      key(uidPK(userID), skUID),
		UpdateExpression:         aws.String("SET #ambiguous = :true"),
		ConditionExpression:      aws.String("#tenantId = :named AND attribute_not_exists(#ambiguous)"),
		ExpressionAttributeNames: exprNames(attrTenantID, attrAmbiguous),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":named": avS(named),
			":true":  &types.AttributeValueMemberBOOL{Value: true},
		},
	}
}

// assertProfileUpdate asserts that the swept profile still exists, as a
// transaction item that writes nothing: REMOVE of the stamp an unstamped
// profile does not carry, guarded by attribute_exists(PK) so that it cannot
// create the item either.
func assertProfileUpdate(table string, profileKey map[string]types.AttributeValue) *types.Update {
	return &types.Update{
		TableName:                aws.String(table),
		Key:                      profileKey,
		UpdateExpression:         aws.String("REMOVE #uidPointer"),
		ConditionExpression:      aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames: exprNames(attrPK, attrUIDPointer),
	}
}

// transactBackfill is one TransactWriteItems call. No conflict retry here, unlike
// the store's transactWrite: the caller's loop re-reads and re-decides, which a
// blind retry of the same request would skip.
func transactBackfill(ctx context.Context, api BackfillAPI, ops []types.TransactWriteItem) error {
	_, err := api.TransactWriteItems(ctx, &awsddb.TransactWriteItemsInput{TransactItems: ops})
	return err
}

// backfillKey is the resume token's wire shape: the two key attributes of the
// last item a page evaluated, which is all a Scan's LastEvaluatedKey carries
// on a table keyed by PK/SK.
//
// It is JSON under base64url rather than the raw pair joined by a separator,
// so that a token pasted on a command line has no character an operator's
// shell will mangle, and so that the format can grow a third attribute — an
// index key, say — without a second parser.
type backfillKey struct {
	PK string `json:"PK"`
	SK string `json:"SK"`
}

func encodeBackfillKey(key map[string]types.AttributeValue) (string, error) {
	pk, sk := getS(key, attrPK), getS(key, attrSK)
	if pk == "" || sk == "" {
		return "", fmt.Errorf("dynamodb: backfill: LastEvaluatedKey lacks PK or SK: %v", key)
	}
	raw, err := json.Marshal(backfillKey{PK: pk, SK: sk})
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func decodeBackfillKey(token string) (map[string]types.AttributeValue, error) {
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("dynamodb: backfill: --start-key is not a token this sweep printed: %w", err)
	}
	var k backfillKey
	if err := json.Unmarshal(raw, &k); err != nil || k.PK == "" || k.SK == "" {
		return nil, errors.New("dynamodb: backfill: --start-key is not a token this sweep printed")
	}
	return key(k.PK, k.SK), nil
}

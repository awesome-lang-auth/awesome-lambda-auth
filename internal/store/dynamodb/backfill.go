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
// Every write is a conditional UpdateItem that names the two index attributes
// and nothing else, guarded by attribute_exists(PK) AND
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
// Nothing else on the profile is read or written: a login updating updatedAt or
// a password change rewriting passwordHash on the same item is unaffected,
// because an UpdateItem is atomic per item and this one names two attributes
// the login path never touches. The sweep is therefore idempotent — a second
// run scans the same table and writes nothing — and resumable from any page
// boundary, which is what the encoded key below is for.
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

// BackfillAPI is the slice of the DynamoDB client the sweep uses. Scan is
// deliberately absent from the store's own API interface (store.go): the store
// never scans and the function's role grants no Scan, so this interface is
// separate to keep that statement true rather than widening it for a job that
// runs elsewhere.
type BackfillAPI interface {
	Scan(ctx context.Context, in *awsddb.ScanInput, optFns ...func(*awsddb.Options)) (*awsddb.ScanOutput, error)
	UpdateItem(ctx context.Context, in *awsddb.UpdateItemInput, optFns ...func(*awsddb.Options)) (*awsddb.UpdateItemOutput, error)
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
	// refused: indexed by a concurrent CreateUser or a concurrent run, or
	// deleted since the scan. Never a failure.
	Skipped int

	// Planned lists the user ids this page would index — on a dry run — or did
	// index. It is what the operator reads to see that the sweep is touching
	// what they expect.
	Planned []string

	// NextKey resumes the sweep at the next page. Empty means the table has
	// been swept to the end.
	NextKey string
}

// BackfillUsersPage sweeps one page of the table and indexes every pre-D6
// profile it finds. Call it until NextKey comes back empty.
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
		// Profiles only, and only the ones the index does not know. _t exists
		// so a sweep can select by type without inferring it from the key
		// prefix (keys.go); the sort key check is belt and braces, because a
		// profile is the only item under its partition that carries _t="user".
		FilterExpression: aws.String("#_t = :user AND #SK = :profile AND " +
			"(attribute_not_exists(#GSI1PK) OR attribute_not_exists(#GSI1SK))"),
		// The two segments of the sort key, and the key to write back. Nothing
		// secret is projected: not the password hash, not a token hash.
		ProjectionExpression: aws.String("#PK, #SK, #tenantId, #userId"),
		ExpressionAttributeNames: exprNames(attrType, attrSK, attrGSI1PK, attrGSI1SK,
			attrPK, attrTenantID, attrUserID),
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
		page.Matched++
		userID, tenantID := getS(m, attrUserID), getS(m, attrTenantID)
		if userID == "" {
			// A profile with no userId attribute is not a profile this store
			// ever wrote (sAlways writes it at creation), and guessing an id
			// from the partition key would be indexing a row this package does
			// not understand. Reported as skipped, with the key, rather than
			// written.
			page.Skipped++
			page.Planned = append(page.Planned, "skipped (no userId): "+getS(m, attrPK))
			continue
		}
		page.Planned = append(page.Planned, userID)
		if opts.DryRun {
			continue
		}

		_, err := api.UpdateItem(ctx, &awsddb.UpdateItemInput{
			TableName:        aws.String(opts.TableName),
			Key:              key(getS(m, attrPK), getS(m, attrSK)),
			UpdateExpression: aws.String("SET #GSI1PK = :pk, #GSI1SK = :sk"),
			// The whole safety argument is this line; see the file header.
			ConditionExpression:      aws.String("attribute_exists(#PK) AND attribute_not_exists(#GSI1PK)"),
			ExpressionAttributeNames: exprNames(attrPK, attrGSI1PK, attrGSI1SK),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk": avS(gsi1AllUsersPK),
				":sk": avS(userGSI1SK(tenantID, userID)),
			},
		})
		switch {
		case err == nil:
			page.Written++
		case isConditionFailed(err):
			page.Skipped++
		default:
			// Stop at the first failed write rather than press on: the page is
			// re-runnable from its own start key, and a partial page is exactly
			// what the conditional write makes harmless to repeat. The key
			// returned is this page's start, not the next one's.
			page.NextKey = opts.StartKey
			return page, wrap("backfill index "+userID, err)
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

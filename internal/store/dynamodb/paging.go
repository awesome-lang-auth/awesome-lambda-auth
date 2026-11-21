package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// DynamoDB request-shape limits, from the API reference. They are named here
// because three fan-out operations must page around them (data-model.md §6.4).
const (
	maxBatchWriteItems = 25
	maxBatchGetItems   = 100
)

// unprocessedAttempts bounds the retry loop for a batch that came back partially
// applied. BatchWriteItem reports throttled items rather than failing, so the
// caller — not the SDK's retryer — owns that loop.
const unprocessedAttempts = 8

// queryAll drains a paginated Query. cap is a hard ceiling: the interfaces this
// serves take no cursor, so an unbounded drain would turn one abusive account
// into a Lambda timeout. Exceeding it is ErrResultTooLarge, never a silent
// truncation.
func (s *Store) queryAll(ctx context.Context, in *awsddb.QueryInput, limit int) ([]map[string]types.AttributeValue, error) {
	var out []map[string]types.AttributeValue
	for {
		page, err := s.api.Query(ctx, in)
		if err != nil {
			return nil, err
		}
		out = append(out, page.Items...)
		if len(out) > limit {
			return nil, ErrResultTooLarge
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

// The offset-paging primitive the four listing interfaces share.
//
// AdminUserStore.ListUsers, SessionLister.GetAllSessions,
// APIKeyAdminStore.ListAll and WebhookAdminStore.ListWebhooks all take
// (limit, offset) positionally, and data-model.md §8.7 asked which of two
// answers to give: map opaque cursors onto the offset parameter, or reproduce
// the reference's over-reading heuristic. Neither. The answer is the third one
// the upstream author spelled out when they specified the index these listings
// query: **offset is positional and is paid for by reading and discarding that
// many index entries.** No key-value store can seek to the Nth item, a cursor
// cannot express the reference's `total` arithmetic without changing the wire,
// and the route clamps limit to 100 — so the cost is real, bounded, and
// accepted.
//
// What is *not* accepted is an unbounded one. limit is clamped by the route;
// offset is not clamped by anything, and offset=1e9 would be a Lambda timeout
// and a five-figure RCU bill from one query string. DefaultMaxPageWindow is the
// ceiling on limit+offset, and exceeding it is ErrPageWindowTooLarge rather than
// a silent truncation — the same choice ErrResultTooLarge makes for the
// cursorless list methods.

// DefaultMaxPageWindow caps limit+offset on every offset-paged listing.
//
// Ten thousand is two orders of magnitude past what any of the reference's own
// consumers asks for — the admin tables page in twenties and clamp at a hundred,
// and the 2fa-policy walk steps in batches of 100 — so a caller that reaches it
// is not paging, and the honest answer to "give me the hundred users starting at
// the ten-thousandth" is that this interface cannot do that affordably and a
// tenant-scoped query can.
const DefaultMaxPageWindow = 10000

// ErrPageWindowTooLarge means limit+offset exceeded Options.MaxPageWindow.
// Nothing was read.
var ErrPageWindowTooLarge = errors.New("dynamodb: paging window exceeds the configured cap")

// pageWindow applies the paging rules the core states once for all three admin
// listers and again for the two API-key and webhook listings, so that no
// implementation of them restates the rules and gets one subtly wrong:
//
//   - limit <= 0 returns an empty page and no error. A store that read a
//     non-positive limit as "no limit" would turn a malformed query string into
//     a full-table read — and, in the 2fa-policy walk, a full-table update.
//   - offset < 0 is read as 0.
//   - limit+offset beyond the cap is ErrPageWindowTooLarge.
//
// The bool reports whether there is anything to do at all.
func (s *Store) pageWindow(limit, offset int) (int, int, bool, error) {
	if limit <= 0 {
		return 0, 0, false, nil
	}
	if offset < 0 {
		offset = 0
	}
	if limit+offset > s.maxPageWindow {
		return 0, 0, false, fmt.Errorf("%w: limit %d + offset %d exceeds %d",
			ErrPageWindowTooLarge, limit, offset, s.maxPageWindow)
	}
	return limit, offset, true, nil
}

// pagedIndexQuery answers one offset page of a directory index: it walks the
// index in its own order, skips offset entries, and returns the canonical items
// the next limit entries resolve to, still in index order.
//
// Two properties are worth stating, because both are contract rather than
// convenience.
//
// **The skip is index-only.** Entries inside the offset are counted and dropped
// without ever being resolved, which is what makes offset cost one index read
// per entry rather than one item read per entry. That is the cost model the
// upstream author documented, and it is the cheaper half of the bargain.
//
// **The page is filled, not truncated.** An index entry whose canonical item
// does not come back does not shorten the page: the walk keeps reading until
// limit items resolve or the index runs out. It has to. The core makes a short
// page mean "nothing follows", because that is how the reference's 2fa-policy
// walk terminates (admin.router.ts:836-847), so a page shortened by one
// unresolvable entry would silently skip every record after it.
//
// There are two ways an entry fails to resolve, and they are not the same kind
// of thing. One is the index lagging a delete, which is transient by definition
// and is why this guard is written defensively rather than because anything
// observable depends on it. The other is real and permanent: the session
// directory is a separate *base* item with its own TTL (sessionIndexItem), and
// TTL reaps items independently, so a directory entry genuinely can outlive the
// session it names by minutes.
//
// GSI1 is eventually consistent and cannot be read consistently, so the reverse
// staleness — an item written microseconds ago and not yet indexed — is simply
// missed. That is acceptable here for the reason it is acceptable in
// ListSessionsForUser: these are admin listings, and the item is reachable by
// key the whole time.
//
// canonicalKey says which main-table item an index entry names. It is a
// parameter and not "the entry's own PK and SK" because the two are only the
// same thing when the indexed item *is* the record: a user profile indexes
// itself, where a session is reached through a separate directory item that
// shares its partition (sessionIndexItem) and an API key by service through its
// id pointer. canonicalKeyOfEntry is the identity case.
func (s *Store) pagedIndexQuery(ctx context.Context, in *awsddb.QueryInput, limit, offset int, canonicalKey canonicalKeyFunc) ([]map[string]types.AttributeValue, error) {
	return s.pagedIndexQueryKeeping(ctx, in, limit, offset, canonicalKey, nil)
}

// pagedIndexQueryKeeping is pagedIndexQuery with one more way for an entry to
// fail to resolve: a canonical item that keep refuses is dropped as if it had
// gone, and the page is still filled. It exists for a sparse index whose
// membership is a state of the record — the pending-invitation directory
// (invitations.go) — where the index can lag a write that took the record out
// of the state, and a resolved record that is no longer in it must neither be
// answered nor shorten the page. A nil keep keeps everything.
func (s *Store) pagedIndexQueryKeeping(ctx context.Context, in *awsddb.QueryInput, limit, offset int, canonicalKey canonicalKeyFunc, keep func(map[string]types.AttributeValue) bool) ([]map[string]types.AttributeValue, error) {
	limit, offset, work, err := s.pageWindow(limit, offset)
	if err != nil || !work {
		return nil, err
	}

	// One index page per round trip, sized so that the BatchGetItem that resolves
	// it is a single call (maxBatchGetItems). Asking for no more than the window
	// still outstanding keeps a limit of 5 from reading 100 entries.
	out := make([]map[string]types.AttributeValue, 0, limit)
	skipped := 0
	for {
		want := limit - len(out)
		if skipped < offset {
			want += offset - skipped
		}
		in.Limit = aws.Int32(int32(min(want, maxBatchGetItems)))

		page, err := s.api.Query(ctx, in)
		if err != nil {
			return nil, err
		}

		entries := page.Items
		if skipped < offset {
			drop := min(offset-skipped, len(entries))
			skipped += drop
			entries = entries[drop:]
		}
		if len(entries) > 0 {
			items, err := s.resolveIndexEntries(ctx, entries, canonicalKey)
			if err != nil {
				return nil, err
			}
			for _, it := range items {
				if keep != nil && !keep(it) {
					continue
				}
				out = append(out, it)
				if len(out) == limit {
					return out, nil
				}
			}
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

// resolveIndexEntries fetches the canonical items a run of index entries names,
// and returns them in the order the entries came in.
//
// The reordering is not optional: BatchGetItem does not preserve request order,
// and the order of the index is the order the listing contracts to answer in.
// Entries whose item has gone are dropped, which is exactly what makes
// pagedIndexQuery's fill loop necessary.
//
// GSI1 projects three attributes on purpose — no secret is ever in a second
// physical copy (§5) — so the full item always comes from the main table, and
// per §5's ownership rule the canonical item is also the only thing allowed to
// say who the item belongs to.
func (s *Store) resolveIndexEntries(ctx context.Context, entries []map[string]types.AttributeValue, canonicalKey canonicalKeyFunc) ([]map[string]types.AttributeValue, error) {
	keys := make([]map[string]types.AttributeValue, 0, len(entries))
	for _, e := range entries {
		keys = append(keys, canonicalKey(e))
	}
	items, err := s.batchGet(ctx, keys)
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]map[string]types.AttributeValue, len(items))
	for _, it := range items {
		byKey[keyString(getS(it, attrPK), getS(it, attrSK))] = it
	}
	out := make([]map[string]types.AttributeValue, 0, len(entries))
	for _, k := range keys {
		if it, ok := byKey[keyString(getS(k, attrPK), getS(k, attrSK))]; ok {
			out = append(out, it)
		}
	}
	return out, nil
}

// canonicalKeyFunc maps one GSI1 entry to the main-table key of the record it
// stands for. See pagedIndexQuery.
type canonicalKeyFunc func(entry map[string]types.AttributeValue) map[string]types.AttributeValue

// canonicalKeyOfEntry is the identity mapping, for indexes whose entries are the
// records themselves.
func canonicalKeyOfEntry(entry map[string]types.AttributeValue) map[string]types.AttributeValue {
	return key(getS(entry, attrPK), getS(entry, attrSK))
}

// canonicalKeyInSamePartition maps an entry to a different sort key in the
// partition it already names — the shape a directory item written beside its
// record takes.
func canonicalKeyInSamePartition(sk string) canonicalKeyFunc {
	return func(entry map[string]types.AttributeValue) map[string]types.AttributeValue {
		return key(getS(entry, attrPK), sk)
	}
}

// keyString is the map key a PK/SK pair is looked up under while a page is being
// put back into index order. NUL separates because it is the one byte no key in
// this table can contain.
func keyString(pk, sk string) string { return pk + "\x00" + sk }

// deleteKeys removes items in batches, retrying whatever DynamoDB reports as
// unprocessed. The whole fan-out is idempotent: a delete of an absent item
// succeeds, so a partial failure is safe to retry from the top.
func (s *Store) deleteKeys(ctx context.Context, keys []map[string]types.AttributeValue) error {
	reqs := make([]types.WriteRequest, 0, len(keys))
	for _, k := range keys {
		reqs = append(reqs, types.WriteRequest{DeleteRequest: &types.DeleteRequest{Key: k}})
	}
	return s.batchWrite(ctx, reqs)
}

// batchWrite applies write requests in batches of maxBatchWriteItems, retrying
// whatever DynamoDB reports as unprocessed.
//
// It is **not** a transaction and must not be mistaken for one: a batch that
// fails halfway leaves the earlier requests applied. Every caller here is
// idempotent on retry — a delete of an absent item succeeds, and a Put of the
// same metadata entry writes the same bytes — which is what makes retrying from
// the top safe, and it is the only thing that does.
func (s *Store) batchWrite(ctx context.Context, reqs []types.WriteRequest) error {
	for start := 0; start < len(reqs); start += maxBatchWriteItems {
		end := min(start+maxBatchWriteItems, len(reqs))
		pending := map[string][]types.WriteRequest{s.table: reqs[start:end]}
		for attempt := 0; len(pending) > 0; attempt++ {
			if attempt == unprocessedAttempts {
				return errors.New("dynamodb: batch delete still unprocessed after retries")
			}
			if attempt > 0 {
				if err := sleepCtx(ctx, backoff(attempt)); err != nil {
					return err
				}
			}
			resp, err := s.api.BatchWriteItem(ctx, &awsddb.BatchWriteItemInput{RequestItems: pending})
			if err != nil {
				return err
			}
			pending = resp.UnprocessedItems
		}
	}
	return nil
}

// batchGet fetches items by key from the main table, following UnprocessedKeys.
// It is used where a GSI1 query hands back keys and the caller needs the full
// item: the index projects only three attributes on purpose (§5).
func (s *Store) batchGet(ctx context.Context, keys []map[string]types.AttributeValue) ([]map[string]types.AttributeValue, error) {
	out := make([]map[string]types.AttributeValue, 0, len(keys))
	for start := 0; start < len(keys); start += maxBatchGetItems {
		end := min(start+maxBatchGetItems, len(keys))
		pending := map[string]types.KeysAndAttributes{
			s.table: {Keys: keys[start:end], ConsistentRead: aws.Bool(true)},
		}
		for attempt := 0; len(pending) > 0; attempt++ {
			if attempt == unprocessedAttempts {
				return nil, errors.New("dynamodb: batch get still unprocessed after retries")
			}
			if attempt > 0 {
				if err := sleepCtx(ctx, backoff(attempt)); err != nil {
					return nil, err
				}
			}
			resp, err := s.api.BatchGetItem(ctx, &awsddb.BatchGetItemInput{RequestItems: pending})
			if err != nil {
				return nil, err
			}
			out = append(out, resp.Responses[s.table]...)
			pending = resp.UnprocessedKeys
		}
	}
	return out, nil
}

// backoff is deliberately coarse. Unprocessed items mean the table is shedding
// load, and a Lambda has a deadline, so this trades a few hundred milliseconds
// for a much better chance of finishing rather than optimising the fast path.
func backoff(attempt int) time.Duration {
	d := 25 * time.Millisecond << attempt
	if d > time.Second {
		d = time.Second
	}
	return d
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

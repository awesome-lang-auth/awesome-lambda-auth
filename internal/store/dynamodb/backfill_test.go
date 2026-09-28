package dynamodb

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"

	auth "github.com/nik2208/awesome-go-auth"
)

// seedPreD6Users writes profiles the way the store wrote them before D6: the
// same item, minus the two GSI1 attributes CreateUser has stamped since. They
// are written straight through the client so the codec cannot "fix" them on the
// way in — that is the whole point of the fixture.
func seedPreD6Users(t *testing.T, client *awsddb.Client, table, tenantID string, n int) []auth.User {
	t.Helper()
	ctx := context.Background()
	out := make([]auth.User, 0, n)
	for i := range n {
		u := auth.User{
			ID:       fmt.Sprintf("old_%04d", i),
			Email:    uniqueEmail("pre-d6"),
			TenantID: tenantID,
		}
		it := profileItem(u)
		delete(it, attrGSI1PK)
		delete(it, attrGSI1SK)
		if _, err := client.PutItem(ctx, &awsddb.PutItemInput{TableName: aws.String(table), Item: it}); err != nil {
			t.Fatalf("put pre-D6 profile %s: %v", u.ID, err)
		}
		out = append(out, u)
	}
	return out
}

// sweep runs the sweep to the end, one page at a time, and returns the totals.
func sweep(t *testing.T, api BackfillAPI, opts BackfillOptions) (pages int, total BackfillPage) {
	t.Helper()
	start := opts.StartKey
	for {
		opts.StartKey = start
		page, err := BackfillUsersPage(context.Background(), api, opts)
		if err != nil {
			t.Fatalf("backfill page %d: %v", pages+1, err)
		}
		pages++
		total.Evaluated += page.Evaluated
		total.Matched += page.Matched
		total.Written += page.Written
		total.Skipped += page.Skipped
		total.Planned = append(total.Planned, page.Planned...)
		if page.NextKey == "" {
			return pages, total
		}
		start = page.NextKey
		if pages > 1000 {
			t.Fatal("the sweep never reached the end of the table")
		}
	}
}

// TestBackfillMakesPreD6ProfilesVisibleToListUsers is the whole reason the job
// exists, driven end to end against DynamoDB Local: profiles written without
// the index attributes are invisible to ListUsers, the sweep writes exactly
// those attributes, and afterwards ListUsers finds every one of them — in the
// same (tenant, id) order a freshly registered profile lands in.
func TestBackfillMakesPreD6ProfilesVisibleToListUsers(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	old := seedPreD6Users(t, client, store.table, "acme", 5)
	fresh := seedUsers(t, store, "acme", 2)

	// Before: only the two post-D6 profiles are in the directory, and every
	// other method still finds the old ones — the index is the only reader
	// that cannot see them.
	before, err := store.ListUsers(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("list before: %v", err)
	}
	if len(before) != len(fresh) {
		t.Fatalf("before the sweep ListUsers returned %v, want only the %d post-D6 profiles", userIDs(before), len(fresh))
	}
	for _, u := range old {
		if _, err := store.GetUserByID(ctx, u.ID, "acme"); err != nil {
			t.Fatalf("GetUserByID cannot see pre-D6 profile %s, which has nothing to do with the index: %v", u.ID, err)
		}
	}

	// Two per page, so the resume token is exercised rather than merely
	// returned once.
	pages, total := sweep(t, client, BackfillOptions{TableName: store.table, PageSize: 2})
	if pages < 2 {
		t.Errorf("the sweep took %d page(s) over %d items with a page size of 2; the resume token was never used", pages, 7)
	}
	if total.Written != len(old) || total.Skipped != 0 {
		t.Errorf("sweep wrote %d and skipped %d, want %d written and none skipped (%v)", total.Written, total.Skipped, len(old), total.Planned)
	}

	after, err := store.ListUsers(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("list after: %v", err)
	}
	want := append(userIDs(old), userIDs(fresh)...)
	sort.Strings(want)
	if fmt.Sprint(userIDs(after)) != fmt.Sprint(want) {
		t.Fatalf("after the sweep ListUsers = %v, want %v", userIDs(after), want)
	}

	// The attributes are the ones CreateUser writes, byte for byte, so a
	// backfilled profile and a registered one are indistinguishable in the
	// index — which is what makes the scoped Query's begins_with reach both.
	for _, u := range old {
		m := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)
		if got := getS(m, attrGSI1PK); got != gsi1AllUsersPK {
			t.Errorf("%s: GSI1PK = %q, want %q", u.ID, got, gsi1AllUsersPK)
		}
		if got, want := getS(m, attrGSI1SK), userGSI1SK("acme", u.ID); got != want {
			t.Errorf("%s: GSI1SK = %q, want %q", u.ID, got, want)
		}
	}
}

// TestBackfillIsIdempotentAndWritesNothingOnADryRun: a second sweep over a
// swept table scans and writes nothing, and a dry run over an unswept one
// reports exactly what a real run would write while leaving the index alone.
func TestBackfillIsIdempotentAndWritesNothingOnADryRun(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	old := seedPreD6Users(t, client, store.table, "", 3)
	seedUsers(t, store, "", 2)

	_, dry := sweep(t, client, BackfillOptions{TableName: store.table, DryRun: true})
	if dry.Written != 0 {
		t.Fatalf("dry run wrote %d profiles", dry.Written)
	}
	if dry.Matched != len(old) || len(dry.Planned) != len(old) {
		t.Errorf("dry run matched %d and planned %v, want the %d pre-D6 profiles", dry.Matched, dry.Planned, len(old))
	}
	still, err := store.ListUsers(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("list after dry run: %v", err)
	}
	if len(still) != 2 {
		t.Fatalf("a dry run changed the directory: ListUsers = %v", userIDs(still))
	}

	_, first := sweep(t, client, BackfillOptions{TableName: store.table})
	if first.Written != len(old) {
		t.Fatalf("first sweep wrote %d, want %d", first.Written, len(old))
	}
	_, second := sweep(t, client, BackfillOptions{TableName: store.table})
	if second.Matched != 0 || second.Written != 0 {
		t.Errorf("second sweep matched %d and wrote %d; the job is meant to be idempotent", second.Matched, second.Written)
	}
}

// TestBackfillSkipsAProfileIndexedMeanwhile is the concurrency argument made
// concrete: a profile that gained its index attributes between the scan and the
// write — here, by a plain PutItem standing in for a concurrent run — is refused
// by the condition and counted as skipped, never overwritten and never an error.
func TestBackfillSkipsAProfileIndexedMeanwhile(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	old := seedPreD6Users(t, client, store.table, "acme", 1)

	// A fake that indexes the profile itself the moment the sweep has scanned
	// it, before the sweep's own write arrives.
	racing := &racingAPI{Client: client, table: store.table, user: old[0]}
	_, total := sweep(t, racing, BackfillOptions{TableName: store.table})
	if total.Matched != 1 || total.Skipped != 1 || total.Written != 0 {
		t.Fatalf("matched %d, skipped %d, written %d; want the one raced profile skipped", total.Matched, total.Skipped, total.Written)
	}

	got, err := store.ListUsers(ctx, "", 100, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].ID != old[0].ID {
		t.Fatalf("ListUsers = %v, want the raced profile exactly once", userIDs(got))
	}
}

// racingAPI wraps the real client and, on the first Scan, rewrites the scanned
// profile with its index attributes present — the state a concurrent
// CreateUser or a second operator's run would have left it in.
type racingAPI struct {
	*awsddb.Client
	table string
	user  auth.User
	raced bool
}

func (r *racingAPI) Scan(ctx context.Context, in *awsddb.ScanInput, optFns ...func(*awsddb.Options)) (*awsddb.ScanOutput, error) {
	out, err := r.Client.Scan(ctx, in, optFns...)
	if err != nil || r.raced {
		return out, err
	}
	r.raced = true
	if _, err := r.Client.PutItem(ctx, &awsddb.PutItemInput{TableName: aws.String(r.table), Item: profileItem(r.user)}); err != nil {
		return nil, err
	}
	return out, nil
}

// TestBackfillResumeTokenRoundTrips pins the token's shape from the outside: it
// is opaque to the operator, survives a command line, and refuses anything the
// sweep did not print.
func TestBackfillResumeTokenRoundTrips(t *testing.T) {
	t.Parallel()

	token, err := encodeBackfillKey(key("USER#acme#usr_1", skProfile))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	back, err := decodeBackfillKey(token)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if getS(back, attrPK) != "USER#acme#usr_1" || getS(back, attrSK) != skProfile {
		t.Errorf("round trip = %v", back)
	}
	for _, bad := range []string{"", "not base64!", "bm90IGpzb24", "e30"} {
		if _, err := decodeBackfillKey(bad); err == nil {
			t.Errorf("decodeBackfillKey(%q) accepted a token the sweep never printed", bad)
		}
	}
}

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// The sweep itself is driven against DynamoDB Local in
// internal/store/dynamodb/backfill_test.go, which is where the behaviour that
// matters — the index becoming visible, the conditional write, the idempotence
// — is pinned. What this file pins is the command around it: the paging loop
// stops where the store says it stops, a failed page prints a key the operator
// can resume from, and a dry run reaches no write.

// fakeBackfillAPI serves a fixed sequence of Scan pages and records every
// UpdateItem. failAt fails the UpdateItem for that user id, once.
type fakeBackfillAPI struct {
	pages   [][]string // user ids per page
	scans   int
	updates []string
	failAt  string
}

func (f *fakeBackfillAPI) Scan(_ context.Context, in *awsddb.ScanInput, _ ...func(*awsddb.Options)) (*awsddb.ScanOutput, error) {
	idx := 0
	if in.ExclusiveStartKey != nil {
		pk := in.ExclusiveStartKey["PK"].(*types.AttributeValueMemberS).Value
		// The fake's resume key names the page it ends: "page-<n>".
		idx = int(pk[len("page-")]-'0') + 1
	}
	f.scans++
	if idx >= len(f.pages) {
		return &awsddb.ScanOutput{ScannedCount: 0}, nil
	}
	out := &awsddb.ScanOutput{ScannedCount: int32(len(f.pages[idx]) + 1)}
	for _, id := range f.pages[idx] {
		out.Items = append(out.Items, map[string]types.AttributeValue{
			"PK":       &types.AttributeValueMemberS{Value: "USER##" + id},
			"SK":       &types.AttributeValueMemberS{Value: "PROFILE"},
			"userId":   &types.AttributeValueMemberS{Value: id},
			"tenantId": &types.AttributeValueMemberS{Value: ""},
		})
	}
	if idx < len(f.pages)-1 {
		out.LastEvaluatedKey = map[string]types.AttributeValue{
			"PK": &types.AttributeValueMemberS{Value: "page-" + string(rune('0'+idx))},
			"SK": &types.AttributeValueMemberS{Value: "PROFILE"},
		}
	}
	return out, nil
}

func (f *fakeBackfillAPI) UpdateItem(_ context.Context, in *awsddb.UpdateItemInput, _ ...func(*awsddb.Options)) (*awsddb.UpdateItemOutput, error) {
	id := strings.TrimPrefix(in.Key["PK"].(*types.AttributeValueMemberS).Value, "USER##")
	if id == f.failAt {
		f.failAt = ""
		return nil, errors.New("ProvisionedThroughputExceededException: simulated")
	}
	f.updates = append(f.updates, id)
	return &awsddb.UpdateItemOutput{}, nil
}

func captureOut(t *testing.T) (*os.File, func() string) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatalf("temp file: %v", err)
	}
	return f, func() string {
		_ = f.Close()
		raw, err := os.ReadFile(f.Name())
		if err != nil {
			t.Fatalf("read output: %v", err)
		}
		return string(raw)
	}
}

func TestBackfillPagesToTheEndAndWritesEveryMatch(t *testing.T) {
	t.Parallel()
	api := &fakeBackfillAPI{pages: [][]string{{"a", "b"}, {"c"}, {}}}
	stdout, out := captureOut(t)
	stderr, errOut := captureOut(t)

	err := backfillAll(context.Background(), api, backfillFlags{table: "t", pageSize: 2}, stdout, stderr)
	if err != nil {
		t.Fatalf("backfillAll: %v\n%s", err, errOut())
	}
	if got := strings.Join(api.updates, ","); got != "a,b,c" {
		t.Errorf("updates = %q, want every profile on every page", got)
	}
	if api.scans != 3 {
		t.Errorf("scans = %d, want one per page", api.scans)
	}
	if s := out(); !strings.Contains(s, "pages 3, evaluated 6, matched 3, indexed 3, skipped 0") {
		t.Errorf("summary missing or wrong:\n%s", s)
	}
	if s := errOut(); strings.Contains(s, "resume with") {
		t.Errorf("a completed sweep printed a resume key:\n%s", s)
	}
}

func TestBackfillDryRunReachesNoWrite(t *testing.T) {
	t.Parallel()
	api := &fakeBackfillAPI{pages: [][]string{{"a"}, {"b"}}}
	stdout, out := captureOut(t)
	stderr, _ := captureOut(t)

	if err := backfillAll(context.Background(), api, backfillFlags{table: "t", pageSize: 1, dryRun: true}, stdout, stderr); err != nil {
		t.Fatalf("backfillAll: %v", err)
	}
	if len(api.updates) != 0 {
		t.Fatalf("dry run wrote %v", api.updates)
	}
	if s := out(); !strings.Contains(s, "would index a") || !strings.Contains(s, "would index b") {
		t.Errorf("dry run did not report what it would have written:\n%s", s)
	}
}

// TestBackfillFailedPagePrintsTheKeyToResumeFrom: the key printed is the START
// of the page that failed, not the end, so resuming repeats that page — which
// the conditional write makes harmless — rather than skipping its remainder.
func TestBackfillFailedPagePrintsTheKeyToResumeFrom(t *testing.T) {
	t.Parallel()
	api := &fakeBackfillAPI{pages: [][]string{{"a"}, {"b", "c"}, {"d"}}, failAt: "c"}
	stdout, _ := captureOut(t)
	stderr, errOut := captureOut(t)

	err := backfillAll(context.Background(), api, backfillFlags{table: "t", pageSize: 2}, stdout, stderr)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want errReported", err)
	}
	if got := strings.Join(api.updates, ","); got != "a,b" {
		t.Errorf("updates before the failure = %q, want a,b", got)
	}
	s := errOut()
	if !strings.Contains(s, "resume with: --start-key ") {
		t.Fatalf("no resume key printed:\n%s", s)
	}
	// The token is the one the first page returned, i.e. the start of page 2.
	line := s[strings.Index(s, "--start-key ")+len("--start-key "):]
	token := strings.Fields(line)[0]
	api2 := &fakeBackfillAPI{pages: api.pages}
	stdout2, _ := captureOut(t)
	stderr2, _ := captureOut(t)
	if err := backfillAll(context.Background(), api2, backfillFlags{table: "t", pageSize: 2, startKey: token}, stdout2, stderr2); err != nil {
		t.Fatalf("resumed run: %v", err)
	}
	if got := strings.Join(api2.updates, ","); got != "b,c,d" {
		t.Errorf("resumed run wrote %q, want the failed page and everything after it", got)
	}
}

func TestBackfillRunRefusesMissingFlags(t *testing.T) {
	t.Parallel()
	stdout, _ := captureOut(t)
	stderr, errOut := captureOut(t)

	err := run(context.Background(), []string{"backfill-users", "--table", "t"}, stdout, stderr)
	if !errors.Is(err, errReported) {
		t.Fatalf("err = %v, want errReported", err)
	}
	if s := errOut(); !strings.Contains(s, "--region") {
		t.Errorf("the missing flag is not named:\n%s", s)
	}
}

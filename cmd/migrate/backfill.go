package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// `migrate backfill-users`: the one-time sweep that makes profiles written
// before the D6 release visible to the admin user directory.
//
// It belongs in this command and not in the function for the reason the
// package comment gives for the Cognito import: it is a bulk operation over the
// whole table, it wants an operator's credentials rather than the function's
// (the execution role grants no dynamodb:Scan, on purpose — see the policy
// comment in infra/sam/template.yaml), and a sweep that an HTTP request could
// trigger would be a route this product is not allowed to have.
//
// Everything about what the sweep does, and why it is safe on a table that is
// serving logins while it runs, is in internal/store/dynamodb/backfill.go. This
// file is the flags, the paging loop, the summary and the resume token — the
// same shape as `migrate cognito`, because an operator who has run one should
// not have to learn the other.
//
// # When to run it
//
// Once, against a table that holds profiles created before the store gained the
// GSI1 user directory, before admin.enabled is turned on for that deployment.
// The 'first-user' access policy asks ListUsers for the first registered
// account, and GET <admin>/api/users pages the same index; on an unswept table
// both under-report, and neither failure is visible from outside. Running it
// again later is free of consequence: a swept table matches nothing and writes
// nothing.

type backfillFlags struct {
	table     string
	region    string
	profile   string
	endpoint  string
	startKey  string
	pageSize  int
	dryRun    bool
	maxPages  int
	quietList bool
}

func runBackfillUsers(ctx context.Context, args []string, stdout, stderr *os.File) error {
	var f backfillFlags
	fs := flag.NewFlagSet("migrate backfill-users", flag.ContinueOnError)
	fs.SetOutput(stderr)

	fs.StringVar(&f.table, "table", "", "the DynamoDB single table to sweep, i.e. stores.connection.tableName (required)")
	fs.StringVar(&f.region, "region", "", "the region the table lives in (required)")
	fs.StringVar(&f.profile, "profile", "", "a profile in the shared AWS config file; empty uses the default credential chain")
	fs.StringVar(&f.endpoint, "endpoint", "", "override the DynamoDB endpoint, for DynamoDB Local")
	fs.StringVar(&f.startKey, "start-key", "", "resume from the key an interrupted run printed")
	fs.IntVar(&f.pageSize, "page-size", ddbstore.DefaultBackfillPageSize, "items evaluated per Scan page (1-1000); a page is the unit of resumption")
	fs.IntVar(&f.maxPages, "max-pages", 0, "stop after this many pages and print the resume key; 0 sweeps to the end")
	fs.BoolVar(&f.dryRun, "dry-run", false, "scan and report exactly what would be indexed, and write nothing")
	fs.BoolVar(&f.quietList, "quiet", false, "do not list every indexed user id, only the per-page counts")

	fs.Usage = func() {
		fmt.Fprint(stderr, "migrate backfill-users writes the GSI1 user-directory attributes onto every profile\n"+
			"that lacks them, so that GET <admin>/api/users and the first-user access policy see\n"+
			"accounts created before the store gained the directory.\n\n"+
			"It is idempotent and safe to run while the table is serving: every write is a\n"+
			"conditional UpdateItem naming the two index attributes and nothing else. Run it\n"+
			"once per table before turning admin.enabled on.\n\n"+
			"flags:\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return flagError(err)
	}

	missing := make([]string, 0, 2)
	if strings.TrimSpace(f.table) == "" {
		missing = append(missing, "--table")
	}
	if strings.TrimSpace(f.region) == "" {
		// Demanded for the reason `migrate cognito` demands it: a sweep against
		// the wrong region is an empty run that looks successful.
		missing = append(missing, "--region")
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "migrate backfill-users: missing required flag(s): %s\n\n", strings.Join(missing, ", "))
		fs.Usage()
		return errReported
	}
	if f.pageSize < 1 || f.pageSize > 1000 {
		fmt.Fprintf(stderr, "migrate backfill-users: --page-size %d is outside 1-1000\n", f.pageSize)
		return errReported
	}
	if f.maxPages < 0 {
		fmt.Fprintf(stderr, "migrate backfill-users: --max-pages %d is negative\n", f.maxPages)
		return errReported
	}

	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{
		Region:   f.region,
		Endpoint: f.endpoint,
		Profile:  f.profile,
	})
	if err != nil {
		fmt.Fprintf(stderr, "migrate backfill-users: %v\n", err)
		return errReported
	}
	return backfillAll(ctx, client, f, stdout, stderr)
}

// backfillTally is the summary across pages.
type backfillTally struct {
	pages     int
	evaluated int
	matched   int
	written   int
	skipped   int
}

// backfillAll pages the table to the end, or to --max-pages, and reports.
//
// One page at a time and the page fully processed before the next is asked
// for, for the reason importAll gives: the resume key that is printed is
// always the start of a page that did not complete, so resuming from it repeats
// at most one page — and repeating a page is harmless, because every write is
// conditional.
func backfillAll(ctx context.Context, api ddbstore.BackfillAPI, f backfillFlags, stdout, stderr *os.File) error {
	var t backfillTally
	// resumeKey is the start of the page currently being processed: what an
	// interrupted or failed run prints. It lags the next key on purpose.
	resumeKey := f.startKey
	nextKey := f.startKey

	if f.dryRun {
		fmt.Fprintf(stdout, "dry run: table %s, nothing will be written\n", f.table)
	}

	for {
		if err := ctx.Err(); err != nil {
			fmt.Fprintf(stderr, "migrate backfill-users: interrupted\n")
			reportBackfill(stdout, stderr, t, resumeKey)
			return errReported
		}

		page, err := ddbstore.BackfillUsersPage(ctx, api, ddbstore.BackfillOptions{
			TableName: f.table,
			PageSize:  int32(f.pageSize),
			StartKey:  nextKey,
			DryRun:    f.dryRun,
		})
		t.pages++
		t.evaluated += page.Evaluated
		t.matched += page.Matched
		t.written += page.Written
		t.skipped += page.Skipped
		if err != nil {
			fmt.Fprintf(stderr, "migrate backfill-users: page %d failed: %v\n", t.pages, err)
			reportBackfill(stdout, stderr, t, resumeKey)
			return errReported
		}

		verb, count := "indexed", page.Written
		if f.dryRun {
			// A dry run writes nothing, so what it reports is what a real run
			// would have written: every match the sweep understood.
			verb, count = "would index", page.Matched-page.Skipped
		}
		fmt.Fprintf(stdout, "page %d: evaluated %d, matched %d, %s %d, skipped %d\n",
			t.pages, page.Evaluated, page.Matched, verb, count, page.Skipped)
		if !f.quietList {
			for _, id := range page.Planned {
				fmt.Fprintf(stdout, "  %s %s\n", verb, id)
			}
		}

		if page.NextKey == "" {
			reportBackfill(stdout, stderr, t, "")
			return nil
		}
		resumeKey = page.NextKey
		nextKey = page.NextKey
		if f.maxPages > 0 && t.pages >= f.maxPages {
			fmt.Fprintf(stdout, "stopped after %d page(s) as asked\n", t.pages)
			reportBackfill(stdout, stderr, t, resumeKey)
			return nil
		}
	}
}

func reportBackfill(stdout, stderr *os.File, t backfillTally, resumeKey string) {
	fmt.Fprintf(stdout, "pages %d, evaluated %d, matched %d, indexed %d, skipped %d\n",
		t.pages, t.evaluated, t.matched, t.written, t.skipped)
	if t.skipped > 0 {
		fmt.Fprintf(stdout, "skipped profiles were indexed by a concurrent registration or run, or deleted since the scan; none needs attention\n")
	}
	if resumeKey != "" {
		fmt.Fprintf(stderr, "\nresume with: --start-key %s\n"+
			"(re-running from the beginning is also safe and is the simpler recovery:\n"+
			"every profile already indexed is skipped rather than rewritten.)\n", resumeKey)
	}
}

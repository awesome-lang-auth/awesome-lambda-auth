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
// before the D6 release visible to the admin user directory, and — since the
// v0.12.0 pin — gives profiles written before that release the by-id pointer the
// console's user detail route reads across tenants.
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
// both under-report, and neither failure is visible from outside. And once more
// after a table written before the v0.12.0 pin has been upgraded — after the
// new release has replaced the old one everywhere, because a profile the old
// code registers mid-rollout gets no pointer: until then
// GET <admin>/api/users/{id} finds only users under the empty tenant, which is
// what it did before. Running it again later is free of consequence: a swept
// table matches nothing and writes nothing — except that an id found under two
// tenants is reported on every run until an operator resolves it.

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
			"that lacks them, so that GET <admin>/api/users sees the accounts created before\n"+
			"the store gained the directory, and the by-id pointer onto every profile that\n"+
			"lacks one, so that GET <admin>/api/users/{id} finds a user under any tenant.\n\n"+
			"It is idempotent and safe to run while the table is serving: every write is\n"+
			"conditional. Run it once per table before turning admin.enabled on, and again\n"+
			"after upgrading a table written before the v0.12.0 pin. An id it finds under\n"+
			"two tenants is reported as a CONFLICT and needs you.\n\n"+
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

	// The by-id pointer half (internal/store/dynamodb backfill.go).
	pointerMatched int
	pointed        int
	pointerSkipped int
	conflicts      []ddbstore.BackfillConflict
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
		t.pointerMatched += page.PointerMatched
		t.pointed += page.PointersWritten
		t.pointerSkipped += page.PointersSkipped
		t.conflicts = append(t.conflicts, page.Conflicts...)
		if err != nil {
			fmt.Fprintf(stderr, "migrate backfill-users: page %d failed: %v\n", t.pages, err)
			reportBackfill(stdout, stderr, t, resumeKey)
			return errReported
		}

		verb, count := "indexed", page.Written
		pverb, pcount := "pointed", page.PointersWritten
		if f.dryRun {
			// A dry run writes nothing, so what it reports is what a real run
			// would have written: every match the sweep understood.
			verb, count = "would index", page.Matched-page.Skipped
			pverb, pcount = "would point", len(page.PlannedPointers)
		}
		fmt.Fprintf(stdout, "page %d: evaluated %d, matched %d, %s %d, skipped %d; unpointed %d, %s %d, conflicts %d\n",
			t.pages, page.Evaluated, page.Matched, verb, count, page.Skipped,
			page.PointerMatched, pverb, pcount, len(page.Conflicts))
		if !f.quietList {
			for _, id := range page.Planned {
				fmt.Fprintf(stdout, "  %s %s\n", verb, id)
			}
			for _, id := range page.PlannedPointers {
				fmt.Fprintf(stdout, "  %s %s\n", pverb, id)
			}
		}
		// Conflicts are listed whatever --quiet says: they are the one outcome
		// that needs the operator.
		for _, c := range page.Conflicts {
			fmt.Fprintf(stderr, "  CONFLICT %s\n", describeConflict(c))
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
	fmt.Fprintf(stdout, "pages %d, evaluated %d, matched %d, indexed %d, skipped %d; unpointed %d, pointed %d, pointer skipped %d, conflicts %d\n",
		t.pages, t.evaluated, t.matched, t.written, t.skipped,
		t.pointerMatched, t.pointed, t.pointerSkipped, len(t.conflicts))
	if t.skipped > 0 || t.pointerSkipped > 0 {
		fmt.Fprintf(stdout, "skipped profiles were indexed by a concurrent registration or run, or deleted since the scan; none needs attention\n")
	}
	if len(t.conflicts) > 0 {
		// The one outcome that is not self-resolving. The pointer is marked, so
		// the console answers 404 for these ids rather than one of the two
		// records, and registering either id again is refused.
		fmt.Fprintf(stderr, "\n%d user id(s) are held under more than one tenant and NEED ATTENTION:\n", len(t.conflicts))
		for _, c := range t.conflicts {
			fmt.Fprintf(stderr, "  %s\n", describeConflict(c))
		}
		fmt.Fprintf(stderr, "Decide which account keeps each id, delete the other, delete the item\n"+
			"PK=UID#<id> SK=UID, and run this command again: it points the id at the survivor.\n"+
			"The console's DELETE reaches only an account under the empty tenant; one under\n"+
			"another tenant is deleted with DELETE <prefix>/account and that account's token,\n"+
			"or by hand. See docs/config-reference.md §16.6.\n")
	}
	if resumeKey != "" {
		fmt.Fprintf(stderr, "\nresume with: --start-key %s\n"+
			"(re-running from the beginning is also safe and is the simpler recovery:\n"+
			"every profile already indexed is skipped rather than rewritten.)\n", resumeKey)
	}
}

// describeConflict names both halves of one conflict, the empty tenant by name
// rather than as an empty string an operator would read as a formatting bug.
func describeConflict(c ddbstore.BackfillConflict) string {
	tenant := func(t string) string {
		if t == "" {
			return `the empty tenant ""`
		}
		return "tenant " + t
	}
	if c.AlreadyAmbiguous {
		return fmt.Sprintf("user id %s: a profile under %s, and the pointer was already marked ambiguous by an earlier run", c.UserID, tenant(c.TenantID))
	}
	return fmt.Sprintf("user id %s: a profile under %s, and the pointer names %s", c.UserID, tenant(c.TenantID), tenant(c.PointerTenantID))
}

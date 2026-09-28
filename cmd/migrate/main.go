// Command migrate imports users from another identity provider into this
// deployment's table, and runs the one-off sweeps that table needs.
//
//	migrate cognito --user-pool-id <id> --table <name> --region <region> \
//	                [--profile <name>] [--dry-run] [--attribute-map <file>]
//	migrate backfill-users --table <name> --region <region> \
//	                [--profile <name>] [--dry-run] [--start-key <token>]
//
// The second is the user-directory backfill D6 declared and nothing ran: see
// backfill.go here and internal/store/dynamodb/backfill.go for what it does and
// why it is a job rather than a store method.
//
// It is an operator tool, run from a workstation or a pipeline, and it is
// deliberately not part of the deployed artifact: nothing about it belongs on a
// Lambda's critical path, it wants credentials for two accounts at once, and a
// bulk import that could be triggered by an HTTP request would be a route this
// product is not allowed to have.
//
// # What it does and does not carry
//
// It carries the records. It cannot carry the passwords, because a Cognito user
// pool yields no password hash to anybody, ever — that is the point of a managed
// directory. Every imported row therefore lands with an EMPTY passwordHash and a
// migration marker, and the passwords are collected one at a time afterwards, on
// each person's next login, through the password-verifier seam in
// internal/store/migrating. Running this command is the first half of a
// migration; the second half is people logging in.
//
// # Resumability, which matters more than speed here
//
// A bulk import runs against somebody else's API over somebody else's network,
// so it will be interrupted. Three decisions make an interruption cheap, and
// each of them is argued where it is implemented:
//
//   - A user that already exists locally is SKIPPED, never overwritten
//     (importUser). Re-running the whole command is therefore always safe, and
//     is the recommended way to recover from anything.
//   - A paging failure stops the run and PRINTS THE RESUME TOKEN of the last
//     page that completed, which --start-token takes (run). Nothing is lost
//     either way, because of the previous point; the token only saves time.
//   - A record with no email address is SKIPPED AND REPORTED, and the run
//     continues (importUser). One unusable record in a pool of forty thousand
//     must not end the import, and it must not be silently dropped either.
//
// The exit status says which of those happened: 0 when every record was written
// or skipped as already present, 1 when any record could not be imported, so a
// pipeline notices without having to parse the summary.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	// SIGINT and SIGTERM cancel the context rather than killing the process, so
	// an interrupted run still prints its summary and its resume token. An
	// import that has written nine thousand rows and tells you nothing about
	// where it stopped is an import you run again from the beginning.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, errReported) {
			fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		}
		os.Exit(1)
	}
}

// errReported is returned by a subcommand that has already written a complete
// explanation of its own failure. main exits non-zero without adding a second,
// less specific line on top of it.
var errReported = errors.New("migrate: reported")

// usage is written by hand rather than taken from a FlagSet, because the flags
// belong to the subcommand and a top-level FlagSet would have none of them to
// print.
const usage = `migrate imports users from another identity provider into this deployment's table.

usage:
  migrate cognito --user-pool-id <id> --table <name> --region <region> [flags]
  migrate backfill-users --table <name> --region <region> [flags]

commands:
  cognito          import users from an Amazon Cognito user pool
  backfill-users   index pre-existing profiles for the admin user directory (run once, before admin.enabled)

run "migrate <command> -h" for the flags.
`

func run(ctx context.Context, args []string, stdout, stderr *os.File) error {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return errReported
	}
	switch args[0] {
	case "cognito":
		return runCognito(ctx, args[1:], stdout, stderr)
	case "backfill-users":
		return runBackfillUsers(ctx, args[1:], stdout, stderr)
	case "-h", "--help", "help":
		fmt.Fprint(stdout, usage)
		return nil
	default:
		fmt.Fprintf(stderr, "migrate: unknown command %q\n\n%s", args[0], usage)
		return errReported
	}
}

// flagError swallows a flag package failure, because the package has already
// written a complete explanation of it to the FlagSet's output — including the
// usage block, for -h. Returning a second error to be printed on top would say
// the same thing twice, and returning nil would exit 0 on a command line that
// never ran.
func flagError(error) error { return errReported }

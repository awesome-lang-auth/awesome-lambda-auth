package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// TestWireDeviationIDsArePinned makes renaming or dropping a product deviation a
// visible act: the ids are handles the docs and the operators key on.
func TestWireDeviationIDsArePinned(t *testing.T) {
	want := []string{
		"admin-actions-list-omits-the-runner-manifest", // D9d
		"admin-first-user-policy-is-refused",
		"admin-login-skips-the-second-factor",
		"csrf-enabled-by-default",
		"docs-page-carries-a-content-security-policy",
		"idp-kid-derived-from-key-material",
		"inbound-webhook-scripts-are-awaited", // D9d
		"inbound-webhook-scripts-run-on-goja", // D9d
		"inbound-webhooks-are-refused-without-a-runner",
		"library-events-are-bridged-into-the-tools-fan-out",
		"oauth-callback-skips-the-second-factor",
		"outgoing-webhook-delivery-races-the-response",
		"production-by-default",
		"queued-webhook-retries-reuse-the-delivery-id", // D9b
		"queued-webhooks-are-delivered-at-least-once",  // D9b
		"rate-limited-routes-answer-429",
		"refresh-token-families",
		"runtime-settings-seed-only-fills-absent-keys",
		// D9c.
		"sse-event-ids-are-ulids",
		"sse-resume-replays-from-the-event-log",
		"templates-dir-only-seeds-absent-ids",
		"tools-admin-login-redirect-points-into-the-admin-mount",
		"tools-api-key-refusal-is-the-cores-bare-401",
		"tools-stream-is-not-mounted-on-api-gateway",
		"uploaded-assets-carry-a-content-security-policy",
		// ui-uploaded-assets-are-not-served was retired by the admin surface:
		// the upload store is the writer D7 said was missing, and the read
		// path now serves it. docs/deviations.md keeps the entry under
		// "Retired" so the id stays resolvable.
		// admin-user-detail-is-single-tenant was retired by the v0.12.0 pin:
		// the core resolves the detail route through UserLookupStore and the
		// DynamoDB store implements it. cmd/auth/admin_test.go
		// TestAdminUserDetailSpansTenants pins the positive behaviour.
	}
	var got []string
	for _, d := range WireDeviations() {
		got = append(got, d.ID)
		fields := map[string]string{
			"Surface":   d.Surface,
			"Behaviour": d.Behaviour,
			"Reference": d.Reference,
			"Why":       d.Why,
			"Spec":      d.Spec,
		}
		for name, v := range fields {
			if strings.TrimSpace(v) == "" {
				t.Errorf("%s: %s is empty; an entry without it is a bug, not a decision", d.ID, name)
			}
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("WireDeviations ids = %v, want %v", got, want)
	}
}

// TestDeviationsIndexIsComplete pins docs/deviations.md to the three registers:
// every product id must open an index row of its own, and every core id from
// auth.CompatibilityNotes() and every store note must appear in it verbatim.
// The failure message names what to add.
func TestDeviationsIndexIsComplete(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "deviations.md"))
	if err != nil {
		t.Fatalf("read docs/deviations.md: %v", err)
	}
	doc := strings.ReplaceAll(string(raw), "\r\n", "\n")

	for _, d := range WireDeviations() {
		// A row of its own, not a mention in another row: the index once lost
		// templates-dir-only-seeds-absent-ids in a merge and a bare
		// substring check still passed, because a sibling row cites it.
		if !strings.Contains(doc, "\n| `"+d.ID+"` |") {
			t.Errorf("docs/deviations.md has no index row for product deviation `%s`", d.ID)
		}
	}
	for _, d := range auth.CompatibilityNotes().KnownDeviations {
		if !strings.Contains(doc, "`"+d.ID+"`") {
			t.Errorf("docs/deviations.md does not index core deviation `%s` (from awesome-go-auth)", d.ID)
		}
	}
	store, err := ddbstore.New(stubDynamoAPI{}, ddbstore.Options{TableName: "deviations-index"})
	if err != nil {
		t.Fatalf("ddbstore.New: %v", err)
	}
	for _, note := range store.CompatibilityNotes() {
		if !strings.Contains(doc, note) {
			t.Errorf("docs/deviations.md does not quote the store note verbatim:\n%s", note)
		}
	}
}

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
		"admin-first-user-policy-is-refused",
		"admin-login-skips-the-second-factor",
		"admin-user-detail-is-single-tenant",
		"csrf-enabled-by-default",
		"docs-page-carries-a-content-security-policy",
		"idp-kid-derived-from-key-material",
		"oauth-callback-skips-the-second-factor",
		"production-by-default",
		"rate-limited-routes-answer-429",
		"refresh-token-families",
		"runtime-settings-seed-only-fills-absent-keys",
		"templates-dir-only-seeds-absent-ids",
		"uploaded-assets-carry-a-content-security-policy",
		// ui-uploaded-assets-are-not-served was retired by the admin surface:
		// the upload store is the writer D7 said was missing, and the read
		// path now serves it. docs/deviations.md keeps the entry under
		// "Retired" so the id stays resolvable.
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
// every product id, every core id from auth.CompatibilityNotes() and every store
// note must appear in it verbatim. The failure message names what to add.
func TestDeviationsIndexIsComplete(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "deviations.md"))
	if err != nil {
		t.Fatalf("read docs/deviations.md: %v", err)
	}
	doc := strings.ReplaceAll(string(raw), "\r\n", "\n")

	for _, d := range WireDeviations() {
		if !strings.Contains(doc, "`"+d.ID+"`") {
			t.Errorf("docs/deviations.md does not index product deviation `%s`", d.ID)
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

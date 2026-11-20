package dynamodb

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// The function's execution role grants an exact list of DynamoDB actions
// (infra/sam/template.yaml, the AuthTableItems statement), and DynamoDB Local
// enforces no IAM at all: a store call the role does not grant passes every
// integration test here and fails with AccessDenied on the deployed function.
// So the two sides are pinned against each other by reading both, with no
// endpoint needed.
//
// TransactWriteItems is the subtle one. It has no IAM action of its own; each
// item inside it is authorised by its own — Put by PutItem, Update by
// UpdateItem, Delete by DeleteItem, and ConditionCheck by ConditionCheckItem —
// so the test looks inside every transaction this package builds.

// templateGrants returns the actions of the AuthTableItems statement.
func templateGrants(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "infra", "sam", "template.yaml"))
	if err != nil {
		t.Fatalf("read the SAM template: %v", err)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	var grants []string
	in := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "- Sid: AuthTableItems":
			in = true
		case in && strings.HasPrefix(trimmed, "- dynamodb:"):
			grants = append(grants, strings.TrimPrefix(trimmed, "- "))
		case in && strings.HasPrefix(trimmed, "Resource:"):
			return grants
		}
	}
	t.Fatal("the SAM template has no AuthTableItems statement ending in a Resource")
	return nil
}

// knownUngrantedConditionChecks are the transactions that carry a bare
// ConditionCheck the role does not grant, by file. They predate the check and
// are a gap of their own, recorded rather than fixed here: AddRoleToUser
// (roles.go, data-model #29) and AssociateUserWithTenant (tenants.go, #43). The
// list may only shrink.
var knownUngrantedConditionChecks = map[string]bool{
	"roles.go":   true,
	"tenants.go": true,
}

// TestUserTransactionsUseOnlyGrantedActions: every method of the store's API
// interface, and every kind of item any transaction in this package builds,
// is an action the role grants. The user store's own transactions — createUser,
// DeleteUser's profile-and-pointer write, the backfill — are the ones the
// by-id pointer added, and DeleteUser's in particular runs on every
// deployment.
func TestUserTransactionsUseOnlyGrantedActions(t *testing.T) {
	grants := templateGrants(t)
	granted := func(action string) bool { return slices.Contains(grants, "dynamodb:"+action) }

	api := reflect.TypeOf((*API)(nil)).Elem()
	for i := 0; i < api.NumMethod(); i++ {
		name := api.Method(i).Name
		if name == "TransactWriteItems" {
			continue // authorised per item, below
		}
		if !granted(name) {
			t.Errorf("the store's API calls %s, which AuthTableItems does not grant", name)
		}
	}

	itemAction := map[string]string{
		"Put":            "PutItem",
		"Update":         "UpdateItem",
		"Delete":         "DeleteItem",
		"ConditionCheck": "ConditionCheckItem",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", file, err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isTransactWriteItemLit(lit) {
				return true
			}
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				field, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				action, ok := itemAction[field.Name]
				if !ok {
					continue
				}
				seen++
				if granted(action) {
					continue
				}
				if field.Name == "ConditionCheck" && knownUngrantedConditionChecks[file] {
					continue
				}
				t.Errorf("%s: a transaction item %s needs dynamodb:%s, which AuthTableItems does not grant; "+
					"DynamoDB Local will not notice, the deployed function will answer AccessDenied",
					fset.Position(kv.Pos()), field.Name, action)
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("found no transaction items at all; the scan is not looking where the store builds them")
	}
}

// isTransactWriteItemLit reports whether lit is a types.TransactWriteItem,
// written out (types.TransactWriteItem{...}) or elided inside a
// []types.TransactWriteItem{{...}} — the elided form has no type of its own, so
// it is recognised by its keys, which no other struct this package builds
// shares as a set.
func isTransactWriteItemLit(lit *ast.CompositeLit) bool {
	if sel, ok := lit.Type.(*ast.SelectorExpr); ok {
		return sel.Sel.Name == "TransactWriteItem"
	}
	if lit.Type != nil || len(lit.Elts) != 1 {
		return false
	}
	kv, ok := lit.Elts[0].(*ast.KeyValueExpr)
	if !ok {
		return false
	}
	field, ok := kv.Key.(*ast.Ident)
	if !ok {
		return false
	}
	switch field.Name {
	case "Put", "Update", "Delete", "ConditionCheck":
		return true
	}
	return false
}

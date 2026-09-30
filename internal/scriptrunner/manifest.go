package scriptrunner

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// The actions a script may call, and why they are a table compiled into this
// binary rather than anything a request can name.
//
// In the reference `actions` is a Record<id, fn> that ActionRegistry.buildContext
// fills from a module-level registry, which the @webhookAction decorator
// populates at import time (webhook-action.ts:56-115). The script awaits one —
// `await actions['user.suspend'](body.userId)` — and the function runs in the
// API process with the API process's credentials. That last clause is what this
// product's design exists to change. The core hands across only the resolved
// list of ids (tools_webhook.go, resolveInboundActions: the intersection of
// AuthSettings.EnabledWebhookActions and WebhookConfig.AllowedActions), and the
// functions live here, in the runner, where the only credentials are the
// runner's IAM role.
//
// So an action is two edits, and both are the point:
//
//  1. An entry in Shipped() below: its id, the metadata the reference's admin
//     UI shows, its dependsOn, the IAM it needs, and the Go function.
//  2. The same IAM, granted to ScriptRunnerRole in infra/sam/template.yaml. The
//     role grants nothing but writing its own log group today, so an action
//     added without step 2 fails with AccessDenied the first time a script
//     calls it — which is the sandbox working, not a bug.
//
// Nothing else widens what a script can reach. The engine has no I/O primitive
// of any kind (no require, no fetch, no process, no timers — goja implements
// ECMAScript and nothing of Node), so an action is the only door out, and the
// role is the lock on it.

// Action is one entry of the runner's manifest: the reference's
// RegisteredAction (webhook-action.ts:34-58) with the Go function in place of
// the bound method, and the IAM it needs written down beside it.
type Action struct {
	// ID is the stable identifier the administrator's two lists name, e.g.
	// "user.suspend". The reference's WebhookActionMeta.id.
	ID string
	// Label, Category and Description are the reference's display metadata.
	// Nothing in this build shows them yet: GET <admin>/api/actions answers an
	// empty list in the imported core whatever this table holds, because the
	// core has no seam to be told about a registry that lives in another
	// process (upstream adminListActions; see docs/inbound-webhooks.md).
	Label       string
	Category    string
	Description string
	// DependsOn is the reference's dependsOn: other ids that must be in the
	// effective set for this action to be exposed (webhook-action.ts:111-113).
	DependsOn []string
	// IAM is the set of IAM actions this action's Fn calls, written as the
	// policy would write them ("dynamodb:UpdateItem on the auth table"). It is
	// documentation for the second edit above, and it is required to be
	// non-empty whenever Fn touches AWS; an action that needs nothing says
	// "none".
	IAM []string
	// Fn runs the action. args are the script's arguments, exported to Go
	// values; what it returns is handed back to the script as the fulfilment
	// value of a promise, and an error rejects that promise — so a script's
	// `await` sees exactly what an awaited async function would give it in the
	// reference.
	//
	// It runs synchronously on the engine's goroutine and must return before
	// the script continues. That is a constraint and it is deliberate: the
	// sandbox has no event loop, so a promise settled later, from another
	// goroutine, would never be observed. ctx carries the run's deadline;
	// honour it, because the engine cannot interrupt Go code.
	Fn func(ctx context.Context, args []any) (any, error)
}

// Manifest is the runner's action table.
type Manifest []Action

// Shipped is the manifest compiled into cmd/script-runner. It is empty, on
// purpose and for the reason the reference's registry is empty until a host
// decorates something: which effects an inbound webhook may cause is the
// deployment's decision, and each one is paid for in IAM (see the file header).
// A script calling any action on this build meets `actions[id]` undefined and a
// TypeError, which the runner reports as a script that threw — the reference's
// answer for the same script against an empty registry.
func Shipped() Manifest { return nil }

// validate refuses a manifest that could not be resolved unambiguously. It runs
// once, when the runner is built, so a broken table fails the cold start rather
// than a webhook.
func (m Manifest) validate() error {
	seen := make(map[string]struct{}, len(m))
	for i, a := range m {
		id := strings.TrimSpace(a.ID)
		switch {
		case id == "" || id != a.ID:
			return fmt.Errorf("scriptrunner: manifest entry %d has an empty or padded id %q", i, a.ID)
		case a.Fn == nil:
			return fmt.Errorf("scriptrunner: action %q has no function", a.ID)
		case len(a.IAM) == 0:
			return fmt.Errorf("scriptrunner: action %q does not say what IAM it needs; write \"none\" if it needs nothing, and grant the rest to the runner's role", a.ID)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("scriptrunner: action %q is declared twice", a.ID)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// expose is ActionRegistry.buildContext (webhook-action.ts:104-115) with the
// core's half of it already done: allowed is the list the core resolved, which
// is the reference's effectiveSet. An action is exposed when it is in that list,
// in this manifest, and every one of its dependsOn is in that list too.
//
// The list is a closed upper bound. Nothing here can add an id to it — an
// action in the manifest and not in allowed is absent from the sandbox, an id
// in allowed and not in the manifest is absent too — which is the property the
// core's contract names: "a runner may narrow it further; a runner that widens
// it is broken" (tools_webhook.go).
func (m Manifest) expose(allowed []string) []Action {
	effective := make(map[string]struct{}, len(allowed))
	for _, id := range allowed {
		effective[id] = struct{}{}
	}
	var out []Action
	for _, a := range m {
		if _, ok := effective[a.ID]; !ok {
			continue
		}
		depsOK := true
		for _, dep := range a.DependsOn {
			if _, ok := effective[dep]; !ok {
				depsOK = false
				break
			}
		}
		if depsOK {
			out = append(out, a)
		}
	}
	return out
}

// errDeadline is what the interrupt carries when the run's deadline passes.
var errDeadline = errors.New("the script ran past its deadline and was interrupted")

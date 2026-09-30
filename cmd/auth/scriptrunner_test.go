package main

import (
	"context"

	"errors"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// D9d, from the auth function's side: the inbound route mounted with a runner,
// driven end to end through the Lambda event path with a fake runner in the
// seam, and the property the whole block rests on — that this binary links no
// JavaScript engine — checked on the import graph itself.

// inboundEnv is toolsEnv with the inbound route mounted and a runner named.
func inboundEnv(kv ...string) map[string]string {
	return toolsEnv(append([]string{
		"AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS", "true",
		"AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_RUNNER_FUNCTION", "stack-script-runner",
		"AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_TIMEOUT_MS", "3000",
	}, kv...)...)
}

// fakeRunner stands in for the runner Lambda. It records what crossed the seam
// and answers what the test told it to.
type fakeRunner struct {
	mu       sync.Mutex
	requests []auth.InboundScriptRequest
	deadline []time.Duration

	result auth.InboundScriptResult
	emit   bool
	err    error
}

func (f *fakeRunner) RunInboundScript(ctx context.Context, req auth.InboundScriptRequest) (auth.InboundScriptResult, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if d, ok := ctx.Deadline(); ok {
		f.deadline = append(f.deadline, time.Until(d))
	}
	return f.result, f.emit, f.err
}

func newInboundApp(t *testing.T, runner auth.InboundScriptRunner, provider, script string) (*App, map[string]string) {
	t.Helper()
	bundle := newToolsBundle()
	if _, err := bundle.bundle.webhooks.(*auth.MemoryWebhookStore).AddWebhook(context.Background(), auth.WebhookConfig{
		URL:            "https://receiver.example.test/unused",
		Events:         []string{},
		Provider:       provider,
		JSScript:       script,
		AllowedActions: []string{"user.suspend"},
	}); err != nil {
		t.Fatalf("add webhook: %v", err)
	}
	app, err := New(context.Background(), Options{
		Getenv:       envFunc(inboundEnv()),
		Logger:       discardLogger(),
		Stores:       bundle.factory,
		ScriptRunner: runner,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	creds := registerAndToken(t, app, testEmail)
	return app, jsonHeaders("authorization", "Bearer "+creds.accessToken)
}

// TestAnInboundWebhookWithAScriptIsTrackedThroughTheRunner is the brief's end
// to end: POST <tools>/webhook/<provider> for a row with a script, the runner
// answers a result, and the event is on GET <tools>/telemetry.
func TestAnInboundWebhookWithAScriptIsTrackedThroughTheRunner(t *testing.T) {
	t.Parallel()
	const script = "result = {event: 'identity.tenant.user.removed', data: body}"
	runner := &fakeRunner{
		result: auth.InboundScriptResult{Event: "identity.tenant.user.removed", Data: map[string]any{"id": "evt_1"}, TenantID: "t_1"},
		emit:   true,
	}
	app, bearer := newInboundApp(t, runner, "billing", script)

	resp := invoke(t, app, http.MethodPost, "/tools/webhook/billing", jsonHeaders(), nil, ` {"id":"evt_1","amount":12} `)
	if resp.StatusCode != http.StatusOK || strings.TrimSpace(resp.Body) != `{"ok":true}` {
		t.Fatalf("webhook = %d %s, want 200 {\"ok\":true} (tools.router.ts:322)", resp.StatusCode, resp.Body)
	}

	// What crossed: the core's request, the script verbatim, the body raw —
	// and an empty allowlist, because no settings store has enabled any
	// action (tools_webhook.go, inboundEnabledActions).
	if len(runner.requests) != 1 {
		t.Fatalf("the runner was called %d times, want once", len(runner.requests))
	}
	got := runner.requests[0]
	if got.Provider != "billing" || got.Script != script || got.WebhookID == "" {
		t.Errorf("request = %+v", got)
	}
	if string(got.Body) != `{"id":"evt_1","amount":12}` {
		t.Errorf("body crossed as %s, want the provider's bytes", got.Body)
	}
	if len(got.Actions) != 0 {
		t.Errorf("actions = %v, want none: nothing enabled them globally", got.Actions)
	}
	// The deadline is tools.inboundWebhooks.scriptTimeoutMs.
	if d := runner.deadline[0]; d > 3*time.Second || d < 2*time.Second {
		t.Errorf("the runner's deadline was %v away, want the 3000 ms the knob set", d)
	}

	q := invoke(t, app, http.MethodGet, "/tools/telemetry?event=identity.tenant.user.removed", bearer, nil, "")
	if q.StatusCode != http.StatusOK {
		t.Fatalf("telemetry = %d %s", q.StatusCode, q.Body)
	}
	data, _ := decodeBody(t, q)["data"].([]any)
	if len(data) != 1 {
		t.Fatalf("telemetry = %v, want the one event the script declared", data)
	}
	row, _ := data[0].(map[string]any)
	payload, _ := row["data"].(map[string]any)
	if row["tenantId"] != "t_1" || payload["id"] != "evt_1" {
		t.Errorf("row = %v, want the runner's result", row)
	}
}

// TestTheRunnersThreeAnswersReachTheWire: no result is acknowledged and
// tracks nothing; a failed run is the core's 400 and tracks nothing, so the
// provider redelivers.
func TestTheRunnersThreeAnswersReachTheWire(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		runner *fakeRunner
		status int
		body   string
	}{
		{"no result", &fakeRunner{}, http.StatusOK, `{"ok":true}`},
		{"a failed run", &fakeRunner{err: errors.New("lambda: script runner failed the run")}, http.StatusBadRequest, `{"error":"Webhook processing failed"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			app, bearer := newInboundApp(t, tc.runner, "billing", "throw new Error('x')")
			resp := invoke(t, app, http.MethodPost, "/tools/webhook/billing", jsonHeaders(), nil, `{"id":"evt_1"}`)
			if resp.StatusCode != tc.status || strings.TrimSpace(resp.Body) != tc.body {
				t.Errorf("webhook = %d %s, want %d %s", resp.StatusCode, resp.Body, tc.status, tc.body)
			}
			q := invoke(t, app, http.MethodGet, "/tools/telemetry", bearer, nil, "")
			for _, row := range decodeBody(t, q)["data"].([]any) {
				if ev, _ := row.(map[string]any)["event"].(string); !strings.HasPrefix(ev, "identity.") {
					t.Errorf("something was tracked: %v", row)
				}
			}
		})
	}

	// A provider with no row never reaches the runner, and is acknowledged:
	// the reference with no script and no onWebhook.
	runner := &fakeRunner{}
	app, _ := newInboundApp(t, runner, "billing", "result = null")
	resp := invoke(t, app, http.MethodPost, "/tools/webhook/nobody", jsonHeaders(), nil, `{}`)
	if resp.StatusCode != http.StatusOK || len(runner.requests) != 0 {
		t.Errorf("an unknown provider = %d, runner called %d times; want 200 and no call", resp.StatusCode, len(runner.requests))
	}
}

// TestTheRealInvokerIsWiredWhenNothingIsInjected: the composition the binary
// builds, and the three configurations that build none.
func TestTheRealInvokerIsWiredWhenNothingIsInjected(t *testing.T) {
	t.Parallel()
	load := func(env map[string]string) *config.Config {
		cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		return cfg
	}
	runner, err := newScriptRunner(load(inboundEnv()), nil)
	if err != nil {
		t.Fatalf("newScriptRunner: %v", err)
	}
	invoker, ok := runner.(*awsintegration.LambdaScriptRunner)
	if !ok || invoker.FunctionName() != "stack-script-runner" {
		t.Fatalf("runner = %T %v, want the Lambda invoker for stack-script-runner", runner, runner)
	}
	for name, env := range map[string]map[string]string{
		"tools off":   with(baseEnv(), "AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_RUNNER_FUNCTION", "stack-script-runner"),
		"inbound off": toolsEnv("AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_RUNNER_FUNCTION", "stack-script-runner"),
	} {
		if r, err := newScriptRunner(load(env), &fakeRunner{}); err != nil || r != nil {
			t.Errorf("%s: runner = %v, %v; want none", name, r, err)
		}
	}
	// And a runner named with nothing to invoke it is an inert knob.
	var reported bool
	for _, g := range unwiredKnobs(load(toolsEnv("AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_RUNNER_FUNCTION", "stack-script-runner"))) {
		reported = reported || g.Path == "tools.inboundWebhooks.scriptRunnerFunction"
	}
	if !reported {
		t.Error("a script runner named with the inbound route off was not reported as inert")
	}
}

// TestRS15AcceptsANamedRunner: the refusal D9a wrote is narrowed, not
// retired — the default still refuses, and naming a runner loads.
func TestRS15AcceptsANamedRunner(t *testing.T) {
	t.Parallel()
	if _, err := New(context.Background(), Options{Getenv: envFunc(inboundEnv()), Logger: discardLogger(), Stores: memoryStores, ScriptRunner: &fakeRunner{}}); err != nil {
		t.Errorf("a tools block with a named runner was refused: %v", err)
	}
}

// javascriptEngines are the module paths of every JavaScript engine a Go
// binary could link: pure-Go interpreters, cgo bindings to V8 and QuickJS,
// and the WebAssembly runtimes a JavaScript engine can be shipped inside.
var javascriptEngines = []string{
	"github.com/dop251/goja",
	"github.com/grafana/sobek",
	"github.com/robertkrimen/otto",
	"rogchap.com/v8go",
	"github.com/tommie/v8go",
	"github.com/buke/quickjs-go",
	"github.com/lithdew/quickjs",
	"modernc.org/quickjs",
	"github.com/fastschema/qjs",
	"github.com/tetratelabs/wazero",
	"github.com/wasmerio/wasmer-go",
	"github.com/bytecodealliance/wasmtime-go",
}

// TestTheAuthBinaryLinksNoJavaScriptEngine is the owner's decision of
// 2026-09-12 as an assertion: the auth function — the process with the signing
// keys, the session store and the password hashes — never links a JavaScript
// engine. The runner (cmd/script-runner) does, and the two share only
// internal/scriptrunner/wire, which imports none.
//
// It asks the toolchain for this package's dependency graph, the set of
// packages that are linked, rather than grepping imports: an engine arriving
// transitively through some helper package is exactly the regression this
// exists to catch. The go command is always present where tests run — the
// gate's container and CI's setup-go — so its absence is a failure, not a
// skip.
func TestTheAuthBinaryLinksNoJavaScriptEngine(t *testing.T) {
	t.Parallel()
	out, err := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps failed (%v); this test needs the go command to read the import graph:\n%s", err, out)
	}
	deps := strings.Fields(string(out))
	if len(deps) < 50 {
		t.Fatalf("go list -deps returned %d packages, which is not the auth binary's graph:\n%s", len(deps), out)
	}
	for _, dep := range deps {
		for _, engine := range javascriptEngines {
			if dep == engine || strings.HasPrefix(dep, engine+"/") {
				t.Errorf("cmd/auth links %s, a JavaScript engine. Inbound-webhook scripts run in cmd/script-runner, "+
					"never in the auth function (docs/inbound-webhooks.md); find the import that brought it with "+
					"`go mod why -m %s` and move it behind internal/scriptrunner/wire", dep, engine)
			}
		}
		// The engine package itself, whatever it one day embeds.
		if dep == "github.com/nik2208/awesome-lambda-auth/internal/scriptrunner" {
			t.Error("cmd/auth links internal/scriptrunner, the runner's engine; it may import only internal/scriptrunner/wire")
		}
	}
	// And the one it must link, so the check above is looking at the right
	// graph.
	var wired bool
	for _, dep := range deps {
		wired = wired || dep == "github.com/nik2208/awesome-lambda-auth/internal/scriptrunner/wire"
	}
	if !wired {
		t.Error("cmd/auth does not link internal/scriptrunner/wire, so this is not the graph of a binary with the invoker in it")
	}

	// The runner is the one that does, which keeps the list above honest.
	out, err = exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", "../script-runner").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps ../script-runner: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "github.com/dop251/goja\n") {
		t.Error("cmd/script-runner does not link goja; the engine list above no longer names the engine this product uses")
	}
}

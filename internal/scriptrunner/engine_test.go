package scriptrunner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nik2208/awesome-lambda-auth/internal/scriptrunner/wire"
)

// The runner's half of the byte-level pin: every test that can assert what a
// run answers asserts it against the same testdata the invoker decodes
// (internal/scriptrunner/wire/testdata).

func wireFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("wire", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return bytes.TrimSpace(raw)
}

// pinnedRequest is testdata/request.json with the script replaced, so every
// run below starts from the bytes the invoker sends.
func pinnedRequest(t *testing.T, script string) wire.Request {
	t.Helper()
	var req wire.Request
	if err := json.Unmarshal(wireFixture(t, "request.json"), &req); err != nil {
		t.Fatalf("decode request fixture: %v", err)
	}
	req.Script = script
	// The fixture's deadline is a fixed instant, long past by the time this
	// runs; the tests that care about deadlines set their own.
	req.DeadlineUnixMs = 0
	return req
}

// lockedBuffer is a log sink the race detector accepts.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newRunner(t *testing.T, opts Options) (*Runner, *lockedBuffer) {
	t.Helper()
	logs := &lockedBuffer{}
	opts.Log = slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	r, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r, logs
}

func run(t *testing.T, r *Runner, req wire.Request) (wire.Response, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return r.Run(ctx, req)
}

// mustEncodeAs asserts a response's bytes against a shared fixture.
func mustEncodeAs(t *testing.T, resp wire.Response, fixture string) {
	t.Helper()
	got, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := wireFixture(t, fixture); !bytes.Equal(got, want) {
		t.Errorf("the run answered\n  %s\nwant the pinned %s\n  %s", got, fixture, want)
	}
}

// TestAScriptThatSetsResultIsTheMappedResult: the brief's own script, the one
// the contract suite registers, answers the pinned result bytes.
func TestAScriptThatSetsResultIsTheMappedResult(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{})
	resp, err := run(t, r, pinnedRequest(t,
		"result = {event: 'identity.tenant.user.removed', data: body, userId: 'u_1', tenantId: 't_1'}"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	mustEncodeAs(t, resp, "response-result.json")
}

// TestAScriptThatDecidesNothingIsNoResult: null, a non-object, an object with
// no string event — the reference's three silent cases (:299).
func TestAScriptThatDecidesNothingIsNoResult(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{})
	for _, script := range []string{
		"",
		"result = null",
		"result = 'identity.tenant.user.removed'",
		"result = {data: body}",
		"result = {event: 42}",
		"result = {event: new String('boxed')}",
		"let result = {event: 'shadowed'}", // a local; the global stays null, there too
	} {
		resp, err := run(t, r, pinnedRequest(t, script))
		if err != nil {
			t.Errorf("%q: Run: %v", script, err)
			continue
		}
		mustEncodeAs(t, resp, "response-none.json")
	}
}

// TestAScriptThatThrowsIsNoResultNotAnError is the single most important line
// of the contract: an error here would make every broken script an infinite
// redelivery loop.
func TestAScriptThatThrowsIsNoResultNotAnError(t *testing.T) {
	t.Parallel()
	r, logs := newRunner(t, Options{})
	for _, script := range []string{
		"throw new Error('boom')",
		"await Promise.reject(new TypeError('rejected'))",
		"undefinedFunction()",
		"this is not javascript",
		// The reference's wrapper has no newline before `})()`, so a script
		// ending in a line comment swallows it — a SyntaxError there, and here.
		"result = {event: 'x'} // trailing comment",
		"function f() { return f() } f()",
	} {
		resp, err := run(t, r, pinnedRequest(t, script))
		if err != nil {
			t.Errorf("%q: a script that threw was reported as a runner failure: %v", script, err)
			continue
		}
		mustEncodeAs(t, resp, "response-threw.json")
	}
	if !strings.Contains(logs.String(), "inbound webhook script threw") {
		t.Error("a script that threw was not logged; the reference logs it with console.error (:296, :303)")
	}
}

// TestResultIsReadEvenWhenTheScriptThrew: the reference's result check sits
// after its catch (:293-301), so an assignment that precedes the throw is
// tracked.
func TestResultIsReadEvenWhenTheScriptThrew(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{})
	resp, err := run(t, r, pinnedRequest(t,
		"result = {event: 'identity.tenant.user.removed', data: body, userId: 'u_1', tenantId: 't_1'}; await null; throw new Error('after')"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	mustEncodeAs(t, resp, "response-result.json")
}

// TestAScriptPastItsDeadlineIsKilledAndIsATransportError: the run is the
// runner's failure, so the core answers 400 and the provider redelivers.
func TestAScriptPastItsDeadlineIsKilledAndIsATransportError(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{Margin: time.Millisecond})
	for _, script := range []string{
		"while (true) {}",
		"await null; for (;;) {}", // past the first await: the reference's timeout no longer applies there
		"result = {get event() { for (;;) {} }}",
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		started := time.Now()
		_, err := r.Run(ctx, pinnedRequest(t, script))
		cancel()
		if err == nil || !errors.Is(err, errDeadline) {
			t.Errorf("%q: Run = %v, want the deadline error", script, err)
		}
		if elapsed := time.Since(started); elapsed > 2*time.Second {
			t.Errorf("%q: the interrupt took %v", script, elapsed)
		}
	}

	// The invoker's deadline wins when it is earlier than the Lambda's.
	req := pinnedRequest(t, "while (true) {}")
	req.DeadlineUnixMs = time.Now().Add(150 * time.Millisecond).UnixMilli()
	started := time.Now()
	if _, err := run(t, r, req); !errors.Is(err, errDeadline) {
		t.Errorf("the request's deadline was not honoured: %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("the request's deadline of 150 ms took %v", elapsed)
	}

	// And one already past is refused before anything runs.
	req.DeadlineUnixMs = time.Now().Add(-time.Second).UnixMilli()
	if _, err := run(t, r, req); !errors.Is(err, errDeadline) {
		t.Errorf("a request whose deadline had passed was run: %v", err)
	}
}

// TestAPromiseNothingCanSettleIsTheScriptsOwnFailure: no timers, no event
// loop, every action settled before it returns — so a pending promise after
// the job queue drains is final, and answering at once beats billing to the
// deadline.
func TestAPromiseNothingCanSettleIsTheScriptsOwnFailure(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{})
	started := time.Now()
	resp, err := run(t, r, pinnedRequest(t, "result = {event: 'x'}; await new Promise(() => {})"))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	mustEncodeAs(t, resp, "response-never-settled.json")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Errorf("a promise that can never settle was waited on for %v", elapsed)
	}
}

// TestTheScriptHasNoPrimitiveToReachAnything: what a node:vm context lacks,
// this lacks — and the one global V8 has that goja does not (Intl), pinned
// because a script ported from the reference meets it.
func TestTheScriptHasNoPrimitiveToReachAnything(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{})
	for _, name := range []string{
		"require", "module", "exports", "process", "Buffer", "global",
		"fetch", "XMLHttpRequest", "WebSocket",
		"setTimeout", "setInterval", "setImmediate", "queueMicrotask",
		"Intl", "WebAssembly",
	} {
		resp, err := run(t, r, pinnedRequest(t,
			"result = {event: typeof "+name+"}"))
		if err != nil {
			t.Fatalf("%s: Run: %v", name, err)
		}
		if resp.Result == nil || resp.Result.Event != "undefined" {
			t.Errorf("typeof %s = %+v, want undefined", name, resp.Result)
		}
	}
	// Calling one is a script that threw — the reference's ReferenceError.
	resp, err := run(t, r, pinnedRequest(t, "require('fs')"))
	if err != nil || resp.Reason != wire.ReasonThrew {
		t.Errorf("require('fs') = %+v, %v; want a script that threw", resp, err)
	}
	// And the four the reference does put in scope are there.
	resp, err = run(t, r, pinnedRequest(t,
		"result = {event: [typeof body, typeof actions, typeof result, typeof console].join(',')}"))
	if err != nil || resp.Result == nil || resp.Result.Event != "object,object,object,object" {
		t.Errorf("the four sandbox variables = %+v, %v", resp.Result, err)
	}
}

// TestTheLanguageAScriptUsesIsThere: what a mapping script written against the
// reference reaches for.
func TestTheLanguageAScriptUsesIsThere(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{})
	script := strings.Join([]string{
		"const { id, nested: { ok } } = body;",
		"const n = await Promise.resolve(body.amount);",
		"const tag = `evt:${id}:${n}`;",
		"class Box { #v; constructor(v) { this.#v = v } get v() { return this.#v } }",
		"const extra = { ...body, missing: body.nope?.deep ?? 'dflt', lb: /(?<=a)b/.test('ab'), box: new Box(3).v, arr: [1, [2]].flat().length };",
		"result = { event: tag, data: extra, userId: ok ? 'u' : 'x' };",
	}, " ")
	resp, err := run(t, r, pinnedRequest(t, script))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if resp.Result == nil || resp.Result.Event != "evt:evt_1:12" || resp.Result.UserID != "u" {
		t.Fatalf("result = %+v", resp.Result)
	}
	got, _ := json.Marshal(resp.Result.Data)
	const want = `{"amount":12,"arr":2,"box":3,"id":"evt_1","lb":true,"missing":"dflt","nested":{"ok":true}}`
	if string(got) != want {
		t.Errorf("data = %s, want %s", got, want)
	}
}

// TestResultMembersOfTheWrongTypeAreDropped: the core's contract — data is an
// object or nothing, userId and tenantId are strings or nothing — and a data
// the engine cannot encode is dropped rather than failing a run every
// redelivery would fail again.
func TestResultMembersOfTheWrongTypeAreDropped(t *testing.T) {
	t.Parallel()
	r, logs := newRunner(t, Options{})
	for _, script := range []string{
		"result = {event: 'e', data: [1, 2], userId: 7, tenantId: null}",
		"result = {event: 'e', data: 'text'}",
		"const c = {}; c.self = c; result = {event: 'e', data: c}",
		"result = {event: 'e', data: {n: 10n}}",
	} {
		resp, err := run(t, r, pinnedRequest(t, script))
		if err != nil {
			t.Fatalf("%q: Run: %v", script, err)
		}
		got, _ := json.Marshal(resp)
		if string(got) != `{"outcome":"result","result":{"event":"e"}}` {
			t.Errorf("%q answered %s, want the event alone", script, got)
		}
	}
	if !strings.Contains(logs.String(), "not JSON-encodable") {
		t.Error("an unencodable data was dropped without a log line")
	}
}

// testManifest is an inert reference action and two that exist to be
// filtered. Nothing like it is compiled into the runner (Shipped is empty).
func testManifest(calls *[]string) Manifest {
	echo := func(id string) func(context.Context, []any) (any, error) {
		return func(_ context.Context, args []any) (any, error) {
			*calls = append(*calls, id)
			return map[string]any{"action": id, "args": args}, nil
		}
	}
	return Manifest{
		{ID: "test.echo", IAM: []string{"none"}, Fn: echo("test.echo")},
		{ID: "test.fail", IAM: []string{"none"}, Fn: func(context.Context, []any) (any, error) {
			return nil, errors.New("downstream refused")
		}},
		{ID: "test.dependent", IAM: []string{"none"}, DependsOn: []string{"test.echo"}, Fn: echo("test.dependent")},
		{ID: "test.unlisted", IAM: []string{"none"}, Fn: echo("test.unlisted")},
	}
}

// TestActionsAreNeverWidened: an action is callable only when the resolved
// list names it, the manifest has it, and its dependsOn are in the list — and
// awaiting one gives the script its value, or its rejection.
func TestActionsAreNeverWidened(t *testing.T) {
	t.Parallel()
	var calls []string
	r, _ := newRunner(t, Options{Manifest: testManifest(&calls)})

	expose := func(allowed []string) string {
		req := pinnedRequest(t, "result = {event: Object.keys(actions).sort().join(',')}")
		req.Actions = allowed
		resp, err := run(t, r, req)
		if err != nil || resp.Result == nil {
			t.Fatalf("Run(%v) = %+v, %v", allowed, resp, err)
		}
		return resp.Result.Event
	}
	for _, tc := range []struct {
		allowed []string
		want    string
	}{
		{nil, ""},
		{[]string{"user.suspend"}, ""}, // in the list, not in the manifest
		{[]string{"test.echo"}, "test.echo"},
		{[]string{"test.dependent"}, ""}, // its dependency is not in the list
		{[]string{"test.dependent", "test.echo"}, "test.dependent,test.echo"},
		{[]string{"test.echo", "test.fail"}, "test.echo,test.fail"},
	} {
		if got := expose(tc.allowed); got != tc.want {
			t.Errorf("allowed %v exposed %q, want %q", tc.allowed, got, tc.want)
		}
	}

	// Outside the list, an action is not callable: the reference's TypeError,
	// reported as a script that threw, and the function never runs.
	req := pinnedRequest(t, "await actions['test.unlisted']('x'); result = {event: 'called'}")
	req.Actions = []string{"test.echo"}
	resp, err := run(t, r, req)
	if err != nil || resp.Reason != wire.ReasonThrew {
		t.Errorf("calling an unlisted action = %+v, %v; want a script that threw", resp, err)
	}

	// Inside it, awaiting gives the value, and a failing action rejects.
	req = pinnedRequest(t, strings.Join([]string{
		"const r = await actions['test.echo'](body.id, 2);",
		"let failed = '';",
		"try { await actions['test.fail']() } catch (e) { failed = e.message }",
		"result = {event: r.action + ':' + r.args.join('/') + ':' + failed}",
	}, " "))
	req.Actions = []string{"test.echo", "test.fail"}
	resp, err = run(t, r, req)
	if err != nil || resp.Result == nil || resp.Result.Event != "test.echo:evt_1/2:downstream refused" {
		t.Errorf("awaiting the actions = %+v, %v", resp.Result, err)
	}
	if strings.Join(calls, ",") != "test.echo" {
		t.Errorf("functions run = %v, want test.echo alone", calls)
	}
}

// TestTheShippedManifestIsEmpty: which effects a webhook may cause is the
// deployment's decision and is paid for in IAM; this build ships none.
func TestTheShippedManifestIsEmpty(t *testing.T) {
	t.Parallel()
	if m := Shipped(); len(m) != 0 {
		t.Errorf("Shipped() has %d actions; each one needs a matching grant on ScriptRunnerRole and a line in docs/inbound-webhooks.md", len(m))
	}
	if _, err := New(Options{Manifest: Shipped()}); err != nil {
		t.Errorf("the shipped manifest does not validate: %v", err)
	}
}

func TestABrokenManifestRefusesTheColdStart(t *testing.T) {
	t.Parallel()
	fn := func(context.Context, []any) (any, error) { return nil, nil }
	for name, m := range map[string]Manifest{
		"empty id":   {{ID: "", IAM: []string{"none"}, Fn: fn}},
		"padded id":  {{ID: " a", IAM: []string{"none"}, Fn: fn}},
		"no fn":      {{ID: "a", IAM: []string{"none"}}},
		"no IAM":     {{ID: "a", Fn: fn}},
		"duplicated": {{ID: "a", IAM: []string{"none"}, Fn: fn}, {ID: "a", IAM: []string{"none"}, Fn: fn}},
	} {
		if _, err := New(Options{Manifest: m}); err == nil {
			t.Errorf("%s: the manifest was accepted", name)
		}
	}
}

// TestTheConsoleIsTheReferencesOwn: three methods, arguments joined with a
// space, silent in production.
func TestTheConsoleIsTheReferencesOwn(t *testing.T) {
	t.Parallel()
	script := "console.log('one', 2, {a: 1}, null); console.warn('w'); console.error('e'); result = {event: 'logged'}"

	loud, logs := newRunner(t, Options{Console: true})
	if resp, err := run(t, loud, pinnedRequest(t, script)); err != nil || resp.Result == nil {
		t.Fatalf("Run: %+v, %v", resp, err)
	}
	for _, want := range []string{`"message":"one 2 [object Object] "`, `"level":"warn"`, `"level":"error"`, `"provider":"contract"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the console did not write %s:\n%s", want, logs.String())
		}
	}

	quiet, quietLogs := newRunner(t, Options{Console: false})
	if resp, err := run(t, quiet, pinnedRequest(t, script)); err != nil || resp.Result == nil {
		t.Fatalf("Run: %+v, %v", resp, err)
	}
	if strings.Contains(quietLogs.String(), "script console") {
		t.Errorf("the console wrote in production:\n%s", quietLogs.String())
	}

	// console.info does not exist there, so it throws here.
	if resp, err := run(t, loud, pinnedRequest(t, "console.info('x')")); err != nil || resp.Reason != wire.ReasonThrew {
		t.Errorf("console.info = %+v, %v; want a script that threw", resp, err)
	}
}

// TestEveryRunIsAFreshRuntime: nothing a script leaves behind reaches the
// next webhook, as vm.createContext per request guarantees there.
func TestEveryRunIsAFreshRuntime(t *testing.T) {
	t.Parallel()
	r, _ := newRunner(t, Options{})
	if _, err := run(t, r, pinnedRequest(t, "globalThis.leak = 'first'; Array.isArray = () => true; JSON.stringify = () => 'x'")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	resp, err := run(t, r, pinnedRequest(t, "result = {event: typeof leak, data: {isArray: Array.isArray({})}}"))
	if err != nil || resp.Result == nil || resp.Result.Event != "undefined" || resp.Result.Data["isArray"] != false {
		t.Errorf("state crossed between runs: %+v, %v", resp.Result, err)
	}

	// And a script that replaces the builtins within its own run does not
	// change how its result is read.
	resp, err = run(t, r, pinnedRequest(t, "Array.isArray = () => true; JSON.stringify = () => 'x'; result = {event: 'e', data: {k: 1}}"))
	if err != nil || resp.Result == nil || resp.Result.Data["k"] == nil {
		t.Errorf("tampered builtins changed the read: %+v, %v", resp.Result, err)
	}
}

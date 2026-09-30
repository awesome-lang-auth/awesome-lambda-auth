// Package scriptrunner is the inbound-webhook script runner's engine: one
// administrator-authored script, evaluated in a fresh goja runtime, with the
// reference's four sandbox variables and nothing else in scope (block D9d).
//
// It is linked into cmd/script-runner and into nothing else. The auth function
// never imports it — cmd/auth's TestTheAuthBinaryLinksNoJavaScriptEngine fails
// the day it does — because the repository owner decided on 2026-09-12 that no
// JavaScript engine enters the process that holds the signing keys, the session
// store and the password hashes. The auth function hands script, body and the
// resolved allowlist across the core's InboundScriptRunner seam; the product's
// invoker puts them on the wire (internal/scriptrunner/wire) to a Lambda of its
// own; this package runs them there. The runner's IAM role is the sandbox. This
// package is not one, and does not pretend to be: what it guarantees is that a
// script has no primitive with which to reach anything, which is a much smaller
// claim, and the role is what bounds the rest.
//
// # Why goja and not node:vm
//
// Two honest options existed: a Node.js Lambda running the script in node:vm
// exactly as the reference does (tools.router.ts:269-292), or a Go binary
// embedding goja. Node is the highest-fidelity sandbox semantics and the
// lowest-fidelity repository — a second language, a second build and a second
// CI step in a Go repository whose artifacts are byte-reproducible from one
// pinned image. goja keeps one toolchain and one build script, and its
// semantic differences are few enough to pin by test:
//
//   - The language a mapping script uses is there: async/await, arrow
//     functions, template literals, object and array spread, destructuring,
//     optional chaining and nullish coalescing, classes with private fields,
//     regular-expression lookbehind (engine_test.go,
//     TestTheLanguageAScriptUsesIsThere).
//   - What a node:vm context holds beyond ECMAScript is exactly what the
//     reference puts in it — body, actions, result, console — and so it is here.
//     A vm context has no require, no process, no fetch, no timers and no
//     Buffer; neither has this. TestTheScriptHasNoPrimitiveToReachAnything pins
//     the absences one by one.
//   - What goja lacks that V8 has: Intl (toLocaleString formats with no
//     locale data), WebAssembly, and SharedArrayBuffer/Atomics. A script
//     written against the reference that formats a date or a currency with
//     Intl throws a ReferenceError here and is reported as a script that threw.
//     docs/inbound-webhooks.md lists this under "Porting a script".
//
// # The run, in the reference's order
//
// A fresh runtime per run, as vm.createContext makes a fresh context per
// request (:284-289): no state crosses from one webhook to the next. The body
// is parsed by the engine's own JSON.parse, so the script sees what
// express.json would have handed the reference — the same numbers, the same
// last-wins answer to a duplicated key. The script is wrapped in the
// reference's exact async IIFE, byte for byte (:269), so a script that works
// there compiles here and one that does not — a trailing line comment that
// swallows the closing `})()` is the classic — fails here the same way. After
// the promise settles, `result` is read whether or not the script threw:
// the reference's `if (sandbox['result'] && typeof …event === 'string')` sits
// after its catch (:293-301), so a script that assigns result and then throws
// still tracks, and so does it here.
//
// # The deadline, which is not the reference's
//
// vm.runInContext's { timeout: 5_000 } bounds only the synchronous prefix of
// an async IIFE; the reference then awaits the rest with no bound at all. Here
// the whole run is bounded — the core's inbound-webhook-script-runs-out-of-process
// — by the earlier of the invoker's deadline (wire.Request.DeadlineUnixMs) and
// this invocation's own Lambda deadline less a margin, and a run that reaches
// it is interrupted and reported as a failure of the run, not of the script:
// the handler returns an error, Lambda sets FunctionError, and the core answers
// the provider 400 so it redelivers. That is the core's contract for a timeout
// (InboundScriptRunner, "(zero, false, err)"), and it is a registered
// difference of this product: a script that loops is refused and redelivered
// here, where the reference's synchronous timeout would have been caught,
// logged and acknowledged (deviation inbound-webhook-scripts-run-on-goja).
package scriptrunner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/dop251/goja"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/scriptrunner/wire"
)

// DefaultMargin is how long before its own Lambda deadline the runner stops a
// script, so that the invocation ends with this package's error rather than
// with the Lambda service killing the process — which would still be a
// FunctionError, but one whose message says "Task timed out" and nothing about
// which webhook it was.
const DefaultMargin = 500 * time.Millisecond

// maxCallStack bounds recursion. goja's default is math.MaxInt32 frames, which
// turns an unbounded recursion into an out-of-memory kill of the whole
// invocation; V8's default stack holds on the order of ten thousand frames and
// raises a RangeError, which the reference catches as a script error. This is
// the same order of magnitude, and a script that exceeds it is reported the
// same way.
const maxCallStack = 10_000

// wrapPrefix and wrapSuffix are the reference's wrapper, exactly:
// `(async () => { ${config.jsScript} })()` (tools.router.ts:269). Nothing is
// added — not even a newline before the suffix — because the reference adds
// none, and a script that behaves differently wrapped here than there is a
// script that was tested against the wrong thing.
const (
	wrapPrefix = "(async () => { "
	wrapSuffix = " })()"
)

// resultReader is compiled into every runtime *before* the script runs, so the
// two builtins it closes over are the originals whatever the script later does
// to the globals. It reads `result` the way the reference's route does
// (:299-301) — truthy, with a string `event` — and returns the four members the
// core's InboundScriptResult carries, encoded by the engine's own
// JSON.stringify so that a number crosses in the engine's own spelling.
//
// data is kept only when it is an object and not an array: the core types it
// map[string]any and its contract says a runner "should send no data rather
// than wrap" anything else. userId and tenantId are kept only when they are
// strings, for the same reason. A data that JSON.stringify cannot encode — a
// cycle, a BigInt — is dropped and said so, rather than failing the run, since
// every redelivery would fail it again.
const resultReader = `(function (isArray, stringify) {
  return function (r) {
    if (!r) { return undefined; }
    var event = r.event;
    if (typeof event !== 'string') { return undefined; }
    var out = { event: event };
    var userId = r.userId, tenantId = r.tenantId, data = r.data;
    if (typeof userId === 'string') { out.userId = userId; }
    if (typeof tenantId === 'string') { out.tenantId = tenantId; }
    if (data !== null && typeof data === 'object' && !isArray(data)) {
      try {
        var encoded = stringify(data);
        if (typeof encoded === 'string') { out.data = encoded; }
      } catch (e) {
        out.dataError = '' + e;
      }
    }
    return stringify(out);
  };
})(Array.isArray, JSON.stringify)`

// Options configures New.
type Options struct {
	// Manifest is the action table. cmd/script-runner passes Shipped().
	Manifest Manifest
	// Console decides whether the script's console.log/warn/error reach the
	// runner's log. The reference writes them to stderr outside production and
	// discards them in it (tools.router.ts:272-282, NODE_ENV); the runner reads
	// the same decision from the deployment environment.
	Console bool
	// Log is the runner's own log: its CloudWatch group, nobody else's. Nil
	// discards.
	Log *slog.Logger
	// Margin is subtracted from the Lambda deadline. Zero is DefaultMargin.
	Margin time.Duration
}

// Runner evaluates inbound-webhook scripts. It holds no per-run state and is
// safe for concurrent use; each Run builds its own runtime.
type Runner struct {
	manifest Manifest
	console  bool
	log      *slog.Logger
	margin   time.Duration
}

// New validates the manifest and returns a runner, or the reason the manifest
// cannot be used.
func New(opts Options) (*Runner, error) {
	if err := opts.Manifest.validate(); err != nil {
		return nil, err
	}
	log := opts.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	margin := opts.Margin
	if margin <= 0 {
		margin = DefaultMargin
	}
	return &Runner{manifest: opts.Manifest, console: opts.Console, log: log, margin: margin}, nil
}

// Run is the Lambda handler: one request in, one response or one error out.
//
// An error is always a failure of the run and never of the script — the
// deadline, a body that is not JSON, an engine error that is not a JavaScript
// exception. A script that threw, or that decided nothing, is a Response with
// OutcomeNone. See the package comment and wire's for why that split is the
// whole contract.
func (r *Runner) Run(ctx context.Context, req wire.Request) (wire.Response, error) {
	started := time.Now()
	deadline := r.deadline(ctx, req, started)
	logger := r.log.With(slog.String("provider", req.Provider), slog.String("webhookId", req.WebhookID))

	if !started.Before(deadline) {
		logger.Error("inbound webhook script not run: no time left before the deadline")
		return wire.Response{}, fmt.Errorf("scriptrunner: %w", errDeadline)
	}

	resp, err := r.run(ctx, req, deadline, logger)
	elapsed := time.Since(started).Milliseconds()
	if err != nil {
		logger.Error("inbound webhook script run failed", slog.String("error", err.Error()), slog.Int64("durationMs", elapsed))
		return wire.Response{}, err
	}
	logger.Info("inbound webhook script ran",
		slog.String("outcome", resp.Outcome), slog.String("reason", resp.Reason), slog.Int64("durationMs", elapsed))
	return resp, nil
}

// deadline is the earlier of the invoker's and this invocation's own, the
// latter less the margin. With neither — a test, a local run — it is the
// core's default script timeout from now.
func (r *Runner) deadline(ctx context.Context, req wire.Request, now time.Time) time.Time {
	deadline := now.Add(auth.DefaultInboundScriptTimeout)
	if d, ok := ctx.Deadline(); ok {
		deadline = d.Add(-r.margin)
	}
	if req.DeadlineUnixMs > 0 {
		if d := time.UnixMilli(req.DeadlineUnixMs); d.Before(deadline) {
			deadline = d
		}
	}
	return deadline
}

func (r *Runner) run(ctx context.Context, req wire.Request, deadline time.Time, logger *slog.Logger) (wire.Response, error) {
	vm := goja.New()
	vm.SetMaxCallStackSize(maxCallStack)

	// The interrupt covers everything the runtime executes from here on —
	// parsing the body, the script, the job queue, and reading `result`,
	// whose getters are the script's own code — and is disarmed under a lock
	// so that a timer firing just as the run ends cannot interrupt nothing,
	// or interrupt a runtime that is being read.
	runCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	var mu sync.Mutex
	finished := false
	stop := context.AfterFunc(runCtx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !finished {
			vm.Interrupt(errDeadline)
		}
	})
	defer func() {
		stop()
		mu.Lock()
		finished = true
		mu.Unlock()
	}()

	reader, err := r.compileReader(vm)
	if err != nil {
		return wire.Response{}, err
	}

	body, err := parseBody(vm, req.Body)
	if err != nil {
		return wire.Response{}, err
	}

	// The reference's four sandbox variables (:284-289), and nothing else of
	// the host's. result starts as null, as it does there.
	for name, value := range map[string]any{
		"body":    body,
		"actions": r.actionsObject(vm, runCtx, req.Actions, logger),
		"result":  goja.Null(),
		"console": r.consoleObject(vm, logger),
	} {
		if err := vm.Set(name, value); err != nil {
			return wire.Response{}, fmt.Errorf("scriptrunner: setting %s: %w", name, err)
		}
	}

	value, err := vm.RunString(wrapPrefix + req.Script + wrapSuffix)
	threw := false
	switch {
	case err == nil:
	case isInterrupt(err):
		return wire.Response{}, fmt.Errorf("scriptrunner: %w", errDeadline)
	case isScriptError(err):
		// Synchronous: a syntax error, or recursion past the stack. The
		// reference's try around runInContext catches both (:302-305).
		threw = true
		logger.Warn("inbound webhook script threw", slog.String("error", err.Error()))
	default:
		return wire.Response{}, fmt.Errorf("scriptrunner: the engine failed: %w", err)
	}

	if !threw {
		promise, ok := value.Export().(*goja.Promise)
		if !ok {
			// Unreachable for the wrapper above, which always yields a
			// promise; kept as a refusal rather than a guess.
			return wire.Response{}, errors.New("scriptrunner: the wrapped script did not yield a promise")
		}
		switch promise.State() {
		case goja.PromiseStateRejected:
			// The .catch the reference attaches before awaiting (:293-300).
			threw = true
			logger.Warn("inbound webhook script threw", slog.String("error", describe(promise.Result())))
		case goja.PromiseStatePending:
			// RunString has drained the job queue, there are no timers and
			// every action settles before it returns, so nothing can ever
			// settle this. The reference would hang the request; a
			// redelivery would hang the same way. The script's own failure.
			logger.Warn("inbound webhook script never settled: it awaits a promise nothing in the sandbox can resolve")
			return wire.Response{Outcome: wire.OutcomeNone, Reason: wire.ReasonNeverSettled}, nil
		}
	}

	result, err := r.readResult(vm, reader, logger)
	if err != nil {
		return wire.Response{}, err
	}
	if result != nil {
		return wire.Response{Outcome: wire.OutcomeResult, Result: result}, nil
	}
	if threw {
		return wire.Response{Outcome: wire.OutcomeNone, Reason: wire.ReasonThrew}, nil
	}
	return wire.Response{Outcome: wire.OutcomeNone, Reason: wire.ReasonNoResult}, nil
}

func (r *Runner) compileReader(vm *goja.Runtime) (goja.Callable, error) {
	v, err := vm.RunString(resultReader)
	if err != nil {
		return nil, fmt.Errorf("scriptrunner: compiling the result reader: %w", err)
	}
	fn, ok := goja.AssertFunction(v)
	if !ok {
		return nil, errors.New("scriptrunner: the result reader is not a function")
	}
	return fn, nil
}

// parseBody hands the body to the engine's own JSON.parse, looked up before
// the script exists. The core has already checked it is a JSON object or array
// (toolsInboundBody); a body that still fails here is a malformed request, the
// runner's failure and not the script's.
func parseBody(vm *goja.Runtime, body json.RawMessage) (goja.Value, error) {
	text := strings.TrimSpace(string(body))
	if text == "" {
		// express.json()'s empty body, which the core already turns into {}.
		text = "{}"
	}
	parse, ok := goja.AssertFunction(vm.Get("JSON").ToObject(vm).Get("parse"))
	if !ok {
		return nil, errors.New("scriptrunner: JSON.parse is not a function")
	}
	v, err := parse(goja.Undefined(), vm.ToValue(text))
	if err != nil {
		return nil, fmt.Errorf("scriptrunner: the request body is not JSON: %w", err)
	}
	return v, nil
}

// actionsObject is the sandbox's `actions`: exactly the manifest entries the
// resolved list exposes (Manifest.expose), each a function returning a settled
// promise.
func (r *Runner) actionsObject(vm *goja.Runtime, ctx context.Context, allowed []string, logger *slog.Logger) *goja.Object {
	obj := vm.NewObject()
	for _, action := range r.manifest.expose(allowed) {
		action := action
		_ = obj.Set(action.ID, func(call goja.FunctionCall) goja.Value {
			args := make([]any, len(call.Arguments))
			for i, a := range call.Arguments {
				args[i] = a.Export()
			}
			promise, resolve, reject := vm.NewPromise()
			value, err := action.Fn(ctx, args)
			if err != nil {
				logger.Warn("inbound webhook action failed", slog.String("action", action.ID), slog.String("error", err.Error()))
				_ = reject(vm.NewGoError(err))
			} else {
				_ = resolve(vm.ToValue(value))
			}
			return vm.ToValue(promise)
		})
	}
	return obj
}

// consoleObject is the reference's sandboxConsole (:272-282): log, warn and
// error, the arguments joined with a space as args.join(' ') joins them, and
// no-ops when the deployment is production. Only those three, because a script
// calling console.info throws a TypeError there and should throw one here.
func (r *Runner) consoleObject(vm *goja.Runtime, logger *slog.Logger) *goja.Object {
	obj := vm.NewObject()
	for _, level := range []string{"log", "warn", "error"} {
		level := level
		_ = obj.Set(level, func(call goja.FunctionCall) goja.Value {
			if !r.console {
				return goja.Undefined()
			}
			parts := make([]string, len(call.Arguments))
			for i, a := range call.Arguments {
				if a == nil || goja.IsUndefined(a) || goja.IsNull(a) {
					continue
				}
				parts[i] = a.String()
			}
			logger.Info("inbound webhook script console", slog.String("level", level), slog.String("message", strings.Join(parts, " ")))
			return goja.Undefined()
		})
	}
	return obj
}

// readResult runs the reader over the global `result`. A getter of the
// script's that throws while being read is the script's failure, and is
// reported as no result; an interrupt is the run's.
func (r *Runner) readResult(vm *goja.Runtime, reader goja.Callable, logger *slog.Logger) (*auth.InboundScriptResult, error) {
	encoded, err := reader(goja.Undefined(), vm.Get("result"))
	switch {
	case err == nil:
	case isInterrupt(err):
		return nil, fmt.Errorf("scriptrunner: %w", errDeadline)
	case isScriptError(err):
		logger.Warn("reading the script's result threw", slog.String("error", err.Error()))
		return nil, nil
	default:
		return nil, fmt.Errorf("scriptrunner: reading the result: %w", err)
	}
	if goja.IsUndefined(encoded) {
		return nil, nil
	}
	var read struct {
		Event     string  `json:"event"`
		UserID    string  `json:"userId"`
		TenantID  string  `json:"tenantId"`
		Data      *string `json:"data"`
		DataError string  `json:"dataError"`
	}
	if err := json.Unmarshal([]byte(encoded.String()), &read); err != nil {
		// Only reachable by a script that replaced a prototype's toJSON, which
		// the reader's own stringify then honours. Its own doing, so its own
		// failure.
		logger.Warn("the script's result could not be read", slog.String("error", err.Error()))
		return nil, nil
	}
	result := &auth.InboundScriptResult{Event: read.Event, UserID: read.UserID, TenantID: read.TenantID}
	if read.DataError != "" {
		logger.Warn("the script's result.data is not JSON-encodable and was dropped", slog.String("error", read.DataError))
	}
	if read.Data != nil {
		dec := json.NewDecoder(strings.NewReader(*read.Data))
		// json.Number keeps the engine's own spelling of every number on the
		// wire, rather than a round trip through float64 formatting.
		dec.UseNumber()
		var data map[string]any
		if err := dec.Decode(&data); err == nil {
			result.Data = data
		} else {
			// A toJSON that turned the object into something else.
			logger.Warn("the script's result.data did not encode to an object and was dropped")
		}
	}
	return result, nil
}

func isInterrupt(err error) bool {
	var interrupted *goja.InterruptedError
	return errors.As(err, &interrupted)
}

// isScriptError is every error that is the script's own doing: a JavaScript
// exception, a syntax error, or recursion past the stack bound.
func isScriptError(err error) bool {
	var exception *goja.Exception
	var syntax *goja.CompilerSyntaxError
	var overflow *goja.StackOverflowError
	return errors.As(err, &exception) || errors.As(err, &syntax) || errors.As(err, &overflow)
}

// describe renders a rejection reason for the log: an Error's stack when it
// has one, its string form otherwise. The value is the script's, so a getter or
// a toString of its own may throw while being read — outside a JavaScript
// call, where goja surfaces that as a panic — and a log line is not worth
// failing the run for.
func describe(v goja.Value) (s string) {
	defer func() {
		if recover() != nil {
			s = "(a rejection reason that could not be rendered)"
		}
	}()
	if v == nil || goja.IsUndefined(v) {
		return "undefined"
	}
	if obj, ok := v.(*goja.Object); ok {
		if stack := obj.Get("stack"); stack != nil && !goja.IsUndefined(stack) {
			return stack.String()
		}
	}
	return v.String()
}

// Package wire is the one thing the auth function and the script runner share:
// the bytes that cross between them when an inbound webhook's script runs
// (block D9d).
//
// It is a package of its own, and deliberately a package with no dependency
// beyond the standard library and the core's two request and result types, for
// the reason the whole block exists. The owner's decision of 2026-09-12 is that
// no JavaScript engine enters the auth function: the core resolves the action
// allowlist and hands script, body and list across InboundScriptRunner, and the
// product implements the seam by invoking a dedicated Lambda whose IAM role is
// the sandbox. The invoker (internal/integration/aws, LambdaScriptRunner) lives
// in the auth binary and the engine (internal/scriptrunner) lives in the runner
// binary, and if these types sat beside the engine the invoker's import would
// link the engine into the auth artifact — the one outcome the decision
// forbids. cmd/auth's TestTheAuthBinaryLinksNoJavaScriptEngine pins that.
//
// # What crosses, and in which direction
//
// Into the runner: Request, which is the core's auth.InboundScriptRequest
// verbatim — provider, webhook id, the script unwrapped, the raw body, the
// resolved allowlist, under the JSON names the core declares part of its
// contract (tools_webhook.go, InboundScriptRequest) — plus one member of this
// product's own, the deadline. Out of the runner: Response, an outcome and, for
// one of the two outcomes, the core's auth.InboundScriptResult.
//
// There are two outcomes and not three, although the core's seam has three
// answers. The third — "the script could not be run to completion" — is not a
// payload at all: the runner reports it by failing the invocation, so the
// Lambda service sets FunctionError on the response and the invoker maps that
// to the core's (zero, false, err). That keeps the one answer that makes a
// provider redeliver on the one channel a runner cannot fake by accident: a
// handler that returned a value has, by construction, not failed.
//
// testdata/ holds the bytes, and both sides are pinned to them: this package's
// test that the types encode to exactly those bytes, the runner's test that a
// script's run encodes to them, the invoker's test that they decode to the
// core's answers. A change to either side that the other does not share fails
// on the side that made it.
package wire

import (
	"encoding/json"
	"errors"
	"fmt"

	auth "github.com/nik2208/awesome-go-auth"
)

// Request is the invocation payload: the core's request, embedded so that its
// members are promoted to the top level of the JSON object under the core's
// own names, and the deadline.
//
// Embedding rather than copying the five fields is the point. The core's JSON
// names are "part of the contract rather than an implementation detail"
// (tools_webhook.go), and a copy is a second spelling of them that can drift.
type Request struct {
	auth.InboundScriptRequest

	// DeadlineUnixMs is the instant, in milliseconds since the epoch, after
	// which the invoker has stopped waiting: the deadline the core put on the
	// call (ToolsOptions.ScriptTimeout, from tools.inboundWebhooks.scriptTimeoutMs)
	// minus the invoker's margin for the response to travel back.
	//
	// It is absolute rather than a duration because the runner's own cold
	// start happens between the two clocks: a relative budget measured by the
	// invoker and started by the runner would be spent twice by an invocation
	// that paid an init. Two Lambda execution environments share the Amazon
	// Time Sync clock, so the skew an absolute instant is exposed to is
	// milliseconds, and it errs safe either way — early, the run is refused and
	// the provider redelivers; late, the invoker has already refused it.
	//
	// Zero means "no deadline was sent", and the runner then stops at its own
	// Lambda deadline alone. The invoker always sends one.
	DeadlineUnixMs int64 `json:"deadlineUnixMs,omitempty"`
}

// The two outcomes a runner may answer with. See the package comment for why
// the third answer of the core's seam is not among them.
const (
	// OutcomeResult is the core's (result, true, nil): the script left a
	// `result` whose `event` is a string, exactly the reference's test
	// (tools.router.ts:299).
	OutcomeResult = "result"
	// OutcomeNone is the core's (zero, false, nil): the script ran and declared
	// nothing. Reason says which of the silent cases it was.
	OutcomeNone = "none"
)

// The reasons an OutcomeNone carries. They are for the operator reading a log
// line, not for the core, which treats every one of them alike — the route
// acknowledges and falls through to OnWebhook, as the reference does after its
// catch (tools.router.ts:293-306).
const (
	// ReasonNoResult: the script finished and `result` was null, not an
	// object, or had no string `event`.
	ReasonNoResult = "no-result"
	// ReasonThrew: the script threw — synchronously, a syntax error included,
	// or by rejecting its promise. The reference logs and acknowledges
	// (:293-304); so does the core, and so a runner must answer this and never
	// an error, or every broken script becomes an infinite redelivery loop.
	ReasonThrew = "threw"
	// ReasonNeverSettled: the script's promise was still pending when the
	// engine's job queue ran dry. With no timers in the sandbox and every
	// action settled before it returns (internal/scriptrunner, Action), nothing
	// is left that could ever settle it, so waiting for the deadline would buy
	// a bill and no result. The reference hangs the request instead; a
	// redelivery would hang the same way, which is why this is the script's own
	// failure and not the runner's.
	ReasonNeverSettled = "never-settled"
)

// Response is what the runner's handler returns and the invoker decodes.
type Response struct {
	// Outcome is OutcomeResult or OutcomeNone.
	Outcome string `json:"outcome"`
	// Result is present exactly when Outcome is OutcomeResult. It is the core's
	// own type, so its JSON names — event, data, userId, tenantId — are the
	// core's.
	Result *auth.InboundScriptResult `json:"result,omitempty"`
	// Reason is present exactly when Outcome is OutcomeNone.
	Reason string `json:"reason,omitempty"`
}

// Answer maps a Response onto the core's three-valued return, and is the one
// place that mapping is written. The invoker calls it on what it decoded; the
// runner's own tests call it on what they produced, so the two cannot mean
// different things by the same bytes.
//
// A Response that is neither of the two shapes above is an error, never a
// silent "no result": a runner that answered something this build does not
// understand has not told the core that the script declared nothing, and
// acknowledging on its behalf would drop a webhook the provider will not send
// again.
func (r Response) Answer() (auth.InboundScriptResult, bool, error) {
	switch r.Outcome {
	case OutcomeResult:
		if r.Result == nil {
			return auth.InboundScriptResult{}, false, errors.New("script runner: outcome is result but no result was sent")
		}
		return *r.Result, true, nil
	case OutcomeNone:
		return auth.InboundScriptResult{}, false, nil
	default:
		return auth.InboundScriptResult{}, false, fmt.Errorf("script runner: unknown outcome %q", r.Outcome)
	}
}

// Decode reads a Response out of an invocation payload. Unknown members are
// tolerated — a newer runner may say more — and an unknown outcome is not
// (Answer).
func Decode(payload []byte) (Response, error) {
	var r Response
	if err := json.Unmarshal(payload, &r); err != nil {
		return Response{}, fmt.Errorf("script runner: the response is not the runner's JSON: %w", err)
	}
	return r, nil
}

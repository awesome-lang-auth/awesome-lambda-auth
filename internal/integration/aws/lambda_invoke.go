package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/scriptrunner/wire"
)

// The inbound-webhook script runner, as the auth function sees it: one
// synchronous Invoke of another function (block D9d).
//
// The core runs no inbound-webhook script in process and hands script, body and
// the resolved action allowlist across InboundScriptRunner
// (tools_webhook.go). This is the product's implementation of that seam, and
// it is deliberately nothing but transport. It puts the core's request on the
// wire (internal/scriptrunner/wire), invokes the runner function
// (cmd/script-runner) with InvocationType RequestResponse, and maps what comes
// back onto the core's three answers. It evaluates nothing — this package, and
// therefore the auth binary, links no JavaScript engine, and cmd/auth's
// TestTheAuthBinaryLinksNoJavaScriptEngine fails the day it does.
//
// # The mapping, which is the load-bearing part
//
//   - The invocation succeeded and the runner answered OutcomeResult → the
//     core's (result, true, nil): the route tracks it.
//   - The invocation succeeded and the runner answered OutcomeNone — the
//     script decided nothing, or threw → (zero, false, nil): the route
//     acknowledges, as the reference does after its catch.
//   - Anything else → (zero, false, err): the route answers 400 and the
//     provider redelivers. That is the Invoke call failing (the function
//     missing, the role lacking lambda:InvokeFunction, a throttle, the network),
//     the deadline passing, a status other than 200, FunctionError set — which
//     is how the runner reports a run it could not complete, and how the Lambda
//     service reports a runner that crashed or timed out — or a payload this
//     build cannot read.
//
// The core's contract names the one mistake that matters: "reporting a script
// exception as an error turns every bad script into an infinite redelivery
// loop; reporting an invocation failure as 'no result' silently drops
// webhooks". FunctionError is therefore never read as "no result", whatever
// the payload says, and a well-formed OutcomeNone is never read as a failure.
//
// # No SDK retries
//
// The SDK's standard retryer would retry Invoke on a throttle, a 5xx or a
// dropped connection. For this call a retry is a second run of a script that
// may already have applied its actions — a duplicate the provider did not
// cause and cannot see. The provider's own redelivery is the retry mechanism
// for this route, it is what the core's refusal exists to preserve, and it is
// the one a script's idempotence is written against (docs/inbound-webhooks.md).
// So every Invoke is made with RetryMaxAttempts 1.

// LambdaAPI is the single Lambda call the invoker makes. Declared here so a
// test injects a fake, as SNSAPI and SESAPI are.
type LambdaAPI interface {
	Invoke(ctx context.Context, in *lambda.InvokeInput, optFns ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
}

// LambdaScriptRunnerOptions configures NewLambdaScriptRunner.
type LambdaScriptRunnerOptions struct {
	// FunctionName is the runner: a name, a full or partial ARN, optionally
	// qualified — whatever Invoke's FunctionName accepts. It is
	// tools.inboundWebhooks.scriptRunnerFunction, which the SAM template sets to
	// its own ScriptRunnerFunction.
	FunctionName string

	// Region overrides the region the default chain resolves. Empty uses
	// AWS_REGION, which is the runner's region on this stack.
	Region string

	// Client injects a LambdaAPI. Non-nil skips the lazy build.
	Client LambdaAPI

	// ResponseMargin is how much of the core's deadline is kept back for the
	// runner's answer to travel home: the runner is told to stop that much
	// earlier than the invoker stops waiting. Zero is DefaultResponseMargin.
	ResponseMargin time.Duration
}

// DefaultResponseMargin is ResponseMargin's default. A synchronous Invoke's
// response leg is tens of milliseconds within a region; a quarter of a second
// keeps a script that runs to the very end of its budget answerable, out of the
// five seconds the reference's number gives it.
const DefaultResponseMargin = 250 * time.Millisecond

// LambdaScriptRunner implements auth.InboundScriptRunner by invoking a
// function.
type LambdaScriptRunner struct {
	function string
	margin   time.Duration
	client   *lazyClient[LambdaAPI]
}

var _ auth.InboundScriptRunner = (*LambdaScriptRunner)(nil)

// NewLambdaScriptRunner builds the invoker. It performs no I/O; the client is
// built on the first webhook (lazyClient), because a deployment whose provider
// sends nothing for a week should not pay for a Lambda client at every cold
// start.
func NewLambdaScriptRunner(opts LambdaScriptRunnerOptions) (*LambdaScriptRunner, error) {
	function := strings.TrimSpace(opts.FunctionName)
	if function == "" {
		return nil, errors.New("lambda: the script runner needs a function name")
	}
	margin := opts.ResponseMargin
	if margin <= 0 {
		margin = DefaultResponseMargin
	}
	r := &LambdaScriptRunner{function: function, margin: margin}
	if opts.Client != nil {
		client := opts.Client
		r.client = &lazyClient[LambdaAPI]{build: func(context.Context) (LambdaAPI, error) { return client, nil }}
		return r, nil
	}
	shared := &lazyConfig{region: opts.Region}
	r.client = &lazyClient[LambdaAPI]{build: func(ctx context.Context) (LambdaAPI, error) {
		cfg, err := shared.get(ctx)
		if err != nil {
			return nil, err
		}
		return lambda.NewFromConfig(cfg), nil
	}}
	return r, nil
}

// FunctionName is the function this invoker calls, for the cold-start log.
func (r *LambdaScriptRunner) FunctionName() string { return r.function }

// RunInboundScript implements auth.InboundScriptRunner.
//
// ctx carries the core's deadline (ToolsOptions.ScriptTimeout); it bounds the
// Invoke call as the SDK's own timeout, and the same instant less the response
// margin travels to the runner as the point at which it must stop the script.
// With no deadline on ctx — never the case from the core's route — the core's
// own default is applied here, so no call to another function is unbounded.
func (r *LambdaScriptRunner) RunInboundScript(ctx context.Context, req auth.InboundScriptRequest) (auth.InboundScriptResult, bool, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, auth.DefaultInboundScriptTimeout)
		defer cancel()
	}
	deadline, _ := ctx.Deadline()
	runnerDeadline := deadline.Add(-r.margin)
	if !time.Now().Before(runnerDeadline) {
		return auth.InboundScriptResult{}, false, fmt.Errorf("lambda: script runner %s not invoked: the deadline leaves no time to run the script", r.function)
	}

	payload, err := json.Marshal(wire.Request{InboundScriptRequest: req, DeadlineUnixMs: runnerDeadline.UnixMilli()})
	if err != nil {
		return auth.InboundScriptResult{}, false, fmt.Errorf("lambda: encoding the script request: %w", err)
	}

	api, err := r.client.get(ctx)
	if err != nil {
		return auth.InboundScriptResult{}, false, fmt.Errorf("lambda: cannot build a client: %w", err)
	}
	out, err := api.Invoke(ctx, &lambda.InvokeInput{
		FunctionName:   awssdk.String(r.function),
		InvocationType: lambdatypes.InvocationTypeRequestResponse,
		LogType:        lambdatypes.LogTypeNone,
		Payload:        payload,
	}, func(o *lambda.Options) { o.RetryMaxAttempts = 1 })
	if err != nil {
		return auth.InboundScriptResult{}, false, fmt.Errorf("lambda: invoking script runner %s: %w", r.function, err)
	}
	if out.StatusCode != 200 {
		return auth.InboundScriptResult{}, false, fmt.Errorf("lambda: script runner %s answered status %d", r.function, out.StatusCode)
	}
	if out.FunctionError != nil {
		return auth.InboundScriptResult{}, false, fmt.Errorf("lambda: script runner %s failed the run (%s): %s",
			r.function, awssdk.ToString(out.FunctionError), functionErrorMessage(out.Payload))
	}
	resp, err := wire.Decode(out.Payload)
	if err != nil {
		return auth.InboundScriptResult{}, false, fmt.Errorf("lambda: script runner %s: %w", r.function, err)
	}
	return resp.Answer()
}

// functionErrorMessage reads the Lambda runtime's error envelope,
// {"errorMessage": "...", "errorType": "..."}, into one bounded line. The
// message is the runner's own (internal/scriptrunner), or the Lambda service's
// for a crash or a timeout; it never carries the body, and it is cut anyway,
// because a log line is not where a payload belongs.
func functionErrorMessage(payload []byte) string {
	var envelope struct {
		ErrorMessage string `json:"errorMessage"`
		ErrorType    string `json:"errorType"`
	}
	msg := strings.TrimSpace(string(payload))
	if json.Unmarshal(payload, &envelope) == nil && envelope.ErrorMessage != "" {
		msg = envelope.ErrorMessage
		if envelope.ErrorType != "" {
			msg = envelope.ErrorType + ": " + msg
		}
	}
	const limit = 300
	if len(msg) > limit {
		msg = msg[:limit] + "…"
	}
	if msg == "" {
		msg = "no error message"
	}
	return msg
}

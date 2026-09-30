package aws

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
	lambdatypes "github.com/aws/aws-sdk-go-v2/service/lambda/types"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/scriptrunner/wire"
)

// The invoker's half of the byte-level pin: the payloads below are the files
// the runner's own tests produce (internal/scriptrunner/wire/testdata).
func runnerFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "scriptrunner", "wire", "testdata", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return bytes.TrimSpace(raw)
}

type fakeLambda struct {
	mu       sync.Mutex
	out      *lambda.InvokeOutput
	err      error
	inputs   []*lambda.InvokeInput
	options  []lambda.Options
	deadline []time.Time
}

func (f *fakeLambda) Invoke(ctx context.Context, in *lambda.InvokeInput, optFns ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var o lambda.Options
	o.RetryMaxAttempts = 3 // what the standard retryer would do
	for _, fn := range optFns {
		fn(&o)
	}
	d, _ := ctx.Deadline()
	f.inputs, f.options, f.deadline = append(f.inputs, in), append(f.options, o), append(f.deadline, d)
	return f.out, f.err
}

func sampleScriptRequest() auth.InboundScriptRequest {
	return auth.InboundScriptRequest{
		Provider:  "contract",
		WebhookID: "wh_1",
		Script:    "result = {event: 'identity.tenant.user.removed', data: body}",
		Body:      json.RawMessage(`{"id":"evt_1"}`),
		Actions:   []string{"user.suspend"},
	}
}

func newTestInvoker(t *testing.T, fake *fakeLambda) *LambdaScriptRunner {
	t.Helper()
	r, err := NewLambdaScriptRunner(LambdaScriptRunnerOptions{FunctionName: "stack-script-runner", Client: fake})
	if err != nil {
		t.Fatalf("NewLambdaScriptRunner: %v", err)
	}
	return r
}

func invokeWithin(t *testing.T, r *LambdaScriptRunner, d time.Duration) (auth.InboundScriptResult, bool, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	return r.RunInboundScript(ctx, sampleScriptRequest())
}

// TestTheInvokerMapsEveryAnswer is every branch of the mapping the core's
// contract names.
func TestTheInvokerMapsEveryAnswer(t *testing.T) {
	t.Parallel()
	ok := func(payload []byte) *lambda.InvokeOutput {
		return &lambda.InvokeOutput{StatusCode: 200, Payload: payload}
	}
	functionError := func(kind string, payload string) *lambda.InvokeOutput {
		return &lambda.InvokeOutput{StatusCode: 200, FunctionError: awssdk.String(kind), Payload: []byte(payload)}
	}
	for _, tc := range []struct {
		name    string
		out     *lambda.InvokeOutput
		err     error
		emit    bool
		wantErr string
	}{
		{name: "a result", out: ok(runnerFixture(t, "response-result.json")), emit: true},
		{name: "no result", out: ok(runnerFixture(t, "response-none.json"))},
		{name: "a script that threw is no result, not an error", out: ok(runnerFixture(t, "response-threw.json"))},
		{name: "a promise nothing could settle", out: ok(runnerFixture(t, "response-never-settled.json"))},
		{
			name:    "the runner failed the run",
			out:     functionError("Unhandled", `{"errorMessage":"scriptrunner: the script ran past its deadline and was interrupted","errorType":"wrapError"}`),
			wantErr: "past its deadline",
		},
		{
			// FunctionError wins over whatever the payload says: a failed
			// invocation is never read as "the script decided nothing".
			name:    "a function error whose payload looks like no result",
			out:     functionError("Unhandled", string(runnerFixture(t, "response-none.json"))),
			wantErr: "failed the run",
		},
		{
			name:    "the Lambda service killed the runner",
			out:     functionError("Unhandled", `{"errorMessage":"2026-09-30T00:00:00Z Task timed out after 6.00 seconds"}`),
			wantErr: "Task timed out",
		},
		{name: "the invocation itself failed", err: errors.New("AccessDeniedException: not authorized to perform lambda:InvokeFunction"), wantErr: "AccessDenied"},
		{name: "a status other than 200", out: &lambda.InvokeOutput{StatusCode: 202}, wantErr: "status 202"},
		{name: "a payload that is not the runner's", out: ok([]byte(`<html>`)), wantErr: "not the runner's JSON"},
		{name: "an outcome this build does not know", out: ok([]byte(`{"outcome":"later"}`)), wantErr: "unknown outcome"},
		{name: "a result outcome with no result", out: ok([]byte(`{"outcome":"result"}`)), wantErr: "no result was sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeLambda{out: tc.out, err: tc.err}
			result, emit, err := invokeWithin(t, newTestInvoker(t, fake), 5*time.Second)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one containing %q", err, tc.wantErr)
				}
				if emit || !reflect.DeepEqual(result, auth.InboundScriptResult{}) {
					t.Errorf("a failure carried a result: %+v, %v", result, emit)
				}
				return
			}
			if err != nil {
				t.Fatalf("err = %v", err)
			}
			if emit != tc.emit {
				t.Fatalf("emit = %v, want %v", emit, tc.emit)
			}
			if emit && (result.Event != "identity.tenant.user.removed" || result.UserID != "u_1" || result.TenantID != "t_1" || result.Data["id"] != "evt_1") {
				t.Errorf("result = %+v", result)
			}
			if !emit && !reflect.DeepEqual(result, auth.InboundScriptResult{}) {
				t.Errorf("no result carried %+v", result)
			}
		})
	}
}

// TestTheInvokerSendsTheCoresRequestSynchronouslyWithItsDeadline: the payload
// is the core's request verbatim plus the deadline less the response margin;
// the call is RequestResponse, bounded by ctx, and never retried by the SDK.
func TestTheInvokerSendsTheCoresRequestSynchronouslyWithItsDeadline(t *testing.T) {
	t.Parallel()
	fake := &fakeLambda{out: &lambda.InvokeOutput{StatusCode: 200, Payload: runnerFixture(t, "response-none.json")}}
	r := newTestInvoker(t, fake)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	coreDeadline, _ := ctx.Deadline()
	if _, _, err := r.RunInboundScript(ctx, sampleScriptRequest()); err != nil {
		t.Fatalf("RunInboundScript: %v", err)
	}
	if len(fake.inputs) != 1 {
		t.Fatalf("Invoke called %d times, want once", len(fake.inputs))
	}
	in := fake.inputs[0]
	if awssdk.ToString(in.FunctionName) != "stack-script-runner" {
		t.Errorf("FunctionName = %q", awssdk.ToString(in.FunctionName))
	}
	if in.InvocationType != lambdatypes.InvocationTypeRequestResponse {
		t.Errorf("InvocationType = %q, want RequestResponse: the core waits for the answer", in.InvocationType)
	}
	if fake.options[0].RetryMaxAttempts != 1 {
		t.Errorf("RetryMaxAttempts = %d, want 1: an SDK retry is a second run the provider did not ask for", fake.options[0].RetryMaxAttempts)
	}
	if !fake.deadline[0].Equal(coreDeadline) {
		t.Errorf("Invoke's ctx deadline = %v, want the core's %v", fake.deadline[0], coreDeadline)
	}

	var sent wire.Request
	if err := json.Unmarshal(in.Payload, &sent); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !reflect.DeepEqual(sent.InboundScriptRequest, sampleScriptRequest()) {
		t.Errorf("sent %+v, want the core's request verbatim", sent.InboundScriptRequest)
	}
	if want := coreDeadline.Add(-DefaultResponseMargin).UnixMilli(); sent.DeadlineUnixMs != want {
		t.Errorf("deadlineUnixMs = %d, want the core's deadline less the margin, %d", sent.DeadlineUnixMs, want)
	}
	// And the members are the core's own names at the top level.
	var top map[string]json.RawMessage
	_ = json.Unmarshal(in.Payload, &top)
	for _, k := range []string{"provider", "webhookId", "script", "body", "actions", "deadlineUnixMs"} {
		if _, ok := top[k]; !ok {
			t.Errorf("payload lacks %q: %s", k, in.Payload)
		}
	}
}

// TestTheInvokerNeverRunsUnbounded: a deadline too close to run anything is
// refused without an invocation, and a context with none gets the core's
// default.
func TestTheInvokerNeverRunsUnbounded(t *testing.T) {
	t.Parallel()
	fake := &fakeLambda{out: &lambda.InvokeOutput{StatusCode: 200, Payload: runnerFixture(t, "response-none.json")}}
	r := newTestInvoker(t, fake)

	if _, _, err := invokeWithin(t, r, DefaultResponseMargin/2); err == nil {
		t.Error("a deadline inside the response margin was invoked")
	}
	if len(fake.inputs) != 0 {
		t.Errorf("Invoke was called %d times with no time to run", len(fake.inputs))
	}

	before := time.Now()
	if _, _, err := r.RunInboundScript(context.Background(), sampleScriptRequest()); err != nil {
		t.Fatalf("RunInboundScript: %v", err)
	}
	if len(fake.deadline) != 1 || fake.deadline[0].IsZero() {
		t.Fatal("an unbounded context reached Invoke unbounded")
	}
	if got := fake.deadline[0].Sub(before); got > auth.DefaultInboundScriptTimeout+time.Second || got < auth.DefaultInboundScriptTimeout-time.Second {
		t.Errorf("the default bound was %v, want the core's %v", got, auth.DefaultInboundScriptTimeout)
	}
}

func TestTheInvokerNeedsAFunction(t *testing.T) {
	t.Parallel()
	if _, err := NewLambdaScriptRunner(LambdaScriptRunnerOptions{FunctionName: "  "}); err == nil {
		t.Error("an invoker with no function was built")
	}
}

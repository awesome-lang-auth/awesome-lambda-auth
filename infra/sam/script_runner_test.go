package sam

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// iamAction matches a line naming one IAM action: `Action: svc:Name` or
// `- svc:Name`, wildcards included so that a `logs:*` is seen and refused.
var iamAction = regexp.MustCompile(`^(?:Action:\s*|-\s+)([a-z0-9-]+:[A-Za-z*]+)$`)

// D9d: the inbound-webhook script runner's resources. The claim the whole
// block rests on is that the runner's IAM role is the sandbox, so the role is
// asserted statement by statement, and the one relationship CloudFormation
// cannot compute — a function timeout in seconds against a deadline in
// milliseconds — is asserted on the defaults, as X4a asserted the auth
// function's duration alarm against its timeout.

// TestTheScriptRunnerRoleIsTheSandbox: the role grants writing its own log
// group and nothing else, the function uses that role and no other, has no
// trigger, and every resource of the block follows the runner's switch.
func TestTheScriptRunnerRoleIsTheSandbox(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	for _, name := range []string{"ScriptRunnerLogGroup", "ScriptRunnerRole", "ScriptRunnerFunction"} {
		r, ok := tpl.resources[name]
		if !ok {
			t.Fatalf("%s is gone", name)
		}
		if r.condition != "InboundWebhooksEnabled" {
			t.Errorf("%s has Condition %q, want InboundWebhooksEnabled: with the runner off the stack must carry none of it", name, r.condition)
		}
	}
	if got := tpl.conditions["InboundWebhooksEnabled"]; !strings.Contains(got, "!Condition ToolsEnabled") || !strings.Contains(got, "!Ref EnableInboundWebhooks") {
		t.Errorf("InboundWebhooksEnabled = %q, want the tools block and the runner's own switch", got)
	}
	if d := literal(tpl.parameters["EnableInboundWebhooks"].fields["Default"]); d != "false" {
		t.Errorf("EnableInboundWebhooks defaults to %q; an empty parameter set must add no function and no cost", d)
	}

	role := tpl.resources["ScriptRunnerRole"]
	if role.typ != "AWS::IAM::Role" {
		t.Fatalf("ScriptRunnerRole is a %s", role.typ)
	}
	// Exactly two actions, on exactly the group's ARN.
	// Every IAM action the role's body names, inline (`Action: x:Y`) or as a
	// list item (`- x:Y`), in order.
	var actions []string
	for _, line := range strings.Split(role.body, "\n") {
		if m := iamAction.FindStringSubmatch(strings.TrimSpace(line)); m != nil {
			actions = append(actions, m[1])
		}
	}
	want := []string{"sts:AssumeRole", "logs:CreateLogStream", "logs:PutLogEvents"}
	if strings.Join(actions, ",") != strings.Join(want, ",") {
		t.Errorf("ScriptRunnerRole's actions = %v, want exactly %v: the role is the sandbox, and anything more is "+
			"something every script can reach through an action", actions, want)
	}
	for _, forbidden := range []string{"ManagedPolicyArns", "Resource: '*'", `Resource: "*"`, "logs:CreateLogGroup", "PermissionsBoundary: ''"} {
		if strings.Contains(role.body, forbidden) {
			t.Errorf("ScriptRunnerRole carries %q", forbidden)
		}
	}
	if !strings.Contains(role.body, "Resource: !GetAtt ScriptRunnerLogGroup.Arn") {
		t.Error("ScriptRunnerRole's log grant is not scoped to ScriptRunnerLogGroup")
	}
	if !strings.Contains(role.body, "Service: lambda.amazonaws.com") {
		t.Error("ScriptRunnerRole is not assumable by Lambda alone")
	}

	fn := tpl.resources["ScriptRunnerFunction"]
	for prop, want := range map[string]string{
		"Role":          "!GetAtt ScriptRunnerRole.Arn",
		"CodeUri":       "../../dist/script-runner-lambda.zip",
		"Handler":       "bootstrap",
		"Runtime":       "provided.al2023",
		"Architectures": "[arm64]",
		"MemorySize":    "256",
		"Timeout":       "!Ref ScriptRunnerTimeout",
	} {
		if got := fn.props[prop]; got != want {
			t.Errorf("ScriptRunnerFunction %s = %q, want %q", prop, got, want)
		}
	}
	for _, forbidden := range []string{"Policies:", "Events:", "FunctionUrlConfig", "VpcConfig", "Layers:"} {
		if strings.Contains(fn.body, forbidden) {
			t.Errorf("ScriptRunnerFunction carries %q; its only caller is the auth function and its only grants are the role's", forbidden)
		}
	}

	// The auth function may invoke it, by ARN, only with the runner on.
	auth := tpl.resources["AuthFunction"]
	i := strings.Index(auth.body, "Sid: InvokeScriptRunner")
	if i < 0 {
		t.Fatal("AuthFunction has no InvokeScriptRunner statement")
	}
	before := auth.body[:i]
	if j := strings.LastIndex(before, "- !If"); j < 0 || !strings.Contains(before[j:], "InboundWebhooksEnabled") {
		t.Error("InvokeScriptRunner is not conditioned on InboundWebhooksEnabled")
	}
	statement := auth.body[i:]
	if k := strings.Index(statement, "AWS::NoValue"); k > 0 {
		statement = statement[:k]
	}
	if !strings.Contains(statement, "- lambda:InvokeFunction") || !strings.Contains(statement, "Resource: !GetAtt ScriptRunnerFunction.Arn") ||
		strings.Contains(statement, "lambda:*") || strings.Contains(statement, "InvokeAsync") {
		t.Errorf("InvokeScriptRunner is not lambda:InvokeFunction on the runner's ARN alone:\n%s", statement)
	}
	for _, env := range []string{
		"AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_RUNNER_FUNCTION: !If [InboundWebhooksEnabled, !Ref ScriptRunnerFunction",
		"AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_TIMEOUT_MS: !If [InboundWebhooksEnabled, !Ref InboundScriptTimeoutMs",
		"AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS: !If [ToolsEnabled, !Ref EnableInboundWebhooks",
	} {
		if !strings.Contains(auth.body, env) {
			t.Errorf("AuthFunction's environment lacks %s", env)
		}
	}
}

// TestTheScriptRunnerOutlivesItsDeadline: the runner's Timeout is the script
// deadline in seconds plus one, so a looping script ends with the runner's own
// error — naming the webhook — rather than Lambda's kill; the template's
// deadline default is the configuration's; and the duration alarm fires below
// the deadline, where a looping script lands.
func TestTheScriptRunnerOutlivesItsDeadline(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	deadlineMs := numericDefault(t, tpl, "InboundScriptTimeoutMs")
	timeoutS := numericDefault(t, tpl, "ScriptRunnerTimeout")
	threshold := numericDefault(t, tpl, "ScriptRunnerDurationAlarmThresholdMs")

	if want := float64(config.Defaults().Tools.InboundWebhooks.ScriptTimeoutMs); deadlineMs != want {
		t.Errorf("InboundScriptTimeoutMs defaults to %.0f, the configuration's tools.inboundWebhooks.scriptTimeoutMs to %.0f", deadlineMs, want)
	}
	if want := float64(int(deadlineMs)/1000 + 1); timeoutS != want {
		t.Errorf("ScriptRunnerTimeout defaults to %.0f s, want InboundScriptTimeoutMs/1000 + 1 = %.0f s", timeoutS, want)
	}
	if limit := deadlineMs * 0.8; threshold > limit {
		t.Errorf("ScriptRunnerDurationAlarmThresholdMs defaults to %.0f, above 80%% of the %.0f ms deadline (%.0f): "+
			"a looping script is interrupted at the deadline and would never reach the alarm", threshold, deadlineMs, limit)
	}

	// The fourth clock: the auth function waits on the run, so its Timeout
	// must outlive the script deadline plus the second the invoker keeps back
	// for the route (internal/integration/aws, DefaultInvocationMargin) — at
	// the defaults, and at the largest values the parameters allow. Past it
	// the invoker cuts the run short (a 400) rather than letting Lambda kill
	// the auth function mid-Invoke, but a default that did that would be a
	// default that never runs a script to its deadline.
	const invocationMarginMs = 1000
	authTimeoutS := numericDefault(t, tpl, "Timeout")
	if authTimeoutS*1000 < deadlineMs+invocationMarginMs {
		t.Errorf("Timeout defaults to %.0f s, which does not outlive the %.0f ms script deadline plus %d ms", authTimeoutS, deadlineMs, invocationMarginMs)
	}
	deadlineMax := numericField(t, tpl, "InboundScriptTimeoutMs", "MaxValue")
	authTimeoutMax := numericField(t, tpl, "Timeout", "MaxValue")
	if authTimeoutMax*1000 < deadlineMax+invocationMarginMs {
		t.Errorf("InboundScriptTimeoutMs allows %.0f ms, which no Timeout up to its %.0f s maximum can outlive by %d ms", deadlineMax, authTimeoutMax, invocationMarginMs)
	}
	if want := float64(int(deadlineMax)/1000 + 1); numericField(t, tpl, "ScriptRunnerTimeout", "MaxValue") < want {
		t.Errorf("ScriptRunnerTimeout's MaxValue is below InboundScriptTimeoutMs's maximum in seconds plus one (%.0f)", want)
	}

	alarm, ok := tpl.resources["ScriptRunnerDurationAlarm"]
	if !ok {
		t.Fatal("ScriptRunnerDurationAlarm is gone; a looping script is this function's whole exposure")
	}
	for prop, want := range map[string]string{
		"MetricName": "Duration",
		"Statistic":  "Maximum",
		"Threshold":  "!Ref ScriptRunnerDurationAlarmThresholdMs",
	} {
		if got := alarm.props[prop]; got != want {
			t.Errorf("ScriptRunnerDurationAlarm %s = %q, want %q", prop, got, want)
		}
	}
	if !strings.Contains(alarm.body, "Value: !Ref ScriptRunnerFunction") {
		t.Error("ScriptRunnerDurationAlarm does not watch ScriptRunnerFunction")
	}
}

// numericField reads a numeric field of a parameter, MaxValue or MinValue.
func numericField(t *testing.T, tpl *template, name, field string) float64 {
	t.Helper()
	param, ok := tpl.parameters[name]
	if !ok {
		t.Fatalf("parameter %s is gone", name)
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(param.fields[field]), 64)
	if err != nil {
		t.Fatalf("parameter %s has a non-numeric %s %q: %v", name, field, param.fields[field], err)
	}
	return v
}

// TestTheScriptRunnerHasAConcurrencyCap: the inbound route is unauthenticated,
// so the caller chooses the rate, and the one hard cap on what that costs is a
// reservation on the runner. It is on by default and small, because a
// reservation is free, and it is a parameter because an account still on the
// low concurrency quota (a new one often starts at 10) cannot reserve any.
func TestTheScriptRunnerHasAConcurrencyCap(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	param, ok := tpl.parameters["ScriptRunnerReservedConcurrency"]
	if !ok {
		t.Fatal("ScriptRunnerReservedConcurrency is gone: nothing caps what a stranger can make the runner spend")
	}
	d := literal(param.fields["Default"])
	n, err := strconv.Atoi(d)
	if err != nil || n < 1 || n > 20 {
		t.Errorf("ScriptRunnerReservedConcurrency defaults to %q, want a small positive reservation", d)
	}
	if got := tpl.conditions["HasScriptRunnerReservation"]; got != "!Not [!Equals [!Ref ScriptRunnerReservedConcurrency, '']]" {
		t.Errorf("HasScriptRunnerReservation = %q", got)
	}
	if got := tpl.resources["ScriptRunnerFunction"].props["ReservedConcurrentExecutions"]; got != "!If [HasScriptRunnerReservation, !Ref ScriptRunnerReservedConcurrency, !Ref 'AWS::NoValue']" {
		t.Errorf("ScriptRunnerFunction ReservedConcurrentExecutions = %q", got)
	}
}

// TestInboundWebhooksNeedTheToolsBlockIsARule: without it, EnableInboundWebhooks
// on a stack with EnableTools off deploys and silently creates nothing, because
// InboundWebhooksEnabled needs ToolsEnabled.
func TestInboundWebhooksNeedTheToolsBlockIsARule(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(body, "\n  InboundWebhooksNeedTheToolsBlock:\n")
	if i < 0 {
		t.Fatal("the Rule InboundWebhooksNeedTheToolsBlock is gone")
	}
	rule := body[i+1:]
	if j := strings.Index(rule, "\n\n"); j > 0 {
		rule = rule[:j]
	}
	for _, want := range []string{
		"RuleCondition: !Equals [!Ref EnableInboundWebhooks, 'true']",
		"- Assert: !Equals [!Ref EnableTools, 'true']",
	} {
		if !strings.Contains(rule, want) {
			t.Errorf("InboundWebhooksNeedTheToolsBlock lacks %q:\n%s", want, rule)
		}
	}
}

// TestCIBuildsEveryFunctionTheTemplateDeploys: scripts/deploy.sh reads its
// artifact list from the template's CodeUri lines, and CI builds and
// size-checks the functions named in go.yml's LAMBDAS. A function added to one
// and not the other is either never built in CI or built for nothing; this
// holds the two together. (A merge of two blocks that each add a function
// meets it too, which is the point.)
func TestCIBuildsEveryFunctionTheTemplateDeploys(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	codeURI := regexp.MustCompile(`(?m)^\s*CodeUri:\s*\.\./\.\./dist/([A-Za-z0-9._-]+)-lambda\.zip\s*$`)
	var deployed []string
	for _, m := range codeURI.FindAllStringSubmatch(strings.ReplaceAll(string(raw), "\r\n", "\n"), -1) {
		deployed = append(deployed, m[1])
	}

	workflow, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "go.yml"))
	if err != nil {
		t.Fatalf("read go.yml: %v", err)
	}
	var built []string
	in, indent := false, 0
	for _, line := range strings.Split(strings.ReplaceAll(string(workflow), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		lead := len(line) - len(strings.TrimLeft(line, " "))
		if !in {
			if trimmed == "LAMBDAS: >-" {
				in, indent = true, lead
			}
			continue
		}
		if trimmed == "" || lead <= indent {
			break
		}
		built = append(built, strings.Fields(trimmed)...)
	}
	sort.Strings(deployed)
	sort.Strings(built)
	if len(deployed) == 0 || strings.Join(deployed, " ") != strings.Join(built, " ") {
		t.Errorf("the template deploys %v and CI's LAMBDAS builds %v; they must name the same functions", deployed, built)
	}
}

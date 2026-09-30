package sam

import (
	"regexp"
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

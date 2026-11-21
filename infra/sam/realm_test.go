package sam

import (
	"os"
	"strings"
	"testing"
)

// The realm policy parameters and the internal admin API (config-reference
// §7, §16.9, §20): what the template sets, when, and what it must never do.

// rule returns the text of one Rule, from its name to the blank line after it.
func rule(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(body, "\n  "+name+":\n")
	if i < 0 {
		t.Fatalf("the Rule %s is gone", name)
	}
	text := body[i+1:]
	if j := strings.Index(text, "\n\n"); j > 0 {
		text = text[:j]
	}
	return text
}

// TestRealmPolicyVariablesAreSetOnlyWhenTrue: the three realm switches default
// to "false" and set their variable only when "true". The environment layer
// beats the configuration document, so a variable carrying "false" would
// silently reopen a realm whose ConfigFile closed it, or drop a policy it
// demanded. The SSE function reads none of them: it serves the stream alone.
func TestRealmPolicyVariablesAreSetOnlyWhenTrue(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	for param, wiring := range map[string]struct{ condition, variable string }{
		"ClosedRegistration":    {"RegistrationClosed", "AWESOME_AUTH_REGISTRATION_CLOSED"},
		"TwoFactorRequired":     {"TwoFactorIsRequired", "AWESOME_AUTH_2FA_REQUIRED"},
		"TwoFactorEnrolOnLogin": {"TwoFactorEnrolsOnLogin", "AWESOME_AUTH_2FA_ENROL_ON_LOGIN"},
	} {
		p, ok := tpl.parameters[param]
		if !ok {
			t.Errorf("parameter %s is gone", param)
			continue
		}
		if p.fields["Default"] != "'false'" || p.fields["AllowedValues"] != "['true', 'false']" {
			t.Errorf("%s Default=%s AllowedValues=%s, want 'false' and ['true', 'false']", param, p.fields["Default"], p.fields["AllowedValues"])
		}
		if got, want := tpl.conditions[wiring.condition], "!Equals [!Ref "+param+", 'true']"; got != want {
			t.Errorf("condition %s = %q, want %q", wiring.condition, got, want)
		}
		want := wiring.variable + ": !If [" + wiring.condition + ", 'true', !Ref 'AWS::NoValue']"
		if got := envBlocks(t, tpl.resources["AuthFunction"])[wiring.variable]; got != want {
			t.Errorf("AuthFunction's %s is\n%s\nwant\n%s", wiring.variable, got, want)
		}
		if _, ok := envBlocks(t, tpl.resources["SseFunction"])[wiring.variable]; ok {
			t.Errorf("SseFunction sets %s; the stream path reads no realm policy", wiring.variable)
		}
	}
}

// TestClosedRegistrationRefusesOAuthSignUpIsARule is RS-19 at changeset time,
// in its document-aware shape: with no ConfigFile nothing can turn
// oauth.provisioning.autoCreate off, so a closed realm with a client id is
// refused; with one, the function decides.
func TestClosedRegistrationRefusesOAuthSignUpIsARule(t *testing.T) {
	t.Parallel()
	text := rule(t, "ClosedRegistrationRefusesOAuthSignUp")
	for _, want := range []string{
		"- !Equals [!Ref ClosedRegistration, 'true']",
		"- !Equals [!Ref ConfigFile, '']",
		"- !Equals [!Ref OAuthGoogleClientId, '']",
		"- !Equals [!Ref OAuthGithubClientId, '']",
		"RS-19",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("ClosedRegistrationRefusesOAuthSignUp lacks %q:\n%s", want, text)
		}
	}
}

// TestAdminMachineApiIsConditionalAndIAMAuthorized pins the internal API:
// nothing exists without a principal and the console, its one route is ANY
// /admin/{proxy+} under AWS_IAM, it invokes the auth function with payload
// 2.0, and API Gateway may invoke the function for that API's admin route
// alone. The principals reach the function exactly when the API exists.
func TestAdminMachineApiIsConditionalAndIAMAuthorized(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	if p := tpl.parameters["AdminMachinePrincipalArns"]; p.fields["Default"] != "''" || !strings.Contains(p.fields["AllowedPattern"], ":iam::[0-9]{12}:(role|user)/") {
		t.Errorf("AdminMachinePrincipalArns Default=%s AllowedPattern=%s, want empty and a role-or-user ARN list", p.fields["Default"], p.fields["AllowedPattern"])
	}
	if got := tpl.conditions["HasAdminMachinePrincipals"]; got != "!Not [!Equals [!Ref AdminMachinePrincipalArns, '']]" {
		t.Errorf("HasAdminMachinePrincipals = %q", got)
	}
	if got := tpl.conditions["AdminMachineAccessEnabled"]; got != "!And [!Condition AdminConsoleEnabled, !Condition HasAdminMachinePrincipals]" {
		t.Errorf("AdminMachineAccessEnabled = %q, want the console and the principals", got)
	}

	for name, typ := range map[string]string{
		"AdminMachineApi":              "AWS::ApiGatewayV2::Api",
		"AdminMachineIntegration":      "AWS::ApiGatewayV2::Integration",
		"AdminMachineRoute":            "AWS::ApiGatewayV2::Route",
		"AdminMachineStage":            "AWS::ApiGatewayV2::Stage",
		"AdminMachineInvokePermission": "AWS::Lambda::Permission",
	} {
		r := tpl.resources[name]
		if r == nil {
			t.Errorf("%s is gone", name)
			continue
		}
		if r.typ != typ || r.condition != "AdminMachineAccessEnabled" {
			t.Errorf("%s is %s under condition %q, want %s under AdminMachineAccessEnabled: a stack without machine access must carry none of it", name, r.typ, r.condition, typ)
		}
	}
	for resource, props := range map[string]map[string]string{
		"AdminMachineApi":         {"ProtocolType": "HTTP"},
		"AdminMachineIntegration": {"IntegrationType": "AWS_PROXY", "IntegrationUri": "!GetAtt AuthFunction.Arn", "PayloadFormatVersion": "'2.0'"},
		"AdminMachineRoute":       {"RouteKey": "'ANY /admin/{proxy+}'", "AuthorizationType": "AWS_IAM"},
		"AdminMachineStage":       {"StageName": "'$default'", "AutoDeploy": "true"},
		"AdminMachineInvokePermission": {
			"Action":       "lambda:InvokeFunction",
			"FunctionName": "!Ref AuthFunction",
			"Principal":    "apigateway.amazonaws.com",
			"SourceArn":    "!Sub 'arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${AdminMachineApi}/*/*/admin/*'",
		},
	} {
		r := tpl.resources[resource]
		if r == nil {
			continue
		}
		for key, want := range props {
			if got := r.props[key]; got != want {
				t.Errorf("%s %s = %q, want %q", resource, key, got, want)
			}
		}
	}

	want := "AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS: !If\n- AdminMachineAccessEnabled\n- !Ref AdminMachinePrincipalArns\n- !Ref 'AWS::NoValue'"
	if got := envBlocks(t, tpl.resources["AuthFunction"])["AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS"]; got != want {
		t.Errorf("AuthFunction's principals variable is\n%s\nwant\n%s", got, want)
	}
	if _, ok := envBlocks(t, tpl.resources["SseFunction"])["AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS"]; ok {
		t.Error("SseFunction sets the principals; it mounts no console, and its loader would refuse them")
	}
	// The public API carries no IAM route: the machine door is the internal
	// API alone, so CloudFront in front of the public one cannot reach it.
	if strings.Contains(tpl.resources["AuthFunction"].body, "AWS_IAM") || strings.Contains(tpl.resources["HttpApi"].body, "AWS_IAM") {
		t.Error("the public HttpApi carries an AWS_IAM route; machine access belongs to AdminMachineApi alone")
	}
}

// TestAdminMachineApiIsNotACloudFrontOrigin: the internal API is never routed
// by CloudFront. This stack's distribution sends every path to HttpApi, so the
// guarantee is that no origin, behaviour or output of the distribution names
// the internal API — which is what this asserts, on the resource's whole body.
func TestAdminMachineApiIsNotACloudFrontOrigin(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	dists := tpl.ofType("AWS::CloudFront::Distribution")
	if len(dists) == 0 {
		t.Fatal("found no CloudFront distribution, so this assertion would pass vacuously")
	}
	for _, d := range dists {
		if strings.Contains(d.body, "AdminMachine") {
			t.Errorf("%s names the internal admin API; it must never be behind CloudFront", d.name)
		}
		if !strings.Contains(d.body, "${HttpApi}.execute-api") {
			t.Errorf("%s no longer names HttpApi as its origin, so this test no longer knows what it is checking", d.name)
		}
	}
}

// TestAdminMachineAccessNeedsTheConsoleIsARule: principals with the console off
// are refused at changeset time, as the function refuses them at cold start.
func TestAdminMachineAccessNeedsTheConsoleIsARule(t *testing.T) {
	t.Parallel()
	text := rule(t, "AdminMachineAccessNeedsTheConsole")
	for _, want := range []string{
		"RuleCondition: !Not [!Equals [!Ref AdminMachinePrincipalArns, '']]",
		"- Assert: !Equals [!Ref EnableAdminConsole, 'true']",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("AdminMachineAccessNeedsTheConsole lacks %q:\n%s", want, text)
		}
	}
}

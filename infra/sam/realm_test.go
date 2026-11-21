package sam

import (
	"context"
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
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

// TestTwoFactorRequiredRefusesWhatItCannotHoldIsARule is RS-20 at changeset
// time: with TwoFactorRequired "true", an OAuth client id is refused (the
// callback opens a session with no second factor), and so is a root user on a
// mounted console (its one door, POST /admin/login, is not served under the
// policy). Not ConfigFile-aware, unlike RS-19's Rule, because nothing a
// ConfigFile says removes what the environment sets.
func TestTwoFactorRequiredRefusesWhatItCannotHoldIsARule(t *testing.T) {
	t.Parallel()
	for name, wants := range map[string][]string{
		"TwoFactorRequiredRefusesOAuthSignIn": {
			"RuleCondition: !Equals [!Ref TwoFactorRequired, 'true']",
			"- !Equals [!Ref OAuthGoogleClientId, '']",
			"- !Equals [!Ref OAuthGithubClientId, '']",
			"RS-20",
		},
		"TwoFactorRequiredRefusesTheRootUser": {
			"- !Equals [!Ref TwoFactorRequired, 'true']",
			"- !Equals [!Ref EnableAdminConsole, 'true']",
			"- Assert: !Equals [!Ref AdminRootEmail, '']",
			"RS-20",
		},
	} {
		text := rule(t, name)
		if strings.Contains(text, "ConfigFile, ''") {
			t.Errorf("%s depends on ConfigFile; the environment it guards beats the document:\n%s", name, text)
		}
		for _, want := range wants {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, text)
			}
		}
	}
}

// TestAdminMachinePrincipalPatternIsTheLoaders runs sample values of
// AdminMachinePrincipalArns through its AllowedPattern and through
// config.Load, which is what the function does with the variable the
// parameter sets. Whatever the pattern accepts the loader accepts, so a
// changeset that passes cannot deploy a function that refuses to start —
// taking every route down — over a typo; and every shape the loader refuses
// that a regular expression can see is refused at changeset time. A
// duplicate is the one the pattern cannot see, and stays the loader's.
//
// The pattern is compiled by Go's RE2 here and by Java's engine in
// CloudFormation; it uses only syntax the two read alike — anchors,
// alternation, groups, counted and starred repetition, and bracket ranges.
func TestAdminMachinePrincipalPatternIsTheLoaders(t *testing.T) {
	t.Parallel()
	raw := load(t).parameters["AdminMachinePrincipalArns"].fields["AllowedPattern"]
	if !strings.HasPrefix(raw, "'") || !strings.HasSuffix(raw, "'") || strings.Contains(raw[1:len(raw)-1], "'") {
		t.Fatalf("AllowedPattern is not one single-quoted scalar: %s", raw)
	}
	pattern, err := regexp.Compile(raw[1 : len(raw)-1])
	if err != nil {
		t.Fatalf("AllowedPattern does not compile: %v", err)
	}

	loads := func(value string) error {
		env := map[string]string{
			"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT":              "development",
			"AWESOME_AUTH_JWT_ACCESS_SECRET":                   strings.Repeat("a", 40),
			"AWESOME_AUTH_JWT_REFRESH_SECRET":                  strings.Repeat("b", 40),
			"AWESOME_AUTH_ADMIN_ENABLED":                       "true",
			"AWESOME_AUTH_ADMIN_ACCESS_POLICY":                 "is-admin-flag",
			"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS": value,
		}
		_, err := config.Load(context.Background(), config.Options{
			Getenv:             func(k string) (string, bool) { v, ok := env[k]; return v, ok },
			AllowUnimplemented: true,
		})
		var ve *config.ValidationError
		if err != nil && !errors.As(err, &ve) {
			return err
		}
		if ve != nil {
			for _, d := range ve.Diagnostics {
				if strings.HasPrefix(d.Path, "admin.machineAccess.iam.principals") {
					return d
				}
			}
		}
		return nil
	}

	accepted := []string{
		"arn:aws:iam::123456789012:role/identity-service",
		"arn:aws:iam::123456789012:role/service/identity-service",
		"arn:aws:iam::123456789012:role/a/b/c/identity.service+1=2@x_y-z",
		"arn:aws:iam::123456789012:user/ops/deployer",
		"arn:aws-us-gov:iam::123456789012:role/identity-service",
		"arn:aws:iam::123456789012:role/identity-service,arn:aws:iam::210987654321:user/deployer",
		"arn:aws:iam::123456789012:role/odd!path$/identity-service",
	}
	for _, value := range accepted {
		if !pattern.MatchString(value) {
			t.Errorf("the pattern refuses %q, which the loader admits", value)
		}
		if err := loads(value); err != nil {
			t.Errorf("the loader refuses %q, which the pattern admits: %v", value, err)
		}
	}

	refused := []string{
		"arn:aws:iam::123456789012:role/*",
		"arn:aws:iam::123456789012:role/svc*/identity-service",
		"arn:aws:iam::123456789012:role/svc/",
		"arn:aws:iam::123456789012:role/",
		"arn:aws:iam::123456789012:role/identity service",
		"arn:aws:iam::123456789012:role/identity#service",
		"arn:aws:sts::123456789012:assumed-role/identity-service/session-1",
		"arn:aws:iam::123456789012:root",
		"arn:aws:iam::12345678901:role/identity-service",
		"arn:aws:iam::123456789012:group/admins",
		"arn:aws:iam::123456789012:role/identity-service,",
		"arn:aws:iam::123456789012:role/identity-service, arn:aws:iam::123456789012:user/deployer",
	}
	for _, value := range refused {
		if pattern.MatchString(value) {
			t.Errorf("the pattern admits %q", value)
		}
	}
	// The values above that the loader can be handed as written refuse there
	// too, so the pattern is not stricter than the function about any of them.
	for _, value := range refused[:10] {
		if loads(value) == nil {
			t.Errorf("the loader admits %q; the pattern refusing it would block a deployable value", value)
		}
	}

	// The one shape left to the loader.
	dup := "arn:aws:iam::123456789012:role/identity-service,arn:aws:iam::123456789012:role/path/identity-service"
	if !pattern.MatchString(dup) {
		t.Errorf("the pattern refuses %q, a well-formed list", dup)
	}
	if loads(dup) == nil {
		t.Errorf("the loader admits a principal named twice: %q", dup)
	}
}

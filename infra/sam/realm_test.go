package sam

import (
	"context"
	"errors"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

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
		// Staff invitations (v0.15.0), by the same rule.
		"InvitationsEnabled":         {"InvitationsAreEnabled", "AWESOME_AUTH_INVITATIONS_ENABLED"},
		"InvitationsReinvite":        {"InvitationsMayReinvite", "AWESOME_AUTH_INVITATIONS_REINVITE"},
		"AdminRevealInvitationToken": {"AdminRevealsInvitationToken", "AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN"},
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

// TestClosedRegistrationRefusesDualReadIsARule pins RS-21 at changeset time: a
// closed realm migrating from a pool may not dual-read it, whatever ConfigFile
// says, since both knobs reach the function as environment variables.
func TestClosedRegistrationRefusesDualReadIsARule(t *testing.T) {
	t.Parallel()
	text := rule(t, "ClosedRegistrationRefusesDualRead")
	for _, want := range []string{
		"- !Equals [!Ref ClosedRegistration, 'true']",
		"- !Not [!Equals [!Ref CognitoUserPoolId, '']]",
		"- Assert: !Not [!Equals [!Ref CognitoMigrationMode, 'dual-read']]",
		"RS-21",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("ClosedRegistrationRefusesDualRead lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ConfigFile, ''") {
		t.Errorf("ClosedRegistrationRefusesDualRead steps aside for a ConfigFile, which cannot override either environment variable:\n%s", text)
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

// TestInvitationsTtlIsSetOnlyWhenGiven: the one invitation knob that is not a
// switch reaches the auth function only when the operator wrote a value, so
// an empty parameter leaves a ConfigFile's invitations.ttl, or the 72h
// default, in place.
func TestInvitationsTtlIsSetOnlyWhenGiven(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	p, ok := tpl.parameters["InvitationsTtl"]
	if !ok {
		t.Fatal("parameter InvitationsTtl is gone")
	}
	if p.fields["Default"] != "''" {
		t.Errorf("InvitationsTtl Default=%s, want ''", p.fields["Default"])
	}
	if got, want := tpl.conditions["HasInvitationsTtl"], "!Not [!Equals [!Ref InvitationsTtl, '']]"; got != want {
		t.Errorf("condition HasInvitationsTtl = %q, want %q", got, want)
	}
	want := "AWESOME_AUTH_INVITATIONS_TTL: !If [HasInvitationsTtl, !Ref InvitationsTtl, !Ref 'AWS::NoValue']"
	if got := envBlocks(t, tpl.resources["AuthFunction"])["AWESOME_AUTH_INVITATIONS_TTL"]; got != want {
		t.Errorf("AuthFunction's AWESOME_AUTH_INVITATIONS_TTL is\n%s\nwant\n%s", got, want)
	}
	if _, ok := envBlocks(t, tpl.resources["SseFunction"])["AWESOME_AUTH_INVITATIONS_TTL"]; ok {
		t.Error("SseFunction sets AWESOME_AUTH_INVITATIONS_TTL; the stream path reads no realm policy")
	}
}

// ── staff invitations, refused at changeset time ────────────────────────────
//
// config.Load refuses seven invitation configurations at cold start
// (internal/config validateInvitations, config-reference §21.1), and a refusal
// there is every route of the realm down — login included — until a rollback.
// Whatever of that the parameters alone decide is the template's to refuse
// first: InvitationsTtl's pattern, and the Rules these tests pin and evaluate.

// invitationEnv is what the invitation refusals read: the four invitation
// variables, and the console, resource-server, mailer and delivery-webhook
// variables they are weighed against.
var invitationEnv = []string{
	"AWESOME_AUTH_INVITATIONS_ENABLED",
	"AWESOME_AUTH_INVITATIONS_TTL",
	"AWESOME_AUTH_INVITATIONS_REINVITE",
	"AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN",
	"AWESOME_AUTH_ADMIN_ENABLED",
	"AWESOME_AUTH_ADMIN_ACCESS_POLICY",
	"AWESOME_AUTH_RS_ENABLED",
	"AWESOME_AUTH_RS_JWKS_URL",
	"AWESOME_AUTH_MAILER_ENDPOINT",
	"AWESOME_AUTH_MAILER_FROM",
	"AWESOME_AUTH_MAILER_DEFAULT_LANG",
	"AWESOME_AUTH_MAILER_PROVIDER",
	"AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_URL",
}

// invitationRefusals runs config.Load as the auth function does, over the
// environment these parameters give it — the variables above, evaluated from
// the template's AuthFunction, beside a development deployment's signing keys
// — and doc, the ConfigFile's document, or nil for none. It returns the
// refusals on invitations.* and admin.revealInvitationToken; every other
// refusal is left to its own tests.
func invitationRefusals(t *testing.T, tpl *template, params map[string]string, doc config.Document) []string {
	t.Helper()
	env := renderEnv(t, tpl, "AuthFunction", params, invitationEnv...)
	env["AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT"] = "development"
	env["AWESOME_AUTH_JWT_ACCESS_SECRET"] = strings.Repeat("a", 40)
	env["AWESOME_AUTH_JWT_REFRESH_SECRET"] = strings.Repeat("b", 40)
	if _, ok := env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_URL"]; ok {
		// The template hands the signing key over as a Secrets Manager
		// reference, which needs an account; this is the same knob, resolved.
		env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = strings.Repeat("w", 40)
	}
	_, err := config.Load(context.Background(), config.Options{
		Document: doc,
		Getenv:   func(k string) (string, bool) { v, ok := env[k]; return v, ok },
	})
	var ve *config.ValidationError
	if err != nil && !errors.As(err, &ve) {
		t.Fatalf("config.Load: %v", err)
	}
	var out []string
	if ve != nil {
		for _, d := range ve.Diagnostics {
			if d.Severity == config.SeverityError && (strings.HasPrefix(d.Path, "invitations.") || d.Path == "admin.revealInvitationToken") {
				out = append(out, d.Path+": "+d.Problem)
			}
		}
	}
	return out
}

// singleQuotedPattern compiles a parameter's AllowedPattern, which must be one
// single-quoted scalar on one line for this reader. It is compiled by Go's RE2
// here and by Java's engine in CloudFormation, so a pattern uses only syntax
// the two read alike: anchors, alternation, groups, counted repetition and
// bracket ranges.
func singleQuotedPattern(t *testing.T, tpl *template, param string) *regexp.Regexp {
	t.Helper()
	raw := tpl.parameters[param].fields["AllowedPattern"]
	if len(raw) < 2 || !strings.HasPrefix(raw, "'") || !strings.HasSuffix(raw, "'") || strings.Contains(raw[1:len(raw)-1], "'") {
		t.Fatalf("%s's AllowedPattern is not one single-quoted scalar: %s", param, raw)
	}
	pattern, err := regexp.Compile(raw[1 : len(raw)-1])
	if err != nil {
		t.Fatalf("%s's AllowedPattern does not compile: %v", param, err)
	}
	return pattern
}

// TestInvitationsTtlPatternIsTheLoaders holds InvitationsTtl's AllowedPattern
// to what the loader does with invitations.ttl, as
// TestAdminMachinePrincipalPatternIsTheLoaders does for the principals: what
// the pattern admits the loader admits, so a change set that passes cannot
// deploy a function that refuses every cold start over its TTL. The loader
// reads the TTL only with invitations on, so it is asked with them on.
//
// The pattern is narrower than the loader's grammar on purpose, and never
// wider: one whole number of minutes, hours or days, written without a leading
// zero. The other ms spellings the loader reads ("072h", "1w", "3 days",
// "2.5h") are refused here, which costs an operator a rewrite and never a
// cold start.
func TestInvitationsTtlPatternIsTheLoaders(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	pattern := singleQuotedPattern(t, tpl, "InvitationsTtl")

	// config.Load's verdict on one value, with invitations on and nothing else
	// to refuse: the console, and a mailer to deliver.
	loads := func(ttl string) bool {
		return len(invitationRefusals(t, tpl, parameterValues(t, tpl, map[string]string{
			"InvitationsEnabled": "true",
			"EnableAdminConsole": "true",
			"MailerFromAddress":  "auth@example.com",
			"InvitationsTtl":     ttl,
		}), nil)) == 0
	}

	// The same verdict as a predicate — one ms-syntax term that resolves to
	// more than zero and at most 30 days — tied to config.Load at every edge
	// here, so the sweep below can run on it.
	const ceiling = 30 * 24 * time.Hour
	admits := func(ttl string) bool {
		d, err := config.ParseDuration(ttl)
		return err == nil && d.Duration() > 0 && d.Duration() <= ceiling
	}
	for _, ttl := range []string{
		"1m", "43200m", "43201m", "0m",
		"1h", "720h", "721h", "0h",
		"1d", "30d", "31d", "0d",
		"072h", "1w", "5w", "3 days", "2.5h", "72H", "-1h",
	} {
		if got, want := loads(ttl), admits(ttl); got != want {
			t.Errorf("config.Load admits %q: %v; the predicate says %v", ttl, got, want)
		}
	}

	// Every whole number of each unit, and the same with a leading zero.
	for _, unit := range []struct {
		suffix string
		upTo   int
	}{{"m", 50000}, {"h", 1000}, {"d", 40}} {
		for n := 0; n <= unit.upTo; n++ {
			ttl := strconv.Itoa(n) + unit.suffix
			if got, want := pattern.MatchString(ttl), admits(ttl); got != want {
				t.Errorf("the pattern admits %q: %v; the loader: %v", ttl, got, want)
			}
			if padded := "0" + ttl; pattern.MatchString(padded) {
				t.Errorf("the pattern admits %q, a leading zero", padded)
			}
		}
	}

	// Empty is the default, and leaves the variable unset: a ConfigFile's
	// invitations.ttl, or the loader's 72h.
	if !pattern.MatchString("") || !loads("") {
		t.Error(`InvitationsTtl "" must pass the pattern and leave the loader its default`)
	}
	for _, ttl := range []string{"072h", "1w", "3 days", "2.5h", "72H", "+3d", " 3d", "3d ", "1h30m", "-1h", "3"} {
		if pattern.MatchString(ttl) {
			t.Errorf("the pattern admits %q, a spelling it is meant to refuse", ttl)
		}
	}
}

// TestInvitationRefusalsAreRules pins the six Rules' text, as the other
// ...IsARule tests do. Two refuse whatever a ConfigFile says, because the
// variables they read beat the document: AWESOME_AUTH_RS_ENABLED is always
// set, and a reveal flag or a sender this template sets cannot be unset by
// one. Four step aside for a ConfigFile, because their parameters set a
// variable only when "true" and a document can supply what they leave out.
func TestInvitationRefusalsAreRules(t *testing.T) {
	t.Parallel()
	for name, c := range map[string]struct {
		documentAware bool
		wants         []string
	}{
		"RevealRefusesASender": {false, []string{
			"RuleCondition: !Equals [!Ref AdminRevealInvitationToken, 'true']",
			"- !Equals [!Ref MailerFromAddress, '']",
			"- !Equals [!Ref EmailDeliveryWebhookUrl, '']",
		}},
		"InvitationsRefuseResourceServer": {false, []string{
			"RuleCondition: !Equals [!Ref InvitationsEnabled, 'true']",
			"- Assert: !Equals [!Ref EnableResourceServer, 'false']",
		}},
		"InvitationsNeedTheConsole": {true, []string{
			"- !Equals [!Ref InvitationsEnabled, 'true']",
			"- Assert: !Equals [!Ref EnableAdminConsole, 'true']",
		}},
		"InvitationsNeedADelivery": {true, []string{
			"- !Equals [!Ref InvitationsEnabled, 'true']",
			"- !Not [!Equals [!Ref MailerFromAddress, '']]",
			"- !Not [!Equals [!Ref EmailDeliveryWebhookUrl, '']]",
			"- !Equals [!Ref AdminRevealInvitationToken, 'true']",
		}},
		"RevealNeedsInvitations": {true, []string{
			"- !Equals [!Ref AdminRevealInvitationToken, 'true']",
			"- Assert: !Equals [!Ref InvitationsEnabled, 'true']",
		}},
		"ReinviteNeedsInvitations": {true, []string{
			"- !Equals [!Ref InvitationsReinvite, 'true']",
			"- Assert: !Equals [!Ref InvitationsEnabled, 'true']",
		}},
	} {
		text := rule(t, name)
		if got := strings.Contains(text, "- !Equals [!Ref ConfigFile, '']"); got != c.documentAware {
			t.Errorf("%s steps aside for a ConfigFile: %v, want %v:\n%s", name, got, c.documentAware, text)
		}
		for _, want := range c.wants {
			if !strings.Contains(text, want) {
				t.Errorf("%s lacks %q:\n%s", name, want, text)
			}
		}
	}
}

// TestInvitationRulesRefuseWhatTheLoaderRefuses evaluates the Rules and runs
// config.Load on the same parameters. With no ConfigFile they must agree both
// ways, over every combination of the switches the refusals weigh: a refusal
// with no Rule is a stack that deploys and then fails every cold start, and a
// Rule the loader does not share blocks a stack that would have run. With a
// ConfigFile, the two unconditional Rules still refuse what the loader still
// refuses, and the four others step aside, which is right exactly when a
// document can make the loader accept.
func TestInvitationRulesRefuseWhatTheLoaderRefuses(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	rules := readRules(t)
	const configFile = "/var/task/awesome-auth.json"
	const jwks = "https://issuer.example.com/.well-known/jwks.json"
	// A delivery webhook is deployed with its signing key, which the function
	// requires beside the URL, so every set below that names one carries both.
	const webhook = "https://delivery.example.com/hook"
	const webhookKey = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:delivery-webhook"
	consoleDoc := map[string]any{"enabled": true, "accessPolicy": "is-admin-flag"}
	mailerDoc := map[string]any{"endpoint": "https://mail.example.com/send", "from": "auth@example.com"}

	for _, c := range []struct {
		name      string
		given     map[string]string
		doc       config.Document // the ConfigFile's; nil for none
		refusedBy []string        // sorted; nil when the change set passes
		loads     bool
	}{
		{name: "the defaults", loads: true},
		{
			name:      "invitations alone",
			given:     map[string]string{"InvitationsEnabled": "true"},
			refusedBy: []string{"InvitationsNeedADelivery", "InvitationsNeedTheConsole"},
		},
		{
			name:  "invitations with the console and the mailer",
			given: map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "MailerFromAddress": "auth@example.com"},
			loads: true,
		},
		{
			name:  "invitations with the console and the delivery webhook",
			given: map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "EmailDeliveryWebhookUrl": webhook, "EmailDeliveryWebhookSecretArn": webhookKey},
			loads: true,
		},
		{
			name:  "invitations with the console, revealed, re-invitable, for 30d",
			given: map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "AdminRevealInvitationToken": "true", "InvitationsReinvite": "true", "InvitationsTtl": "30d"},
			loads: true,
		},
		{
			name:      "reveal beside the mailer",
			given:     map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "AdminRevealInvitationToken": "true", "MailerFromAddress": "auth@example.com"},
			refusedBy: []string{"RevealRefusesASender"},
		},
		{
			name:      "reveal beside the delivery webhook",
			given:     map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "AdminRevealInvitationToken": "true", "EmailDeliveryWebhookUrl": webhook, "EmailDeliveryWebhookSecretArn": webhookKey},
			refusedBy: []string{"RevealRefusesASender"},
		},
		{
			name:      "reveal beside the mailer with invitations off",
			given:     map[string]string{"AdminRevealInvitationToken": "true", "MailerFromAddress": "auth@example.com"},
			refusedBy: []string{"RevealNeedsInvitations", "RevealRefusesASender"},
		},
		{
			name:      "invitations in resource-server mode",
			given:     map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "MailerFromAddress": "auth@example.com", "EnableResourceServer": "true", "ResourceServerJwksUrl": jwks},
			refusedBy: []string{"InvitationsRefuseResourceServer"},
		},
		{
			name:      "reinvite with invitations off",
			given:     map[string]string{"InvitationsReinvite": "true"},
			refusedBy: []string{"ReinviteNeedsInvitations"},
		},
		{
			name:      "reveal with invitations off",
			given:     map[string]string{"AdminRevealInvitationToken": "true"},
			refusedBy: []string{"RevealNeedsInvitations"},
		},

		// A ConfigFile that supplies what the parameters leave out: the four
		// document-aware Rules step aside, and the loader accepts — a Rule
		// there would be stricter than the function.
		{
			name:  "invitations, the console and the mailer in the ConfigFile",
			given: map[string]string{"InvitationsEnabled": "true", "ConfigFile": configFile},
			doc:   config.Document{"schemaVersion": 1, "admin": consoleDoc, "email": map[string]any{"mailer": mailerDoc}},
			loads: true,
		},
		{
			name:  "reinvite and reveal, invitations and the console in the ConfigFile",
			given: map[string]string{"InvitationsReinvite": "true", "AdminRevealInvitationToken": "true", "ConfigFile": configFile},
			doc:   config.Document{"schemaVersion": 1, "admin": consoleDoc, "invitations": map[string]any{"enabled": true}},
			loads: true,
		},
		// A ConfigFile that does not: the refusal a Rule cannot see, left to
		// the function at cold start.
		{
			name:  "invitations alone, a ConfigFile without the console",
			given: map[string]string{"InvitationsEnabled": "true", "ConfigFile": configFile},
			doc:   config.Document{"schemaVersion": 1},
		},
		// The two unconditional Rules, with a ConfigFile trying to undo what
		// they refuse: the environment beats the document, so the loader
		// refuses all the same.
		{
			name:      "reveal beside the mailer, a ConfigFile clearing both",
			given:     map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "AdminRevealInvitationToken": "true", "MailerFromAddress": "auth@example.com", "ConfigFile": configFile},
			doc:       config.Document{"schemaVersion": 1, "admin": map[string]any{"revealInvitationToken": false}, "email": map[string]any{"mailer": map[string]any{"from": ""}}},
			refusedBy: []string{"RevealRefusesASender"},
		},
		{
			name:      "invitations in resource-server mode, a ConfigFile turning both off",
			given:     map[string]string{"InvitationsEnabled": "true", "EnableAdminConsole": "true", "MailerFromAddress": "auth@example.com", "EnableResourceServer": "true", "ResourceServerJwksUrl": jwks, "ConfigFile": configFile},
			doc:       config.Document{"schemaVersion": 1, "resourceServer": map[string]any{"enabled": false}, "invitations": map[string]any{"enabled": false}},
			refusedBy: []string{"InvitationsRefuseResourceServer"},
		},
	} {
		params := parameterValues(t, tpl, c.given)
		if got := refusedBy(t, rules, params); !slices.Equal(got, c.refusedBy) {
			t.Errorf("%s: refused by %v, want %v", c.name, got, c.refusedBy)
		}
		if got := invitationRefusals(t, tpl, params, c.doc); (len(got) == 0) != c.loads {
			t.Errorf("%s: config.Load refuses %v, want loads=%v", c.name, got, c.loads)
		}
	}

	switches := []struct{ param, on, off string }{
		{"InvitationsEnabled", "true", "false"},
		{"InvitationsReinvite", "true", "false"},
		{"AdminRevealInvitationToken", "true", "false"},
		{"EnableAdminConsole", "true", "false"},
		{"EnableResourceServer", "true", "false"},
		{"MailerFromAddress", "auth@example.com", ""},
		{"EmailDeliveryWebhookUrl", webhook, ""},
	}
	combinations, disagreements := 0, 0
	for _, ttl := range []string{"", "1m", "72h", "30d", "720h", "43200m"} {
		for mask := 0; mask < 1<<len(switches); mask++ {
			given := map[string]string{"InvitationsTtl": ttl, "ResourceServerJwksUrl": jwks}
			for i, s := range switches {
				given[s.param] = s.off
				if mask&(1<<i) != 0 {
					given[s.param] = s.on
				}
			}
			if given["EmailDeliveryWebhookUrl"] != "" {
				given["EmailDeliveryWebhookSecretArn"] = webhookKey
			}
			params := parameterValues(t, tpl, given)
			refused, loader := refusedBy(t, rules, params), invitationRefusals(t, tpl, params, nil)
			combinations++
			if (len(refused) > 0) != (len(loader) > 0) {
				disagreements++
				if disagreements <= 10 {
					t.Errorf("%v:\n  the Rules refuse %v\n  config.Load refuses %v", given, refused, loader)
				}
			}
		}
	}
	if disagreements > 0 {
		t.Errorf("the Rules and config.Load disagree on %d of %d parameter sets", disagreements, combinations)
	}
}

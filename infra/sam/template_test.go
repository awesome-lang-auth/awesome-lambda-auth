// Package sam holds the quickstart CloudFormation template and the assertions
// about it that are cheap to state here and expensive to discover in an account.
//
// There is no Go code in this package and there is not meant to be. What there
// is, is a set of structural claims that `cloudformation validate-template`
// would not make and that a reviewer cannot be relied on to make twice a year:
// that every function has a log group with an expiry, that every alarm has an
// action and a description, that the alarm set stays inside the free allowance
// it was designed against, and that no account id, ARN or address has been
// committed. Each of them is a convention somebody would otherwise have to
// remember while adding the next function.
//
// It is deliberately a line-oriented reader rather than a YAML one. Adding a
// YAML dependency to this module to read one file in the repository would put it
// in the go.mod of a deployed Lambda binary, and everything asserted below lives
// at the top two levels of indentation, where CloudFormation's own conventions
// make a scanner sufficient. The scanner refuses to pass vacuously: if it finds
// no resources, no functions or no alarms, that is a failure and not a quiet
// success, which is the failure mode a hand-rolled parser actually has.
package sam

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const templateFile = "template.yaml"

// ── the reader ──────────────────────────────────────────────────────────────

type resource struct {
	name      string
	typ       string
	condition string
	dependsOn []string
	// props holds the scalar properties written on one line directly under
	// Properties:. That is every property asserted below and nothing else; a
	// nested block is visible through body instead.
	props map[string]string
	body  string
}

type entry struct {
	name   string
	fields map[string]string
}

type template struct {
	parameters map[string]entry
	resources  map[string]*resource
	order      []string
}

var (
	topLevelKey = regexp.MustCompile(`^([A-Za-z]+):\s*$`)
	blockName   = regexp.MustCompile(`^  ([A-Za-z0-9]+):\s*$`)
	blockField  = regexp.MustCompile(`^    ([A-Za-z0-9]+):\s*(.*)$`)
	propField   = regexp.MustCompile(`^      ([A-Za-z0-9]+):\s*(.*)$`)
	listItem    = regexp.MustCompile(`^      - (.+)$`)
)

func skip(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

// load reads the template into the two sections the assertions need. Anything it
// cannot make sense of is left out rather than guessed at, and every assertion
// below states what it needs, so a property this reader silently missed shows up
// as a failing test and not as a passing one.
func load(t *testing.T) *template {
	t.Helper()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	tpl := &template{parameters: map[string]entry{}, resources: map[string]*resource{}}
	section := ""
	var current *resource
	var currentParam *entry
	inProperties := false
	inDependsOn := false

	for _, line := range lines {
		if skip(line) {
			continue
		}
		if m := topLevelKey.FindStringSubmatch(line); m != nil {
			section = m[1]
			current, currentParam, inProperties, inDependsOn = nil, nil, false, false
			continue
		}
		switch section {
		case "Parameters":
			if m := blockName.FindStringSubmatch(line); m != nil {
				tpl.parameters[m[1]] = entry{name: m[1], fields: map[string]string{}}
				p := tpl.parameters[m[1]]
				currentParam = &p
				continue
			}
			if currentParam == nil {
				continue
			}
			if m := blockField.FindStringSubmatch(line); m != nil {
				currentParam.fields[m[1]] = strings.TrimSpace(m[2])
				tpl.parameters[currentParam.name] = *currentParam
			}
		case "Resources":
			if m := blockName.FindStringSubmatch(line); m != nil {
				current = &resource{name: m[1], props: map[string]string{}}
				tpl.resources[m[1]] = current
				tpl.order = append(tpl.order, m[1])
				inProperties, inDependsOn = false, false
				continue
			}
			if current == nil {
				continue
			}
			current.body += line + "\n"
			if m := blockField.FindStringSubmatch(line); m != nil {
				inProperties = m[1] == "Properties"
				inDependsOn = false
				switch m[1] {
				case "Type":
					current.typ = strings.TrimSpace(m[2])
				case "Condition":
					current.condition = strings.TrimSpace(m[2])
				case "DependsOn":
					if v := strings.TrimSpace(m[2]); v != "" {
						current.dependsOn = append(current.dependsOn, splitInline(v)...)
					} else {
						inDependsOn = true
					}
				}
				continue
			}
			if inDependsOn {
				if m := listItem.FindStringSubmatch(line); m != nil {
					current.dependsOn = append(current.dependsOn, strings.TrimSpace(m[1]))
					continue
				}
				inDependsOn = false
			}
			if inProperties {
				if m := propField.FindStringSubmatch(line); m != nil {
					if v := strings.TrimSpace(m[2]); v != "" {
						current.props[m[1]] = v
					}
				}
			}
		}
	}

	if len(tpl.resources) == 0 || len(tpl.parameters) == 0 {
		t.Fatalf("read no resources (%d) or no parameters (%d) out of %s: the reader in this file "+
			"no longer understands the template, and every assertion below would pass vacuously",
			len(tpl.resources), len(tpl.parameters), templateFile)
	}
	return tpl
}

// splitInline turns `[A, B]` or `A` into a list.
func splitInline(v string) []string {
	v = strings.Trim(v, "[]")
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (t *template) ofType(types ...string) []*resource {
	var out []*resource
	for _, name := range t.order {
		r := t.resources[name]
		for _, want := range types {
			if r.typ == want {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// literal strips the `!Sub` and the quotes off a scalar, so that
// `!Sub '${AWS::StackName}-auth'` and `'${AWS::StackName}-auth'` compare equal.
// The substitution itself is left alone: two names that must match are compared
// as the same unresolved expression, which is stronger than comparing what they
// would resolve to under a stack name this test would have had to invent.
func literal(v string) string {
	v = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(v), "!Sub"))
	return strings.Trim(strings.TrimSpace(v), `'"`)
}

// ── the log group convention ────────────────────────────────────────────────

// TestEveryFunctionHasALogGroupWithAnExpiry is the enforcement half of the
// convention documented above AuthLogGroup in the template.
//
// A log group Lambda creates for itself has no expiry at all, and nothing about
// that looks wrong until the CloudWatch storage line does. So every function in
// this template must be paired with an explicit group, named exactly the way
// Lambda would have named it, with the retention parameter on it, and ordered
// after it — and a block that adds the SSE function, the webhook worker, the
// script runner or the migrate job fails here rather than in a bill.
func TestEveryFunctionHasALogGroupWithAnExpiry(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	functions := tpl.ofType("AWS::Serverless::Function", "AWS::Lambda::Function")
	if len(functions) == 0 {
		t.Fatal("found no functions in the template, so this test proves nothing")
	}

	// Index the log groups by the name they are created under, not by logical
	// id: the name is what Lambda matches on, and a group with the right logical
	// id and the wrong name is precisely the mistake this catches.
	groups := map[string]*resource{}
	for _, g := range tpl.ofType("AWS::Logs::LogGroup") {
		name, ok := g.props["LogGroupName"]
		if !ok {
			t.Errorf("%s has no LogGroupName, so Lambda cannot be made to write into it", g.name)
			continue
		}
		groups[literal(name)] = g
	}

	for _, fn := range functions {
		name, ok := fn.props["FunctionName"]
		if !ok {
			t.Errorf("%s sets no FunctionName, so the log group it needs cannot be named "+
				"(/aws/lambda/<FunctionName>) and Lambda will create a never-expiring one", fn.name)
			continue
		}
		want := "/aws/lambda/" + literal(name)
		group, ok := groups[want]
		if !ok {
			t.Errorf("%s (FunctionName %s) has no log group named %q.\n\n"+
				"Add one — AWS::Logs::LogGroup with that LogGroupName and "+
				"RetentionInDays: !Ref LogRetentionDays — and a DependsOn from the function to it. "+
				"Without it Lambda creates the group itself, with NO EXPIRY, and the stack looks correct.",
				fn.name, literal(name), want)
			continue
		}
		if got := strings.TrimSpace(group.props["RetentionInDays"]); got != "!Ref LogRetentionDays" {
			t.Errorf("%s has RetentionInDays %q, want %q: retention is one knob for the whole stack, "+
				"so that raising it is one decision and not an audit of every group",
				group.name, got, "!Ref LogRetentionDays")
		}
		if !slices.Contains(fn.dependsOn, group.name) {
			t.Errorf("%s does not DependsOn %s. It is a race, not a style point: the function can be "+
				"invoked — and therefore create its own group — before CloudFormation creates this one",
				fn.name, group.name)
		}
	}
}

// TestLogRetentionDefaultsToFourteenDays pins the number rather than merely the
// presence of one. Never-expire is the failure this whole convention is about;
// a default of 3653 would satisfy every other assertion here and would be the
// same bill in slow motion.
func TestLogRetentionDefaultsToFourteenDays(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	param, ok := tpl.parameters["LogRetentionDays"]
	if !ok {
		t.Fatal("LogRetentionDays is gone; every log group in the template references it")
	}
	if got := param.fields["Default"]; got != "14" {
		t.Errorf("LogRetentionDays defaults to %q, want 14 — long enough to debug last week, "+
			"short enough that stored volume stops growing", got)
	}
}

// ── the alarms ──────────────────────────────────────────────────────────────

// freeAlarmMetrics is CloudWatch's always-free allowance for standard-resolution
// alarm metrics, and it is the budget this stack's alarm set was designed
// against. Past it an alarm costs about USD 0.10 a month.
const freeAlarmMetrics = 10

// TestTheAlarmSetStaysInsideTheFreeAllowance is a tripwire on a cost decision,
// not a rule about good taste. It is expected to fail one day — the per-function
// quartet is four alarm metrics and this product has four more functions coming
// — and the point is that it fails while somebody is in a position to decide,
// rather than showing up as a line on a bill.
func TestTheAlarmSetStaysInsideTheFreeAllowance(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	alarms := tpl.ofType("AWS::CloudWatch::Alarm")
	if len(alarms) == 0 {
		t.Fatal("the template declares no alarms at all")
	}
	if len(alarms) > freeAlarmMetrics {
		t.Errorf("the template declares %d alarms, past CloudWatch's free %d.\n\n"+
			"That is about USD %.2f a month, which may well be the right call — the per-function set is "+
			"four alarm metrics and this product has more functions coming. If it is: raise the number "+
			"here and update the alarm costs in docs/cost-model.md and infra/sam/README.md in the same "+
			"commit, so the stack's monthly cost stays written down somewhere true.",
			len(alarms), freeAlarmMetrics, float64(len(alarms)-freeAlarmMetrics)*0.10)
	}
}

// TestEveryAlarmIsActionableAndGated: an alarm with no action is decoration, and
// an alarm whose action is not gated on HasAlarmTarget would make the target a
// required parameter — which is how an address ends up committed as a default.
// The description is asserted because it is the entire body of the notification
// somebody reads at 3am.
func TestEveryAlarmIsActionableAndGated(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	alarms := tpl.ofType("AWS::CloudWatch::Alarm")
	if len(alarms) == 0 {
		t.Fatal("the template declares no alarms at all")
	}
	for _, a := range alarms {
		if !strings.Contains(a.body, "AlarmActions:") {
			t.Errorf("%s has no AlarmActions: an alarm nothing is told about is decoration", a.name)
		}
		if !strings.Contains(a.body, "HasAlarmTarget") {
			t.Errorf("%s does not gate its AlarmActions on HasAlarmTarget, so the stack would need a "+
				"notification target to deploy at all", a.name)
		}
		if !strings.Contains(a.body, "AlarmDescription:") {
			t.Errorf("%s has no AlarmDescription, and the description is the whole of what the "+
				"notification says", a.name)
		}
		if _, ok := a.props["TreatMissingData"]; !ok {
			t.Errorf("%s does not say how to treat missing data. An idle stack publishes no Lambda or "+
				"DynamoDB metrics at all, and an alarm that fires because nothing happened is an alarm "+
				"somebody turns off", a.name)
		}
		if a.condition != "AlarmsEnabled" {
			t.Errorf("%s has Condition %q, want AlarmsEnabled so that EnableAlarms turns the whole set "+
				"off in one place", a.name, a.condition)
		}
	}
}

// TestNoAlarmIsHighResolution: an alarm on a period under 60 seconds is billed
// at three times the standard rate and is worth it for nothing here — every
// incident this set watches for is minutes long by nature.
func TestNoAlarmIsHighResolution(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	for _, a := range tpl.ofType("AWS::CloudWatch::Alarm") {
		raw, ok := a.props["Period"]
		if !ok {
			t.Errorf("%s sets no Period", a.name)
			continue
		}
		period, err := strconv.Atoi(raw)
		if err != nil {
			t.Errorf("%s has an unreadable Period %q", a.name, raw)
			continue
		}
		if period < 60 {
			t.Errorf("%s has Period %d, which makes it a high-resolution alarm at three times the "+
				"price. Nothing here needs sub-minute resolution", a.name, period)
		}
	}
}

// TestTheDurationAlarmFiresBeforeTheTimeout is the one coupling in this template
// that CloudFormation cannot express: a threshold in milliseconds and a timeout
// in seconds, with no arithmetic available to relate them.
//
// The relationship is the whole point of the alarm. A function that has started
// timing out bills its entire timeout on every request, so an alarm set AT the
// timeout reports an incident that is already being paid for, and one set above
// it never fires at all.
func TestTheDurationAlarmFiresBeforeTheTimeout(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	timeout := numericDefault(t, tpl, "Timeout")
	threshold := numericDefault(t, tpl, "DurationAlarmThresholdMs")

	if limit := timeout * 1000 * 0.8; threshold > limit {
		t.Errorf("DurationAlarmThresholdMs defaults to %.0f ms against a Timeout default of %.0f s, "+
			"so the alarm fires at %.0f%% of the timeout. Want 80%% or less (%.0f ms): the alarm has to "+
			"arrive before the function starts billing its whole timeout, not after",
			threshold, timeout, threshold/(timeout*1000)*100, limit)
	}
}

func numericDefault(t *testing.T, tpl *template, name string) float64 {
	t.Helper()
	param, ok := tpl.parameters[name]
	if !ok {
		t.Fatalf("parameter %s is gone", name)
	}
	v, err := strconv.ParseFloat(strings.TrimSpace(param.fields["Default"]), 64)
	if err != nil {
		t.Fatalf("parameter %s has a non-numeric Default %q: %v", name, param.fields["Default"], err)
	}
	return v
}

// ── the upload bucket ───────────────────────────────────────────────────────

// TestTheUploadBucketIsPrivateEncryptedAndConditional is the enforcement half
// of the comment above AdminUploadsBucket. Every bucket in this template must
// be off unless asked for, block public access four ways, disable ACLs and
// encrypt at rest — and the IAM statements that reach it must be conditioned
// on the same switch and scoped to the bucket's prefix, never to a wildcard.
// A later block that adds a bucket — access logs, an export — fails here
// rather than in a public-bucket finding.
func TestTheUploadBucketIsPrivateEncryptedAndConditional(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	buckets := tpl.ofType("AWS::S3::Bucket")
	if len(buckets) == 0 {
		t.Fatal("the template declares no bucket, so this test proves nothing")
	}
	for _, b := range buckets {
		if b.condition == "" {
			t.Errorf("%s has no Condition: a bucket that always exists is a bill and a namespace collision on every deploy", b.name)
		}
		for _, want := range []string{
			"BlockPublicAcls: true", "BlockPublicPolicy: true",
			"IgnorePublicAcls: true", "RestrictPublicBuckets: true",
			"ObjectOwnership: BucketOwnerEnforced",
			"SSEAlgorithm:",
		} {
			if !strings.Contains(b.body, want) {
				t.Errorf("%s lacks %q; the bucket must be private and encrypted in every configuration", b.name, want)
			}
		}
		if strings.Contains(b.body, "BucketName:") {
			t.Errorf("%s sets a BucketName; a fixed name collides with a bucket a previous stack left behind", b.name)
		}
		if strings.Contains(b.body, "WebsiteConfiguration") || strings.Contains(b.body, "PublicRead") {
			t.Errorf("%s is configured for public serving; the function serves the objects, not S3", b.name)
		}
	}

	fn, ok := tpl.resources["AuthFunction"]
	if !ok {
		t.Fatal("AuthFunction is gone")
	}
	for _, sid := range []string{"AdminUploadObjects", "AdminUploadListing"} {
		i := strings.Index(fn.body, "Sid: "+sid)
		if i < 0 {
			t.Errorf("AuthFunction grants no statement with Sid %s", sid)
			continue
		}
		// The statement must sit inside an !If on the upload switch: look back
		// from the Sid to the nearest condition name.
		before := fn.body[:i]
		j := strings.LastIndex(before, "- !If")
		if j < 0 || !strings.Contains(before[j:], "AdminUploadsEnabled") {
			t.Errorf("Sid %s is not conditioned on AdminUploadsEnabled; a stack without the bucket would grant S3 access to nothing, or to everything", sid)
		}
	}
	// The assertions are positive, because the template writes its ARNs
	// through ${AdminUploadsBucket.Arn} and a literal wildcard could never
	// appear in an honest or a dishonest edit: what has to be seen is the
	// prefix on the object grant, the bucket ARN and no s3:prefix condition on
	// the listing grant, and no '*' Resource anywhere in the S3 block.
	start := strings.Index(fn.body, "Sid: AdminUploadObjects")
	end := strings.Index(fn.body[start:], "AWS::NoValue")
	if start < 0 || end < 0 {
		t.Fatal("cannot isolate the S3 statements in AuthFunction")
	}
	s3Block := fn.body[start : start+end]
	if !strings.Contains(s3Block, "Resource: !Sub '${AdminUploadsBucket.Arn}/uploads/*'") {
		t.Error("AdminUploadObjects is not scoped to ${AdminUploadsBucket.Arn}/uploads/*, the one prefix the store writes under")
	}
	if !strings.Contains(s3Block, "Resource: !GetAtt AdminUploadsBucket.Arn") {
		t.Error("AdminUploadListing is not scoped to the bucket's own ARN")
	}
	// No prefix condition on the listing, on purpose: S3 answers a missing
	// key 404 only to a caller that holds s3:ListBucket for that request, and
	// a GetObject carries no s3:prefix, so a conditioned grant would turn
	// every miss into a 403 the store reads as a failure
	// (internal/integration/aws/s3_uploads.go, TestS3AccessDeniedIsAFailureNotAMiss).
	if strings.Contains(s3Block, "s3:prefix") {
		t.Error("AdminUploadListing carries an s3:prefix condition, which does not apply to GetObject/HeadObject and turns every missing upload into a 403 instead of a 404")
	}
	for _, line := range strings.Split(s3Block, "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "Resource:") && strings.Contains(trimmed, "'*'") {
			t.Errorf("an S3 statement names Resource '*': %s", trimmed)
		}
	}
	if strings.Contains(fn.body, "s3:*") || strings.Contains(fn.body, "arn:aws:s3:::*") {
		t.Error("AuthFunction carries an S3 wildcard; every S3 grant is scoped to the upload bucket")
	}

	// The bucket policy exists, is conditioned with the bucket, and only
	// denies: the one thing a policy on a private bucket should add is the
	// TLS requirement.
	policy, ok := tpl.resources["AdminUploadsBucketPolicy"]
	if !ok {
		t.Fatal("AdminUploadsBucketPolicy is gone; the bucket must refuse requests that are not over TLS")
	}
	if policy.condition != "AdminUploadsEnabled" {
		t.Errorf("AdminUploadsBucketPolicy Condition = %q, want AdminUploadsEnabled, the bucket's own switch", policy.condition)
	}
	for _, want := range []string{"Effect: Deny", "aws:SecureTransport: 'false'", "${AdminUploadsBucket.Arn}/*"} {
		if !strings.Contains(policy.body, want) {
			t.Errorf("AdminUploadsBucketPolicy lacks %q", want)
		}
	}
	if strings.Contains(policy.body, "Effect: Allow") {
		t.Error("AdminUploadsBucketPolicy grants something; the function's access comes from its role, and the bucket policy only denies")
	}
}

// ── the admin console's variables and grants follow its switch ──────────────

// TestTheRootUserFollowsTheConsoleSwitch is the enforcement half of the
// comment above HasAdminRootPasswordHash: the two root-user variables and the
// IAM read of the hash exist only with the console on. Before it, a stack with
// EnableAdminConsole=false and a root user configured still fetched the hash
// at every cold start and held a GetSecretValue grant for a console it did
// not mount, against two comments that said otherwise.
func TestTheRootUserFollowsTheConsoleSwitch(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")

	i := strings.Index(body, "HasAdminRootPasswordHash: !And")
	if i < 0 {
		t.Fatal("HasAdminRootPasswordHash is gone or no longer an !And")
	}
	condition := body[i:]
	if j := strings.Index(condition, "\n\n"); j > 0 {
		condition = condition[:j]
	}
	for _, want := range []string{"!Condition AdminConsoleEnabled", "!Condition HasAdminRootEmail", "AdminRootPasswordHashArn"} {
		if !strings.Contains(condition, want) {
			t.Errorf("HasAdminRootPasswordHash lacks the term %q:\n%s", want, condition)
		}
	}

	tpl := load(t)
	fn := tpl.resources["AuthFunction"]
	if fn == nil {
		t.Fatal("AuthFunction is gone")
	}
	for _, name := range []string{"AWESOME_AUTH_ADMIN_ROOT_EMAIL", "AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH_SECRETSMANAGER", "Sid: ReadAdminRootPasswordHash"} {
		k := strings.Index(fn.body, name)
		if k < 0 {
			t.Errorf("AuthFunction no longer carries %s", name)
			continue
		}
		// The condition sits within a few lines of the name, before it for the
		// IAM statement (`- !If` / `- HasAdminRootPasswordHash`) and after it
		// for a variable (`!If` / `- HasAdminRootPasswordHash`).
		lo, hi := k-200, k+200
		if lo < 0 {
			lo = 0
		}
		if hi > len(fn.body) {
			hi = len(fn.body)
		}
		if !strings.Contains(fn.body[lo:hi], "HasAdminRootPasswordHash") {
			t.Errorf("%s is not conditioned on HasAdminRootPasswordHash, so it outlives the console switch:\n%s", name, fn.body[lo:hi])
		}
	}
}

// TestTheConsoleParameterOffersOnlyTheFlagPolicy pins the two values that
// left AdminAccessPolicy's AllowedValues: `open` admits the world on a stack
// whose every front door is internet-facing, and `first-user` is refused at
// cold start on every driver (RS-17). Both stay in the schema so a family
// document parses and meets the warning or the refusal; neither is something
// this template should offer as a choice.
func TestTheConsoleParameterOffersOnlyTheFlagPolicy(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	param, ok := tpl.parameters["AdminAccessPolicy"]
	if !ok {
		t.Fatal("AdminAccessPolicy is gone")
	}
	if got := param.fields["AllowedValues"]; got != "[is-admin-flag]" {
		t.Errorf("AdminAccessPolicy AllowedValues = %s, want [is-admin-flag]: open and first-user are ConfigFile-only", got)
	}
	if got := param.fields["Default"]; got != "is-admin-flag" {
		t.Errorf("AdminAccessPolicy Default = %s, want is-admin-flag", got)
	}
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	if !strings.Contains(strings.ReplaceAll(string(raw), "\r\n", "\n"), "AdminConsoleNeedsSameSiteCookies:") {
		t.Error("the Rule refusing the console beside CookieSameSite none is gone (RS-18 at changeset time)")
	}
}

// ── what must never be committed ────────────────────────────────────────────

var (
	// An ARN with a real account id in it. The `\d{12}` inside an AllowedPattern
	// is a pattern and not a number, so it does not match.
	literalAccountArn = regexp.MustCompile(`arn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:`)
	// A default value carrying an address. Descriptions are prose and may say
	// "an email address"; a Default is a value that ships.
	defaultLine = regexp.MustCompile(`^\s+Default:\s*(.+)$`)
)

// TestNoAccountIdArnOrAddressIsCommitted guards the one class of mistake this
// template is structurally exposed to: every one of these values has a natural
// place to go here — an alarm's notification target above all — and each of them
// is a parameter with an empty default for exactly that reason.
func TestNoAccountIdArnOrAddressIsCommitted(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")

	for i, line := range lines {
		where := fmt.Sprintf("%s:%d", templateFile, i+1)
		if m := literalAccountArn.FindString(line); m != "" {
			t.Errorf("%s commits an ARN with an account id in it (%q). Every ARN here is a parameter "+
				"with an empty default:\n%s", where, m, line)
		}
		if m := defaultLine.FindStringSubmatch(line); m != nil {
			if strings.Contains(m[1], "@") {
				t.Errorf("%s has an address in a parameter default. AlarmEmail, MailerFromAddress and "+
					"every other address-shaped knob defaults to empty:\n%s", where, line)
			}
		}
	}
}

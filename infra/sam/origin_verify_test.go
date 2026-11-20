package sam

import (
	"os"
	"strings"
	"testing"
)

// TestOriginVerifyIsWiredToBothFunctions pins how the template reaches
// http.originVerify: the three parameters, one condition that is the switch for
// everything, the same three variables on both functions — each absent unless a
// secret is named, because the function refuses a header or an exemption set
// without one, and an unconditional line would refuse every existing stack on
// upgrade — and a read of that one secret on both roles, selector stripped.
func TestOriginVerifyIsWiredToBothFunctions(t *testing.T) {
	t.Parallel()
	tpl := load(t)

	for name, want := range map[string]map[string]string{
		"OriginVerifySecretArn": {
			"Default":        "''",
			"AllowedPattern": `'^$|^arn:[a-z0-9-]+:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:.+$'`,
		},
		"OriginVerifyHeader":        {"Default": "X-Origin-Verify"},
		"OriginVerifyExemptHealthz": {"Default": "'false'", "AllowedValues": "['true', 'false']"},
	} {
		p, ok := tpl.parameters[name]
		if !ok {
			t.Errorf("parameter %s is gone", name)
			continue
		}
		for field, v := range want {
			if got := p.fields[field]; got != v {
				t.Errorf("%s %s = %s, want %s", name, field, got, v)
			}
		}
	}
	if got := tpl.conditions["HasOriginVerify"]; got != "!Not [!Equals [!Ref OriginVerifySecretArn, '']]" {
		t.Errorf("HasOriginVerify = %q, want the secret ARN as the switch", got)
	}

	want := map[string]string{
		"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN":     "AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN: !If [HasOriginVerify, !Ref OriginVerifySecretArn, !Ref 'AWS::NoValue']",
		"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER":         "AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER: !If [HasOriginVerify, !Ref OriginVerifyHeader, !Ref 'AWS::NoValue']",
		"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_EXEMPT_HEALTHZ": "AWESOME_AUTH_HTTP_ORIGIN_VERIFY_EXEMPT_HEALTHZ: !If [HasOriginVerify, !Ref OriginVerifyExemptHealthz, !Ref 'AWS::NoValue']",
	}
	for _, fn := range []string{"AuthFunction", "SseFunction"} {
		r := tpl.resources[fn]
		if r == nil {
			t.Fatalf("%s is gone", fn)
		}
		env := envBlocks(t, r)
		for name, def := range want {
			if got := env[name]; got != def {
				t.Errorf("%s's %s is\n%s\nwant\n%s", fn, name, got, def)
			}
		}
		i := strings.Index(r.body, "Sid: ReadOriginVerifySecret")
		if i < 0 {
			t.Errorf("%s's role cannot read the origin-verification secret", fn)
			continue
		}
		before, stmt := r.body[:i], r.body[i:]
		if end := strings.Index(stmt, "- !Ref 'AWS::NoValue'"); end >= 0 {
			stmt = stmt[:end]
		}
		for _, line := range []string{"secretsmanager:GetSecretValue", "!Select [0, !Split ['#', !Ref OriginVerifySecretArn]]"} {
			if !strings.Contains(stmt, line) {
				t.Errorf("%s's ReadOriginVerifySecret lacks %s", fn, line)
			}
		}
		if j := strings.LastIndex(before, "- !If"); j < 0 || !strings.HasPrefix(strings.TrimSpace(before[j+len("- !If"):]), "- HasOriginVerify") {
			t.Errorf("%s's ReadOriginVerifySecret is not under !If [HasOriginVerify, …]: a stack without the check would still hold the read", fn)
		}
	}
}

// TestOriginVerifyAndCloudFrontAreExclusiveIsARule: this stack's distribution
// does not send the header, so a stack with both on would refuse every request
// that came through it.
func TestOriginVerifyAndCloudFrontAreExclusiveIsARule(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	body := strings.ReplaceAll(string(raw), "\r\n", "\n")
	i := strings.Index(body, "\n  OriginVerifyAndCloudFrontAreExclusive:\n")
	if i < 0 {
		t.Fatal("the Rule OriginVerifyAndCloudFrontAreExclusive is gone")
	}
	rule := body[i+1:]
	if j := strings.Index(rule, "\n\n"); j > 0 {
		rule = rule[:j]
	}
	for _, want := range []string{
		"RuleCondition: !Not [!Equals [!Ref OriginVerifySecretArn, '']]",
		"- Assert: !Equals [!Ref EnableCloudFront, 'false']",
	} {
		if !strings.Contains(rule, want) {
			t.Errorf("OriginVerifyAndCloudFrontAreExclusive lacks %q:\n%s", want, rule)
		}
	}
}

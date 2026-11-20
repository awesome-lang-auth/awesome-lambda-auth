package config

import (
	"strings"
	"testing"
)

// A secret ARN in the shape the template's AllowedPattern and
// validateOriginVerify accept. The account id is a documentation placeholder.
const testOriginVerifyARN = "arn:aws:secretsmanager:eu-west-1:123456789012:secret:auth/origin-verify-AbCdEf"

// TestOriginVerifyIsOffByDefault pins the backward-compatible default: no
// secret, the default header name, no exemption, and a document that never
// mentions the block loads exactly as it did before the block existed.
func TestOriginVerifyIsOffByDefault(t *testing.T) {
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	ov := cfg.HTTP.OriginVerify
	if ov.Enabled() || ov.SecretARN != "" || ov.ExemptHealthz || ov.Header != DefaultOriginVerifyHeader {
		t.Errorf("http.originVerify defaults = %+v, want off with header %s", ov, DefaultOriginVerifyHeader)
	}
}

// TestOriginVerifyLoadsFromEitherSource: the document form and the three
// AWESOME_AUTH_HTTP_ORIGIN_VERIFY_* variables reach the same fields, the
// environment wins over the document as it does for every knob, and the two
// strings are trimmed before anything compares them.
func TestOriginVerifyLoadsFromEitherSource(t *testing.T) {
	t.Run("document", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "http.originVerify.secretArn", " "+testOriginVerifyARN+"#value ")
		set(doc, "http.originVerify.header", " X-Edge-Secret ")
		set(doc, "http.originVerify.exemptHealthz", true)
		cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		want := OriginVerify{Header: "X-Edge-Secret", SecretARN: testOriginVerifyARN + "#value", ExemptHealthz: true}
		if cfg.HTTP.OriginVerify != want || !cfg.HTTP.OriginVerify.Enabled() {
			t.Errorf("http.originVerify = %+v, want %+v", cfg.HTTP.OriginVerify, want)
		}
	})
	t.Run("environment over the document", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "http.originVerify.header", "X-From-The-Document")
		env := baseEnv()
		env["AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN"] = testOriginVerifyARN
		env["AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER"] = "X-From-The-Environment"
		env["AWESOME_AUTH_HTTP_ORIGIN_VERIFY_EXEMPT_HEALTHZ"] = "true"
		cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		want := OriginVerify{Header: "X-From-The-Environment", SecretARN: testOriginVerifyARN, ExemptHealthz: true}
		if cfg.HTTP.OriginVerify != want {
			t.Errorf("http.originVerify = %+v, want %+v", cfg.HTTP.OriginVerify, want)
		}
		if got := cfg.Source("http.originVerify.header"); got != "AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER" {
			t.Errorf("source of http.originVerify.header = %q, want the variable", got)
		}
	})
	t.Run("an empty header asks for the default", func(t *testing.T) {
		env := baseEnv()
		env["AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN"] = testOriginVerifyARN
		env["AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER"] = "  "
		cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg.HTTP.OriginVerify.Header != DefaultOriginVerifyHeader {
			t.Errorf("header = %q, want the default", cfg.HTTP.OriginVerify.Header)
		}
	})
}

// TestOriginVerifyRefusesWhatWouldCheckNothing: each refusal names its path and
// a remedy. A header or an exemption written without a secret is the case that
// matters most — the operator believes the origin is checked and it is not —
// and it is refused by source, so writing the default header name explicitly
// is refused too.
func TestOriginVerifyRefusesWhatWouldCheckNothing(t *testing.T) {
	for _, tc := range []struct {
		name string
		doc  map[string]any
		env  map[string]string
		path string
		want string
	}{
		{
			name: "header without a secret",
			doc:  map[string]any{"http.originVerify.header": "X-Edge-Secret"},
			path: "http.originVerify.header", want: "secretArn is not",
		},
		{
			name: "the default header written out without a secret",
			env:  map[string]string{"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER": DefaultOriginVerifyHeader},
			path: "http.originVerify.header", want: "secretArn is not",
		},
		{
			name: "exemption without a secret",
			doc:  map[string]any{"http.originVerify.exemptHealthz": true},
			path: "http.originVerify.exemptHealthz", want: "secretArn is not",
		},
		{
			name: "a secret name instead of an ARN",
			doc:  map[string]any{"http.originVerify.secretArn": "auth/origin-verify"},
			path: "http.originVerify.secretArn", want: "not a Secrets Manager secret ARN",
		},
		{
			name: "an ARN of another service",
			doc:  map[string]any{"http.originVerify.secretArn": "arn:aws:ssm:eu-west-1:123456789012:parameter/origin"},
			path: "http.originVerify.secretArn", want: "not a Secrets Manager secret ARN",
		},
		{
			name: "an empty selector",
			doc:  map[string]any{"http.originVerify.secretArn": testOriginVerifyARN + "#"},
			path: "http.originVerify.secretArn", want: "not a Secrets Manager secret ARN",
		},
		{
			name: "a header name that is not a token",
			doc:  map[string]any{"http.originVerify.secretArn": testOriginVerifyARN, "http.originVerify.header": "X Origin Verify"},
			path: "http.originVerify.header", want: "not a valid HTTP header name",
		},
		{
			name: "a header the auth surface reads",
			doc:  map[string]any{"http.originVerify.secretArn": testOriginVerifyARN, "http.originVerify.header": "authorization"},
			path: "http.originVerify.header", want: "a header the auth surface reads",
		},
		{
			name: "the client address the limiter keys on",
			env:  map[string]string{"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN": testOriginVerifyARN, "AWESOME_AUTH_HTTP_ORIGIN_VERIFY_HEADER": "X-Forwarded-For"},
			path: "http.originVerify.header", want: "a header the auth surface reads",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			for path, v := range tc.doc {
				set(doc, path, v)
			}
			env := baseEnv()
			for k, v := range tc.env {
				env[k] = v
			}
			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			d := requireRule(t, err, "", tc.path)
			if !strings.Contains(d.Problem, tc.want) {
				t.Errorf("problem = %q, want it to say %q", d.Problem, tc.want)
			}
		})
	}
}

// TestOriginVerifyAcceptsTheShapesItDocuments: a bare ARN, one with a JSON
// selector, a GovCloud partition, and any header name that is a token and not
// reserved.
func TestOriginVerifyAcceptsTheShapesItDocuments(t *testing.T) {
	for _, tc := range []struct{ arn, header string }{
		{testOriginVerifyARN, ""},
		{testOriginVerifyARN + "#headerValue", "X-Edge-Secret"},
		{"arn:aws-us-gov:secretsmanager:us-gov-west-1:123456789012:secret:origin+verify=1@edge.v2-xYz123", "x-cdn-token"},
	} {
		doc := baseDoc()
		set(doc, "http.originVerify.secretArn", tc.arn)
		if tc.header != "" {
			set(doc, "http.originVerify.header", tc.header)
		}
		if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())}); err != nil {
			t.Errorf("secretArn %q, header %q: Load refused it:\n%v", tc.arn, tc.header, err)
		}
	}
}

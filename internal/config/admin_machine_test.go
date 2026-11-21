package config

import (
	"strings"
	"testing"
)

// admin.machineAccess.iam.principals: who may call the admin API with no
// session, on a credential API Gateway verified. cmd/auth/admin_machine.go
// does the matching; what is pinned here is what the loader accepts.

func consoleDoc() Document {
	doc := baseDoc()
	set(doc, "admin.enabled", true)
	set(doc, "admin.accessPolicy", "is-admin-flag")
	return doc
}

func TestAdminMachineAccessIsOffByDefault(t *testing.T) {
	cfg, err := Load(t.Context(), Options{Document: consoleDoc(), Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Admin.MachineAccess.Enabled() || cfg.Admin.MachineAccess.IAM.Principals != nil {
		t.Errorf("machine access is on with nothing configured: %+v", cfg.Admin.MachineAccess)
	}
}

func TestAdminMachineAccessLoadsFromEitherSource(t *testing.T) {
	const role = "arn:aws:iam::123456789012:role/service/identity-service"
	const user = "arn:aws:iam::123456789012:user/ops/backfill"

	doc := consoleDoc()
	set(doc, "admin.machineAccess.iam.principals", []any{role})
	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load from the document: %v", err)
	}
	if got := cfg.Admin.MachineAccess.IAM.Principals; len(got) != 1 || got[0] != role {
		t.Errorf("principals from the document = %v", got)
	}

	env := baseEnv()
	env["AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS"] = " " + role + " , " + user + ","
	cfg, err = Load(t.Context(), Options{Document: consoleDoc(), Getenv: getenvFrom(env)})
	if err != nil {
		t.Fatalf("load from the variable: %v", err)
	}
	if got := strings.Join(cfg.Admin.MachineAccess.IAM.Principals, "|"); got != role+"|"+user {
		t.Errorf("principals from the variable = %q, want both, trimmed, the trailing comma dropped", got)
	}
	if got := cfg.Source("admin.machineAccess.iam.principals"); got != "AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS" {
		t.Errorf("source = %q", got)
	}
}

// TestAdminMachineAccessRefusesWhatItCannotRead: every entry is a role or user
// ARN, and the near-misses an operator actually writes are refused by name;
// the block is refused without a console to admit anyone to.
func TestAdminMachineAccessRefusesWhatItCannotRead(t *testing.T) {
	const path = "admin.machineAccess.iam.principals"
	cases := []struct {
		name       string
		principals []any
		noConsole  bool
		wantPath   string
		wantText   string
	}{
		{"a role session copied from a log line", []any{"arn:aws:sts::123456789012:assumed-role/identity-service/1795000000"}, false, path + "[0]", "session name"},
		{"the account's root user", []any{"arn:aws:iam::123456789012:root"}, false, path + "[0]", "root user"},
		{"a wildcard", []any{"arn:aws:iam::123456789012:role/*"}, false, path + "[0]", "wildcard"},
		{"an empty entry", []any{""}, false, path + "[0]", "wildcard"},
		{"a role name with no ARN", []any{"identity-service"}, false, path + "[0]", "not an IAM role or user ARN"},
		{"a group", []any{"arn:aws:iam::123456789012:group/admins"}, false, path + "[0]", "not an IAM role or user ARN"},
		{"an account id that is not one", []any{"arn:aws:iam::12345:role/identity-service"}, false, path + "[0]", "not an IAM role or user ARN"},
		{"a federated user", []any{"arn:aws:sts::123456789012:federated-user/ops"}, false, path + "[0]", "not an IAM role or user ARN"},
		{
			"one role twice, with and without its path",
			[]any{"arn:aws:iam::123456789012:role/service/identity-service", "arn:aws:iam::123456789012:role/identity-service"},
			false, path + "[1]", "already names",
		},
		{"principals with the console off", []any{"arn:aws:iam::123456789012:role/identity-service"}, true, path, "admin.enabled is off"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := consoleDoc()
			if tc.noConsole {
				doc = baseDoc()
			}
			set(doc, "admin.machineAccess.iam.principals", tc.principals)
			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			d := requireRule(t, err, "", tc.wantPath)
			if !strings.Contains(d.Error(), tc.wantText) {
				t.Errorf("the diagnostic does not say %q:\n%s", tc.wantText, d.Error())
			}
		})
	}
}

// TestAdminMachineAccessAcceptsTheShapesItDocuments: roles and users, with and
// without a path, in any partition.
func TestAdminMachineAccessAcceptsTheShapesItDocuments(t *testing.T) {
	doc := consoleDoc()
	set(doc, "admin.machineAccess.iam.principals", []any{
		"arn:aws:iam::123456789012:role/identity-service",
		"arn:aws:iam::123456789012:role/service/team/backfill-runner",
		"arn:aws:iam::210987654321:role/identity-service",
		"arn:aws:iam::123456789012:user/ops",
		"arn:aws-cn:iam::123456789012:role/identity-service",
		"arn:aws:iam::123456789012:role/name+with=all,the.@chars_-",
	})
	if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())}); err != nil {
		t.Fatalf("the documented shapes must load:\n%v", err)
	}
}

// TestIAMPrincipalKey pins the identity the match is made on, for a configured
// ARN and for the caller ARN API Gateway reports.
func TestIAMPrincipalKey(t *testing.T) {
	for arn, want := range map[string]string{
		"arn:aws:iam::123456789012:role/identity-service":                   "role:aws:123456789012:identity-service",
		"arn:aws:iam::123456789012:role/service/identity-service":           "role:aws:123456789012:identity-service",
		"arn:aws:sts::123456789012:assumed-role/identity-service/session-1": "role:aws:123456789012:identity-service",
		"arn:aws-us-gov:sts::123456789012:assumed-role/identity-service/s":  "role:aws-us-gov:123456789012:identity-service",
		"arn:aws:iam::123456789012:user/ops/backfill":                       "user:arn:aws:iam::123456789012:user/ops/backfill",
		"arn:aws:iam::123456789012:root":                                    "",
		"arn:aws:iam::123456789012:group/admins":                            "",
		"arn:aws:sts::123456789012:assumed-role/identity-service":           "",
		"arn:aws:sts::123456789012:assumed-role/identity-service/has space": "",
		"arn:aws:sts::123456789012:federated-user/ops":                      "",
		"arn:aws:iam::123456789012:role/":                                   "",
		"arn:aws:iam:eu-west-1:123456789012:role/identity-service":          "",
		"arn:aws:iam::1234567890ab:role/identity-service":                   "",
		"": "",
	} {
		got, ok := IAMPrincipalKey(arn)
		if got != want || ok != (want != "") {
			t.Errorf("IAMPrincipalKey(%q) = %q, %v; want %q", arn, got, ok, want)
		}
	}
}

package config

import (
	"strconv"
	"strings"
	"testing"
)

// TestConfiguringAnUnwiredDomainIsRefused is the promise that an operator who
// configures something that does nothing gets told. Each case touches one domain
// that P1 validates but does not act on; none of them may load silently.
func TestConfiguringAnUnwiredDomainIsRefused(t *testing.T) {
	cases := []struct {
		domain string
		mutate func(Document)
	}{
		{"tools", func(doc Document) {
			set(doc, "tools.basePath", "/ops")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.domain, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)

			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			d := requireRule(t, err, RuleUnimplemented, tc.domain)
			if !strings.Contains(d.Error(), "not yet wired") {
				t.Errorf("diagnostic does not say the block is inert:\n%s", d.Error())
			}
			if !strings.Contains(d.Error(), "P") {
				t.Errorf("diagnostic does not name the phase that wires it:\n%s", d.Error())
			}
		})
	}
}

// TestUnwiredDomainViaEnvIsAlsoRefused: the phase gap is detected on the layered
// result, so an override supplied through the environment counts exactly as much
// as one written in the document.
//
// It used to say this with AWESOME_AUTH_UI_ENABLED, and moved to the tools
// block when `ui` was wired. The domain is incidental — what is under test is
// that the environment layer is compared like the document layer — but a test
// naming a wired domain would assert nothing at all, so the move is the point
// rather than a rename.
func TestUnwiredDomainViaEnvIsAlsoRefused(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_TOOLS_BASE_PATH"] = "/ops"

	_, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
	requireRule(t, err, RuleUnimplemented, "tools")
}

// TestUnwiredDomainViaSecretIsAlsoRefused: a secret supplied through its
// documented variable leaves no trace in the Config tree, so the check also looks
// at what actually resolved.
//
// The SSE distributor's password stands in for what used to be the admin
// bootstrap secret here, which stood in for idProvider.privateKey before it:
// both of those domains are wired now, and this test needs a domain that still
// has a secretPrefix. `tools` is the last one, and its only secret is this one.
// TestAdminIsWired holds the other side — the bootstrap secret through the same
// kind of variable loads, because it is read.
func TestUnwiredDomainViaSecretIsAlsoRefused(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_TOOLS_SSE_DISTRIBUTOR_PASSWORD"] = "sse-distributor-password-value"

	_, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
	requireRule(t, err, RuleUnimplemented, "tools")
}

// TestRuntimeSettingsIsWired is the other side of the refusal table for the
// domain this block opened: a document that seeds the runtime-mutable layer
// loads instead of tripping the phase gap.
//
// Each case declares the store alongside the seed, because the schema requires
// them together (checkStoreRequirements) — so this also pins that un-gating
// relaxed nothing, and in particular that the widened requirement still fires
// for the two shapes the old one missed. What cmd/auth then does with the seed
// is its own tests' business.
func TestRuntimeSettingsIsWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
	}{
		{"require2fa", func(doc Document) {
			set(doc, "runtimeSettings.require2fa", true)
		}},
		{"a webhook allowlist", func(doc Document) {
			set(doc, "runtimeSettings.enabledWebhookActions", []any{"user.created"})
		}},
		{"an explicitly cleared webhook allowlist", func(doc Document) {
			set(doc, "runtimeSettings.enabledWebhookActions", []any{})
		}},
		{"the grace period alone", func(doc Document) {
			set(doc, "runtimeSettings.lazyEmailVerificationGracePeriodDays", 14)
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			set(doc, "stores.enable.settings", true)
			tc.mutate(doc)

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			if err != nil {
				t.Fatalf("runtimeSettings is wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if w.Path == "runtimeSettings" && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("runtimeSettings is still reported as an unwired domain: %s", w.Problem)
				}
			}
			if _, gated := UnwiredDomains()["runtimeSettings"]; gated {
				t.Error("runtimeSettings is still listed by UnwiredDomains")
			}
		})
	}

	// The seed still needs somewhere to go: without the store every one of those
	// documents is refused by name, including the two the narrower rule used to
	// miss (rules_test.go has those two directly).
	t.Run("without the store", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "runtimeSettings.require2fa", true)

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		requireRule(t, err, RuleStoreRequired, "stores.enable.settings")
	})
}

// TestDocsIsWired is the other side of the refusal table for the domain this
// block opened: a document that configures the documentation surface loads
// instead of tripping the phase gate.
//
// Both spellings of the switch are here, and `false` matters as much as `true`.
// It is the value an operator writes to turn the surface off — the one thing the
// gate made impossible to say, since saying it was itself a configured domain —
// and it is the value the old refusal case in the table above used.
//
// Neither knob needs a store, which is what makes this block unlike
// runtimeSettings: the whole surface is two routes the imported adapter mounts,
// so there is nothing to persist and nothing to refuse for a driver that lacks
// it. What cmd/auth then does with the block is its own tests' business.
func TestDocsIsWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
	}{
		{"the surface switched off", func(doc Document) {
			set(doc, "docs.swagger", "false")
		}},
		{"the surface switched on", func(doc Document) {
			set(doc, "docs.swagger", "true")
		}},
		{"auto stated explicitly", func(doc Document) {
			set(doc, "docs.swagger", "auto")
		}},
		{"a base path of its own", func(doc Document) {
			set(doc, "docs.basePath", "/public/api/auth")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			if err != nil {
				t.Fatalf("docs is wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if w.Path == "docs" && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("docs is still reported as an unwired domain: %s", w.Problem)
				}
			}
			if _, gated := UnwiredDomains()["docs"]; gated {
				t.Error("docs is still listed by UnwiredDomains")
			}
		})
	}
}

// TestUIIsWired is the other side of the refusal table for the domain this block
// opened: a document that configures the hosted UI loads instead of tripping the
// phase gate.
//
// Every case here is a knob that used to be enough to refuse a deployment on its
// own, which is what the gate did and why it had to go before the block could be
// used. `false` is in the table for the reason it was in TestDocsIsWired's: it is
// the value an operator writes to say the surface is deliberately off, and the
// gate made saying it impossible, because saying it was itself a configured
// domain.
//
// The block needs no store of its own, which is what makes it unlike
// runtimeSettings: the branding the UI *reads* from a settings store is
// optional, and with no store configured the core serves the static branding
// exactly as the reference serves its empty settings object. So there is nothing
// for checkStoreRequirements to insist on and nothing here that should refuse.
// What cmd/auth then does with the block — including the one refusal it adds,
// for an assetsDir that cannot render a page — is its own tests' business.
func TestUIIsWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
	}{
		{"the surface switched on", func(doc Document) {
			set(doc, "ui.enabled", true)
		}},
		{"the surface switched off deliberately", func(doc Document) {
			set(doc, "ui.enabled", false)
		}},
		{"branding alone", func(doc Document) {
			set(doc, "ui.branding.siteName", "Example")
			set(doc, "ui.branding.primaryColor", "#112233")
		}},
		{"headless, with no pages served", func(doc Document) {
			set(doc, "ui.enabled", true)
			set(doc, "ui.headless", true)
		}},
		{"an asset directory of its own", func(doc Document) {
			set(doc, "ui.enabled", true)
			set(doc, "ui.assetsDir", "/var/task/ui")
		}},
		// The name said "accepted and not honoured" until the admin block: the
		// knob names an S3 location now, and this filesystem spelling still loads
		// — a family document has to — and is reported at cold start instead.
		{"an upload directory in the filesystem spelling, which loads and is reported", func(doc Document) {
			set(doc, "ui.uploadDir", "/var/task/uploads")
		}},
		{"an upload location in the S3 spelling", func(doc Document) {
			set(doc, "ui.uploadDir", "s3://example-uploads/uploads")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			if err != nil {
				t.Fatalf("ui is wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if w.Path == "ui" && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("ui is still reported as an unwired domain: %s", w.Problem)
				}
			}
			if _, gated := UnwiredDomains()["ui"]; gated {
				t.Error("ui is still listed by UnwiredDomains")
			}
		})
	}
}

// TestAdminIsWired is the other side of the refusal table for the domain this
// block opened: a document that configures the admin console loads instead of
// tripping the phase gate.
//
// Every case is something that used to refuse a deployment on its own, and one
// of them is not in the document at all. `admin` was the last wired domain to
// carry a secretPrefix: a bootstrap secret supplied through its documented
// variable leaves no trace in the Config tree, the prefix was what noticed it,
// and the case that supplies nothing else is what shows the prefix went with the
// entry rather than outliving it. `admin.basePath` is here because it was the
// refusal table's own admin case until this commit, and `false` for the reason
// it is in TestDocsIsWired and TestUIIsWired: the gate made a deliberately-off
// console impossible to write down.
//
// Un-gating relaxed nothing, and the sub-tests after the table pin that. The
// block has refusals of its own which the gate used to pre-empt, so they were
// unreachable without AllowUnimplemented and are the block's real front door
// now: RS-6 for an enabled console with no access decision — the reference
// builds that router, warns on stderr and serves it unguarded
// (admin.router.ts:516-537) — RS-17 for `first-user` on every driver and RS-10
// for it on a driver that cannot list at all, RS-18 for a session console
// beside cookies.sameSite: none, the store requirement behind the two RBAC
// spellings of the policy, and the enum the policy is held to. What cmd/auth
// then builds out of the block is its own tests' business (admin_test.go).
func TestAdminIsWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
		env    map[string]string
	}{
		{name: "the console switched off deliberately", mutate: func(doc Document) {
			set(doc, "admin.enabled", false)
		}},
		{name: "mounted under is-admin-flag", mutate: func(doc Document) {
			set(doc, "admin.enabled", true)
			set(doc, "admin.accessPolicy", "is-admin-flag")
		}},
		{name: "mounted under a role, with the rbac store beside it", mutate: func(doc Document) {
			set(doc, "stores.enable.rbac", true)
			set(doc, "admin.enabled", true)
			set(doc, "admin.accessPolicy", "rbac:admin")
		}},
		{name: "mounted under a permission, with the rbac store beside it", mutate: func(doc Document) {
			set(doc, "stores.enable.rbac", true)
			set(doc, "admin.enabled", true)
			set(doc, "admin.accessPolicy", "permission:console.access")
		}},
		{name: "a base path of its own", mutate: func(doc Document) {
			set(doc, "admin.basePath", "/console")
		}},
		{name: "a root user's address", mutate: func(doc Document) {
			set(doc, "admin.rootUser.email", "root@example.test")
		}},
		{name: "the two knobs that reach constants in the core", mutate: func(doc Document) {
			set(doc, "admin.sessionTtl", "8h")
			set(doc, "admin.upload.maxFileSizeMb", 10)
		}},
		{
			name:   "a bootstrap secret through its variable and nothing in the document",
			mutate: func(Document) {},
			env:    map[string]string{"AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET": "admin-bootstrap-secret-value-0123456789"},
		},
		{
			name: "mounted on the bootstrap secret alone, which RS-6 accepts as the guard",
			mutate: func(doc Document) {
				set(doc, "admin.enabled", true)
			},
			env: map[string]string{"AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET": "admin-bootstrap-secret-value-0123456789"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)
			env := baseEnv()
			for k, v := range tc.env {
				env[k] = v
			}

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if err != nil {
				t.Fatalf("admin is wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if w.Path == "admin" && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("admin is still reported as an unwired domain: %s", w.Problem)
				}
			}
			if _, gated := UnwiredDomains()["admin"]; gated {
				t.Error("admin is still listed by UnwiredDomains")
			}
		})
	}

	t.Run("enabled with no access decision", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "admin.enabled", true)

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		requireRule(t, err, RuleAdminUnguarded, "admin.accessPolicy")
	})

	t.Run("a role policy without the rbac store", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "admin.enabled", true)
		set(doc, "admin.accessPolicy", "rbac:admin")

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		requireRule(t, err, RuleStoreRequired, "stores.enable.rbac")
	})

	t.Run("a policy outside the five spellings", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "admin.enabled", true)
		set(doc, "admin.accessPolicy", "everyone")

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		if err == nil {
			t.Fatal("an access policy the schema does not know loaded")
		}
		if !strings.Contains(err.Error(), "admin.accessPolicy") {
			t.Errorf("the refusal does not name admin.accessPolicy:\n%v", err)
		}
	})

	// first-user, on the un-gated front door and without AllowUnimplemented:
	// RS-17 on every driver, because ids are random here and "first" is
	// whoever drew the lowest one, and RS-10 beside it on a driver that cannot
	// list at all. The table used to load this policy as a wired one; it is
	// wired, and refused.
	t.Run("first-user on a driver that can list users", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "admin.enabled", true)
		set(doc, "admin.accessPolicy", "first-user")

		_, err := Load(t.Context(), Options{
			Document:     doc,
			Getenv:       getenvFrom(baseEnv()),
			Capabilities: func(string) StoreCapabilities { return StoreCapabilities{ListUsers: true} },
		})
		requireRule(t, err, RuleFirstUserRandomIDs, "admin.accessPolicy")
		requireNoRule(t, err, RuleFirstUserListUsers)
	})

	t.Run("first-user on a driver that cannot list users", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "admin.enabled", true)
		set(doc, "admin.accessPolicy", "first-user")

		_, err := Load(t.Context(), Options{
			Document:     doc,
			Getenv:       getenvFrom(baseEnv()),
			Capabilities: func(string) StoreCapabilities { return StoreCapabilities{ListUsers: false} },
		})
		requireRule(t, err, RuleFirstUserListUsers, "admin.accessPolicy")
		requireRule(t, err, RuleFirstUserRandomIDs, "admin.accessPolicy")
	})

	t.Run("a session console beside sameSite none", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "admin.enabled", true)
		set(doc, "admin.accessPolicy", "is-admin-flag")
		set(doc, "cookies.sameSite", "none")
		set(doc, "cookies.secure", true)

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		requireRule(t, err, RuleAdminCrossSiteCookie, "cookies.sameSite")
	})
}

// TestAllowUnimplementedDowngradesToWarning: the gap stays visible in the
// deployment log, it just no longer refuses. It must never become silence.
func TestAllowUnimplementedDowngradesToWarning(t *testing.T) {
	doc := baseDoc()
	set(doc, "tools.basePath", "/ops")

	cfg, err := Load(t.Context(), Options{
		Document:           doc,
		Getenv:             getenvFrom(baseEnv()),
		AllowUnimplemented: true,
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	for _, w := range cfg.Warnings() {
		if w.Path == "tools" && strings.Contains(w.Problem, "not yet wired") {
			return
		}
	}
	t.Errorf("the phase gap disappeared instead of becoming a warning; warnings: %v", cfg.Warnings())
}

// TestWiredDomainsAreNotFlagged: the whole point of the P1 scope is that these
// domains work, so configuring them must not trip the phase-gap check.
func TestWiredDomainsAreNotFlagged(t *testing.T) {
	doc := baseDoc()
	set(doc, "cookies.secure", true)
	set(doc, "cookies.sameSite", "none")
	set(doc, "security.csrf.enabled", true)
	set(doc, "security.jwt.accessTokenTtl", "10m")
	set(doc, "security.password.bcryptSaltRounds", 13)
	set(doc, "sessions.checkOn", "allcalls")
	set(doc, "tokens.magicLinkTtlMinutes", 30)
	set(doc, "email.verification.mode", "strict")
	set(doc, "http.apiPrefix", "/identity")
	set(doc, "stores.enable.metadata", true)
	set(doc, "deployment.stage", "prod")

	cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("every knob here is in the P1 scope, so this must load:\n%v", err)
	}
	if cfg.Email.Verification.Mode != EmailVerificationStrict {
		t.Errorf("email.verification.mode = %q, want strict", cfg.Email.Verification.Mode)
	}
}

// TestDeliveryDomainsAreWired is the other side of the refusal table: the two
// blocks that select a credential transport must now load, because a deployment
// that configures them gets mail and text messages rather than a phase error.
//
// Both are written the way the schema requires them — email.mailer needs an
// endpoint and a from address together, sms needs an endpoint — so this also
// pins that un-gating did not quietly relax the block's own validation. What
// the AWS transports then do with the endpoint is cmd/auth's unwiredKnobs
// problem, not this package's.
func TestDeliveryDomainsAreWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
	}{
		{"email.mailer", func(doc Document) {
			set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
			set(doc, "email.mailer.from", "no-reply@example.com")
			set(doc, "email.mailer.fromName", "Example")
			set(doc, "email.mailer.defaultLang", "it")
		}},
		{"sms", func(doc Document) {
			set(doc, "sms.endpoint", "https://sms.example.com/send")
			set(doc, "sms.codeTtlMinutes", 5)
		}},
		{"both together", func(doc Document) {
			set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
			set(doc, "email.mailer.from", "no-reply@example.com")
			set(doc, "sms.endpoint", "https://sms.example.com/send")
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
			if err != nil {
				t.Fatalf("the delivery blocks are wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if (w.Path == "email.mailer" || w.Path == "sms") && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("%s is still reported as an unwired domain: %s", w.Path, w.Problem)
				}
			}
		})
	}
}

// TestDeliverySecretsNoLongerTripThePhaseGap: a secret supplied through its
// documented environment variable leaves no trace in the Config tree, so the
// phase check looks at resolved secrets too. Both delivery blocks had a
// secretPrefix, and removing the domains has to remove that half as well —
// otherwise an operator who puts the SMS credentials in Secrets Manager gets a
// refusal for a block that works.
func TestDeliverySecretsNoLongerTripThePhaseGap(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_MAILER_API_KEY"] = "mailer-api-key-value"
	env["AWESOME_AUTH_SMS_API_KEY"] = "sms-api-key-value"
	env["AWESOME_AUTH_SMS_USERNAME"] = "sms-user"
	env["AWESOME_AUTH_SMS_PASSWORD"] = "sms-pass"

	doc := baseDoc()
	set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
	set(doc, "email.mailer.from", "no-reply@example.com")
	set(doc, "sms.endpoint", "https://sms.example.com/send")

	if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)}); err != nil {
		t.Fatalf("delivery secrets must not reopen the phase gap:\n%v", err)
	}
}

// TestEmailFlowDomainsAreWired is the P2 counterpart of
// TestDeliveryDomainsAreWired: the three email-flow knobs the mailer left behind
// — the site-URL allowlist, the templates directory and the delivery webhook —
// load now instead of tripping the phase gap.
//
// Each is written the way the schema requires it, so the test also pins that
// un-gating relaxed nothing: the webhook needs its signing secret, the
// templates directory needs the store it seeds. What cmd/auth then does with
// them — resolve links, seed the store, post deliveries — is its own tests'
// business.
func TestEmailFlowDomainsAreWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
		env    func(map[string]string)
	}{
		{"email.siteUrls", func(doc Document) {
			set(doc, "email.siteUrls", []any{"https://app.example.com", "https://alt.example.com"})
		}, nil},
		{"email.templatesDir", func(doc Document) {
			set(doc, "email.templatesDir", "/var/task/templates")
			set(doc, "stores.enable.templates", true)
		}, nil},
		{"email.deliveryWebhook", func(doc Document) {
			set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook")
			set(doc, "email.deliveryWebhook.timeoutMs", 1500)
		}, func(env map[string]string) {
			env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = "delivery-webhook-signing-secret"
		}},
		{"all three together", func(doc Document) {
			set(doc, "email.siteUrls", []any{"https://app.example.com"})
			set(doc, "email.templatesDir", "/var/task/templates")
			set(doc, "stores.enable.templates", true)
			set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook")
		}, func(env map[string]string) {
			env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = "delivery-webhook-signing-secret"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)
			env := baseEnv()
			if tc.env != nil {
				tc.env(env)
			}

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if err != nil {
				t.Fatalf("the email-flow domains are wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if strings.HasPrefix(w.Path, "email.") && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("%s is still reported as an unwired domain: %s", w.Path, w.Problem)
				}
			}
			for _, path := range []string{"email.siteUrls", "email.templatesDir", "email.deliveryWebhook"} {
				if _, gated := UnwiredDomains()[path]; gated {
					t.Errorf("%s is still listed by UnwiredDomains", path)
				}
			}
		})
	}
}

// TestIdentityDomainsAreWired is the P5 counterpart: `idProvider` and
// `resourceServer` load instead of tripping the phase gap, in each of the three
// postures a deployment can take — a KMS signer, a PEM signer, and
// resource-server mode.
//
// Each block is written the way the schema requires it, so the test also pins
// that un-gating relaxed nothing: a client needs its secret and a redirect URI,
// resource-server mode needs an https JWKS URL (RS-8). What cmd/auth then does
// with them — mount the OIDC endpoints, publish the JWKS, verify a bearer
// against a remote issuer — is its own tests' business.
func TestIdentityDomainsAreWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
		env    func(map[string]string)
	}{
		{"idProvider with a KMS signer", func(doc Document) {
			set(doc, "idProvider.enabled", true)
			set(doc, "idProvider.kmsKeyId", "alias/awesome-auth-idp")
			set(doc, "idProvider.issuer", "https://auth.example.com/auth")
		}, nil},
		{"idProvider with a PEM signer", func(doc Document) {
			set(doc, "idProvider.enabled", true)
		}, func(env map[string]string) {
			env["AWESOME_AUTH_IDP_PRIVATE_KEY"] = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"
		}},
		{"idProvider with a client registry", func(doc Document) {
			set(doc, "idProvider.kmsKeyId", "alias/awesome-auth-idp")
			set(doc, "idProvider.kmsPreviousKeyIds", []any{"alias/awesome-auth-idp-2025"})
			set(doc, "idProvider.clients", []any{map[string]any{
				"clientId":     "console",
				"name":         "Ops console",
				"redirectUris": []any{"https://console.example.com/callback", "http://localhost:4200/callback"},
			}})
		}, func(env map[string]string) {
			env["AWESOME_AUTH_IDP_CLIENT_CONSOLE_SECRET"] = "console-client-secret"
		}},
		{"resourceServer", func(doc Document) {
			set(doc, "resourceServer.enabled", true)
			set(doc, "resourceServer.jwksUrl", "https://idp.example.com/.well-known/jwks.json")
			set(doc, "resourceServer.issuer", "https://idp.example.com")
			set(doc, "resourceServer.jwksCacheTtlMs", 60000)
		}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)
			env := baseEnv()
			if tc.env != nil {
				tc.env(env)
			}

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if err != nil {
				t.Fatalf("the identity domains are wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if (w.Path == "idProvider" || w.Path == "resourceServer") && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("%s is still reported as an unwired domain: %s", w.Path, w.Problem)
				}
			}
			for _, path := range []string{"idProvider", "resourceServer"} {
				if _, gated := UnwiredDomains()[path]; gated {
					t.Errorf("%s is still listed by UnwiredDomains", path)
				}
			}
		})
	}
}

// TestIdentitySecretsNoLongerTripThePhaseGap is the idProvider half of
// TestDeliverySecretsNoLongerTripThePhaseGap: the domain had a secretPrefix, and
// removing the domain has to remove that cover too, or an operator who puts the
// signing key in Secrets Manager gets a refusal for a block that works.
func TestIdentitySecretsNoLongerTripThePhaseGap(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_IDP_PRIVATE_KEY"] = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----"

	if _, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)}); err != nil {
		t.Fatalf("an idProvider secret must not reopen the phase gap:\n%v", err)
	}
}

// TestDeliveryWebhookRequiresItsSecret: the webhook is handed every minted
// credential, so a url without the secret that signs the requests is refused,
// and a secret without a url is refused as the dead configuration it is.
func TestDeliveryWebhookRequiresItsSecret(t *testing.T) {
	t.Run("url without a secret", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook")

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		d := requireRule(t, err, "", "email.deliveryWebhook.secret")
		if !strings.Contains(d.Remedy, "AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET") {
			t.Errorf("the remedy does not name the variable that supplies the secret:\n%s", d.Remedy)
		}
	})

	t.Run("secret reference without a url", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "email.deliveryWebhook.secret", map[string]any{"envVar": "MY_HOOK_SECRET"})
		env := baseEnv()
		env["MY_HOOK_SECRET"] = "delivery-webhook-signing-secret"

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		requireRule(t, err, "", "email.deliveryWebhook.url")
	})

	t.Run("a non-positive timeout", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook")
		set(doc, "email.deliveryWebhook.timeoutMs", 0)
		env := baseEnv()
		env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = "delivery-webhook-signing-secret"

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		requireRule(t, err, "", "email.deliveryWebhook.timeoutMs")
	})

	t.Run("a timeout past the ceiling", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook")
		set(doc, "email.deliveryWebhook.timeoutMs", maxWebhookTimeoutMs+1)
		env := baseEnv()
		env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = "delivery-webhook-signing-secret"

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		requireRule(t, err, "", "email.deliveryWebhook.timeoutMs")
	})

	// A refusal is written to CloudWatch, and this is the one URL knob in the
	// schema whose path may itself be a secret: a receiver that cannot verify an
	// HMAC signature is told to carry a capability token in the path instead,
	// which is why cmd/auth logs only the origin of it at cold start
	// (webhookOrigin). A diagnostic that echoed the whole value would undo that
	// for exactly the deployments most likely to produce one.
	t.Run("a refusal never echoes the receiver's path", func(t *testing.T) {
		const capability = "hunter2-capability-token"
		for _, tc := range []struct{ name, url string }{
			{"plain http", "http://delivery.example.com/hook/" + capability},
			{"not a URL at all", "delivery.example.com/hook/" + capability},
		} {
			t.Run(tc.name, func(t *testing.T) {
				doc := baseDoc()
				set(doc, "email.deliveryWebhook.url", tc.url)
				env := baseEnv()
				env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = "delivery-webhook-signing-secret"

				_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
				d := requireRule(t, err, "", "email.deliveryWebhook.url")
				said := d.Problem + " " + d.Remedy
				if strings.Contains(said, capability) {
					t.Errorf("the diagnostic echoes the receiver's path, where the capability token lives:\n%s", said)
				}
			})
		}
	})

	t.Run("the timeout has an environment override", func(t *testing.T) {
		env := baseEnv()
		env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_URL"] = "https://delivery.example.com/hook"
		env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = "delivery-webhook-signing-secret"
		env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_TIMEOUT_MS"] = "750"

		cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if got := cfg.Email.DeliveryWebhook.TimeoutMs; got != 750 {
			t.Errorf("timeoutMs = %d, want 750 from the environment", got)
		}
		if got := cfg.SecretValue("email.deliveryWebhook.secret"); got != "delivery-webhook-signing-secret" {
			t.Errorf("the secret did not resolve through its documented variable")
		}
	})
}

// TestTokenClaimDomainsAreWired is the P3 counterpart of
// TestEmailFlowDomainsAreWired: the TOTP issuer and the two token-claim knobs
// load instead of tripping the phase gap.
//
// Each is written the way the schema requires it, so this also pins that
// un-gating relaxed nothing: the claims webhook needs its signing secret, an
// extra claim needs exactly one of fromUserField and const. What cmd/auth then
// does with them — build the claims hook, label the otpauth URI — is its own
// tests' business.
func TestTokenClaimDomainsAreWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
		env    func(map[string]string)
	}{
		{"twoFactor", func(doc Document) {
			set(doc, "twoFactor.appName", "Example App")
		}, nil},
		{"security.jwt.extraClaims", func(doc Document) {
			set(doc, "security.jwt.extraClaims.tenant", map[string]any{"fromUserField": "tenantId"})
			set(doc, "security.jwt.extraClaims.plan", map[string]any{"const": "enterprise"})
		}, nil},
		{"security.jwt.claimsWebhook", func(doc Document) {
			set(doc, "security.jwt.claimsWebhook.url", "https://claims.example.com/hook")
			set(doc, "security.jwt.claimsWebhook.timeoutMs", 1500)
		}, func(env map[string]string) {
			env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"
		}},
		{"all three together", func(doc Document) {
			set(doc, "twoFactor.appName", "Example App")
			set(doc, "security.jwt.extraClaims.tenant", map[string]any{"fromUserField": "tenantId"})
			set(doc, "security.jwt.claimsWebhook.url", "https://claims.example.com/hook")
		}, func(env map[string]string) {
			env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)
			env := baseEnv()
			if tc.env != nil {
				tc.env(env)
			}

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if err != nil {
				t.Fatalf("the P3 domains are wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("%s is still reported as an unwired domain: %s", w.Path, w.Problem)
				}
			}
			for _, path := range []string{"twoFactor", "security.jwt.extraClaims", "security.jwt.claimsWebhook"} {
				if _, gated := UnwiredDomains()[path]; gated {
					t.Errorf("%s is still listed by UnwiredDomains", path)
				}
			}
		})
	}
}

// TestClaimsWebhookRequiresItsSecret: the receiver is handed the user profile
// and its answer decides what the token authorises, so a url without the secret
// that signs the requests is refused, and a secret without a url is refused as
// the dead configuration it is — the same rule the delivery webhook has, for a
// different reason (config.go, the Webhook type).
func TestClaimsWebhookRequiresItsSecret(t *testing.T) {
	const secretPath = "security.jwt.claimsWebhook.secret"

	t.Run("url without a secret", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "security.jwt.claimsWebhook.url", "https://claims.example.com/hook")

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		d := requireRule(t, err, "", secretPath)
		if !strings.Contains(d.Remedy, "AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET") {
			t.Errorf("the remedy does not name the variable that supplies the secret:\n%s", d.Remedy)
		}
		// The wording has to be the claims webhook's own: an operator told
		// "every request carries a credential" about this knob would be told
		// something untrue about the block they are fixing.
		if strings.Contains(d.Problem, "delivery webhook") {
			t.Errorf("the diagnostic describes the delivery webhook instead:\n%s", d.Problem)
		}
	})

	t.Run("secret reference without a url", func(t *testing.T) {
		doc := baseDoc()
		set(doc, secretPath, map[string]any{"envVar": "MY_CLAIMS_SECRET"})
		env := baseEnv()
		env["MY_CLAIMS_SECRET"] = "claims-webhook-signing-secret"

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		requireRule(t, err, "", "security.jwt.claimsWebhook.url")
	})

	t.Run("a non-positive timeout", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "security.jwt.claimsWebhook.url", "https://claims.example.com/hook")
		set(doc, "security.jwt.claimsWebhook.timeoutMs", 0)
		env := baseEnv()
		env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"

		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		requireRule(t, err, "", "security.jwt.claimsWebhook.timeoutMs")
	})

	// The ceiling, and the reason it is enforced here rather than only by the
	// CFN parameter's MaxValue: the value can arrive by three routes and
	// CloudFormation bounds one of them. This subtest uses the two the template
	// cannot see — the environment variable and the document — because a rule
	// that only held for a stack deployed through the template would not be a
	// rule this product has.
	//
	// What it buys: every login, refresh and step-up waits on this receiver
	// inside the invocation, so a deadline past the function's own Timeout does
	// not turn a slow receiver into a fast 500 — it fails the invocation and
	// answers nothing.
	t.Run("a timeout past the ceiling", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			load func() (*Config, error)
		}{
			{"from the environment", func() (*Config, error) {
				env := baseEnv()
				env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_URL"] = "https://claims.example.com/hook"
				env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"
				env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS"] = "600000"
				return Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
			}},
			{"from the document", func() (*Config, error) {
				doc := baseDoc()
				set(doc, "security.jwt.claimsWebhook.url", "https://claims.example.com/hook")
				set(doc, "security.jwt.claimsWebhook.timeoutMs", maxWebhookTimeoutMs+1)
				env := baseEnv()
				env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"
				return Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				_, err := tc.load()
				d := requireRule(t, err, "", "security.jwt.claimsWebhook.timeoutMs")
				if !strings.Contains(d.Remedy, strconv.Itoa(maxWebhookTimeoutMs)) {
					t.Errorf("the remedy does not name the ceiling the operator has to get under:\n%s", d.Remedy)
				}
			})
		}
	})

	// And the ceiling itself loads: a rule written as > would refuse the
	// documented maximum, which is the sort of off-by-one an operator discovers
	// from a failed deployment.
	t.Run("the ceiling itself is accepted", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "security.jwt.claimsWebhook.url", "https://claims.example.com/hook")
		set(doc, "security.jwt.claimsWebhook.timeoutMs", maxWebhookTimeoutMs)
		env := baseEnv()
		env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"

		cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		if err != nil {
			t.Fatalf("load at the documented ceiling: %v", err)
		}
		if got := cfg.Security.JWT.ClaimsWebhook.TimeoutMs; got != maxWebhookTimeoutMs {
			t.Errorf("timeoutMs = %d, want %d", got, maxWebhookTimeoutMs)
		}
	})

	// The same reasoning the delivery webhook's refusals follow: a cold-start
	// failure is written to CloudWatch, and a receiver behind a gateway that
	// cannot check an HMAC is commonly given a capability token in the path.
	t.Run("a refusal never echoes the receiver's path", func(t *testing.T) {
		const capability = "hunter2-capability-token"
		for _, tc := range []struct{ name, url string }{
			{"plain http", "http://claims.example.com/hook/" + capability},
			{"not a URL at all", "claims.example.com/hook/" + capability},
		} {
			t.Run(tc.name, func(t *testing.T) {
				doc := baseDoc()
				set(doc, "security.jwt.claimsWebhook.url", tc.url)
				env := baseEnv()
				env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"

				_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
				d := requireRule(t, err, "", "security.jwt.claimsWebhook.url")
				said := d.Problem + " " + d.Remedy
				if strings.Contains(said, capability) {
					t.Errorf("the diagnostic echoes the receiver's path, where the capability token lives:\n%s", said)
				}
			})
		}
	})

	t.Run("url, timeout and secret all have environment overrides", func(t *testing.T) {
		env := baseEnv()
		env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_URL"] = "https://claims.example.com/hook"
		env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_SECRET"] = "claims-webhook-signing-secret"
		env["AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS"] = "900"

		cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if got := cfg.Security.JWT.ClaimsWebhook.TimeoutMs; got != 900 {
			t.Errorf("timeoutMs = %d, want 900 from the environment", got)
		}
		if got := cfg.SecretValue(secretPath); got != "claims-webhook-signing-secret" {
			t.Errorf("the secret did not resolve through its documented variable")
		}
	})
}

// TestTemplatesDirRequiresTheTemplateStore: a directory that seeds a store
// nobody enabled would be read and discarded, which spec §1.17 treats as a
// misconfiguration rather than a no-op.
func TestTemplatesDirRequiresTheTemplateStore(t *testing.T) {
	doc := baseDoc()
	set(doc, "email.templatesDir", "/var/task/templates")

	_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
	d := requireRule(t, err, RuleStoreRequired, "stores.enable.templates")
	if !strings.Contains(d.Problem, "email.templatesDir") {
		t.Errorf("the diagnostic does not name the knob that needs the store:\n%s", d.Problem)
	}
}

// TestOAuthDomainIsWired is the P4 counterpart of TestEmailFlowDomainsAreWired:
// the whole oauth block loads now — the two built-in providers, a generic one,
// and the provisioning policy — instead of tripping the phase gap.
//
// Each case is written the way the schema requires it, so the test also pins
// that un-gating relaxed nothing: every provider needs its three required
// values (RS-11), and the deployment needs a redirect allowlist.
func TestOAuthDomainIsWired(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
		env    func(map[string]string)
	}{
		{"a built-in provider", func(doc Document) {
			set(doc, "oauth.providers.google.clientId", "123.apps.googleusercontent.com")
			set(doc, "oauth.providers.google.callbackUrl", "https://auth.example.com/auth/oauth/google/callback")
		}, func(env map[string]string) {
			env["AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET"] = "google-client-secret"
		}},
		{"a generic provider", func(doc Document) {
			set(doc, "oauth.providers.acme.clientId", "acme-client")
			set(doc, "oauth.providers.acme.callbackUrl", "https://auth.example.com/auth/oauth/acme/callback")
			set(doc, "oauth.providers.acme.authorizationUrl", "https://idp.example.com/authorize")
			set(doc, "oauth.providers.acme.tokenUrl", "https://idp.example.com/token")
			set(doc, "oauth.providers.acme.userInfoUrl", "https://idp.example.com/userinfo")
			set(doc, "oauth.providers.acme.scope", "openid email")
			set(doc, "oauth.providers.acme.profileMap", map[string]any{"id": "$.sub", "email": "$.mail ?? $.userPrincipalName"})
		}, func(env map[string]string) {
			env["AWESOME_AUTH_OAUTH_ACME_CLIENT_SECRET"] = "acme-client-secret"
		}},
		{"the provisioning policy", func(doc Document) {
			set(doc, "oauth.provisioning.autoCreate", false)
			set(doc, "oauth.provisioning.onEmailMatch", "conflict")
			set(doc, "oauth.provisioning.requireVerifiedEmail", true)
			set(doc, "oauth.provisioning.allowedEmailDomains", []any{"example.com"})
			set(doc, "oauth.provisioning.fieldMap", map[string]any{"firstName": "$.given_name"})
		}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			// Every OAuth deployment needs both of these (RS-11) — a redirect
			// allowlist, and the store the callback binds a provider identity
			// in — so they belong in the baseline of each case rather than in
			// the three mutators.
			set(doc, "email.siteUrls", []any{"https://app.example.com"})
			set(doc, "stores.enable.linkedAccounts", true)
			tc.mutate(doc)
			env := baseEnv()
			if tc.env != nil {
				tc.env(env)
			}

			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if err != nil {
				t.Fatalf("the oauth domain is wired, so this must load:\n%v", err)
			}
			for _, w := range cfg.Warnings() {
				if w.Path == "oauth" && strings.Contains(w.Problem, "not yet wired") {
					t.Errorf("oauth is still reported as an unwired domain: %s", w.Problem)
				}
			}
			if _, gated := UnwiredDomains()["oauth"]; gated {
				t.Error("oauth is still listed by UnwiredDomains")
			}
		})
	}
}

// TestOAuthClientSecretNoLongerTripsThePhaseGap: the oauth domain carried a
// secretPrefix, and removing the domain has to remove that half too — otherwise
// an operator who puts a provider's client secret in Secrets Manager gets a
// refusal for a block that works.
func TestOAuthClientSecretNoLongerTripsThePhaseGap(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_OAUTH_GITHUB_CLIENT_ID"] = "Iv1.0123456789abcdef"
	env["AWESOME_AUTH_OAUTH_GITHUB_CLIENT_SECRET"] = "github-client-secret"
	env["AWESOME_AUTH_OAUTH_GITHUB_CALLBACK_URL"] = "https://auth.example.com/auth/oauth/github/callback"

	doc := baseDoc()
	set(doc, "email.siteUrls", []any{"https://app.example.com"})
	set(doc, "stores.enable.linkedAccounts", true)

	if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)}); err != nil {
		t.Fatalf("an OAuth client secret must not reopen the phase gap:\n%v", err)
	}
}

// TestUnwiredDomainsAreDocumented keeps the exported list and the internal table
// in step, since the deployment tooling reads the exported one.
func TestUnwiredDomainsAreDocumented(t *testing.T) {
	exported := UnwiredDomains()
	if len(exported) != len(unwiredDomains()) {
		t.Fatalf("UnwiredDomains has %d entries, the table has %d", len(exported), len(unwiredDomains()))
	}
	for _, path := range sortedDomainPaths() {
		phase, ok := exported[path]
		if !ok {
			t.Errorf("%s is missing from UnwiredDomains", path)
			continue
		}
		if phase == "" {
			t.Errorf("%s has no phase recorded", path)
		}
	}
}

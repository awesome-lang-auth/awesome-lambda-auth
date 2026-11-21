package config

import (
	"strings"
	"testing"
)

// The realm knobs: registration.closed, twoFactor.required and
// twoFactor.enrolOnLogin. Each reaches the core as one field (cmd/auth
// httpConfig and twoFactorOptions); what is pinned here is what the loader
// decides about them — the two sources, the defaults, the one refusal and the
// warnings.

// googleProvider writes a complete Google block with a redirect allowlist and
// its store, so that RS-11 is satisfied and a case fails, if it fails, for the
// rule it is about.
func googleProvider(doc Document) {
	set(doc, "email.siteUrls", []any{"https://app.example.com"})
	set(doc, "stores.enable.linkedAccounts", true)
	set(doc, "oauth.providers.google.clientId", "123.apps.googleusercontent.com")
	set(doc, "oauth.providers.google.callbackUrl", "https://auth.example.com/auth/oauth/google/callback")
}

func googleEnv() map[string]string {
	env := baseEnv()
	env["AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET"] = "google-client-secret"
	return env
}

// TestRealmKnobsAreOffByDefault: a document that never mentions them loads
// the deployment it loaded before they existed.
func TestRealmKnobsAreOffByDefault(t *testing.T) {
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(baseEnv())})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Registration.Closed || cfg.TwoFactor.Required || cfg.TwoFactor.EnrolOnLogin {
		t.Errorf("registration.closed=%v twoFactor.required=%v twoFactor.enrolOnLogin=%v, want all false",
			cfg.Registration.Closed, cfg.TwoFactor.Required, cfg.TwoFactor.EnrolOnLogin)
	}
	for _, w := range cfg.Warnings() {
		if strings.HasPrefix(w.Path, "twoFactor.") || strings.HasPrefix(w.Path, "registration.") {
			t.Errorf("an unconfigured realm warns about %s: %s", w.Path, w.Error())
		}
	}
}

// TestRealmKnobsLoadFromEitherSource: the document and the documented
// variables, and the variable wins, as for every knob.
func TestRealmKnobsLoadFromEitherSource(t *testing.T) {
	t.Run("document", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "registration.closed", true)
		set(doc, "twoFactor.required", true)
		set(doc, "twoFactor.enrolOnLogin", true)
		cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if !cfg.Registration.Closed || !cfg.TwoFactor.Required || !cfg.TwoFactor.EnrolOnLogin {
			t.Errorf("the document's three true values did not load: %+v %+v", cfg.Registration, cfg.TwoFactor)
		}
		if got := cfg.Source("registration.closed"); got != SourceDocument {
			t.Errorf("registration.closed source = %q, want the document", got)
		}
	})
	t.Run("environment over the document", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "registration.closed", true)
		set(doc, "twoFactor.required", true)
		env := baseEnv()
		env["AWESOME_AUTH_REGISTRATION_CLOSED"] = "false"
		env["AWESOME_AUTH_2FA_REQUIRED"] = "false"
		env["AWESOME_AUTH_2FA_ENROL_ON_LOGIN"] = "true"
		cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.Registration.Closed || cfg.TwoFactor.Required || !cfg.TwoFactor.EnrolOnLogin {
			t.Errorf("the variables did not win: closed=%v required=%v enrolOnLogin=%v",
				cfg.Registration.Closed, cfg.TwoFactor.Required, cfg.TwoFactor.EnrolOnLogin)
		}
		for path, want := range map[string]string{
			"registration.closed":    "AWESOME_AUTH_REGISTRATION_CLOSED",
			"twoFactor.required":     "AWESOME_AUTH_2FA_REQUIRED",
			"twoFactor.enrolOnLogin": "AWESOME_AUTH_2FA_ENROL_ON_LOGIN",
		} {
			if got := cfg.Source(path); got != want {
				t.Errorf("%s source = %q, want %s", path, got, want)
			}
		}
	})
	t.Run("a value that is not a boolean is refused with its variable", func(t *testing.T) {
		env := baseEnv()
		env["AWESOME_AUTH_REGISTRATION_CLOSED"] = "invite-only"
		_, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
		d := requireRule(t, err, "", "registration.closed")
		if !strings.Contains(d.Error(), "AWESOME_AUTH_REGISTRATION_CLOSED") {
			t.Errorf("the diagnostic does not name the variable: %s", d.Error())
		}
	})
	t.Run("a misspelt key is refused with a hint", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "registration.close", true)
		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv())})
		d := requireRule(t, err, "", "registration.close")
		if !strings.Contains(d.Error(), "did you mean closed?") {
			t.Errorf("no spelling hint: %s", d.Error())
		}
	})
}

// TestClosedRegistrationBesideOAuth is RS-19 and the shapes around it. Closing
// POST <prefix>/register closes one of two self-registration doors; the OAuth
// callback is the other, open by default (oauth.provisioning.autoCreate), and a
// closed realm that leaves it open to every account at the provider is
// refused — and so is one narrowed by domain on an address the provider has
// not verified. Each other row takes one of the rule's conditions away.
func TestClosedRegistrationBesideOAuth(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
		env    map[string]string
		// refusedOn is the path RS-19 reports, empty when the document loads;
		// warned is the narrowed-realm warning on
		// oauth.provisioning.allowedEmailDomains.
		refusedOn string
		warned    bool
	}{
		{
			name:      "closed, a provider, autoCreate by default and no domain list",
			mutate:    func(doc Document) { set(doc, "registration.closed", true); googleProvider(doc) },
			refusedOn: "oauth.provisioning.autoCreate",
		},
		{
			name: "the same with autoCreate written true",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.autoCreate", true)
			},
			refusedOn: "oauth.provisioning.autoCreate",
		},
		{
			name:   "the same, closed through the variable",
			mutate: googleProvider,
			env: func() map[string]string {
				env := googleEnv()
				env["AWESOME_AUTH_REGISTRATION_CLOSED"] = "true"
				return env
			}(),
			refusedOn: "oauth.provisioning.autoCreate",
		},
		{
			// requireVerifiedEmail defaults to off, so the domain is matched on
			// whatever address the provider asserts, verified or not.
			name: "closed and narrowed to the company's domain, verification not required",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.allowedEmailDomains", []any{"example.com"})
			},
			refusedOn: "oauth.provisioning.requireVerifiedEmail",
		},
		{
			name: "the same with requireVerifiedEmail written false",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.allowedEmailDomains", []any{"example.com"})
				set(doc, "oauth.provisioning.requireVerifiedEmail", false)
			},
			refusedOn: "oauth.provisioning.requireVerifiedEmail",
		},
		{
			name: "closed with autoCreate off: the callback creates nobody",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.autoCreate", false)
			},
		},
		{
			name:   "closed with autoCreate turned off by its variable",
			mutate: func(doc Document) { set(doc, "registration.closed", true); googleProvider(doc) },
			env: func() map[string]string {
				env := googleEnv()
				env["AWESOME_AUTH_OAUTH_PROVISIONING_AUTO_CREATE"] = "false"
				return env
			}(),
		},
		{
			name: "closed, narrowed to the company's domain and to verified addresses: loads, and says so",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.allowedEmailDomains", []any{"example.com"})
				set(doc, "oauth.provisioning.requireVerifiedEmail", true)
			},
			warned: true,
		},
		{
			name: "the same with verification required through its variable",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.allowedEmailDomains", []any{"example.com"})
			},
			env: func() map[string]string {
				env := googleEnv()
				env["AWESOME_AUTH_OAUTH_PROVISIONING_REQUIRE_VERIFIED_EMAIL"] = "true"
				return env
			}(),
			warned: true,
		},
		{
			// Verification alone narrows nothing: every verified address at
			// the provider still signs up.
			name: "closed with verification required and no domain list",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.requireVerifiedEmail", true)
			},
			refusedOn: "oauth.provisioning.autoCreate",
		},
		{
			// autoCreate defaults to true with no provider at all, so a rule on
			// the flag alone would refuse every closed realm.
			name:   "closed with no provider configured",
			mutate: func(doc Document) { set(doc, "registration.closed", true) },
		},
		{
			name:   "open, with a provider that creates accounts",
			mutate: googleProvider,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := baseDoc()
			tc.mutate(doc)
			env := tc.env
			if env == nil {
				env = googleEnv()
			}
			cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
			if tc.refusedOn != "" {
				d := requireRule(t, err, RuleClosedRegistrationOAuth, tc.refusedOn)
				wants := []string{"google", "registration.closed", "autoCreate: false", "allowedEmailDomains"}
				if tc.refusedOn == "oauth.provisioning.requireVerifiedEmail" {
					// The narrowed shape: name the domain it lets in, and the
					// knob that is missing.
					wants = []string{"google", "registration.closed", "example.com", "requireVerifiedEmail: true", "unverified"}
				}
				for _, want := range wants {
					if !strings.Contains(d.Error(), want) {
						t.Errorf("the RS-19 diagnostic does not mention %q:\n%s", want, d.Error())
					}
				}
				if n := len(validationError(t, err).Diagnostics); n != 1 {
					t.Errorf("RS-19 reported %d diagnostics, want exactly one shape: %v", n, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("this configuration must load:\n%v", err)
			}
			var warned *Diagnostic
			for i, w := range cfg.Warnings() {
				if w.Path == "oauth.provisioning.allowedEmailDomains" {
					warned = &cfg.Warnings()[i]
				}
			}
			if tc.warned != (warned != nil) {
				t.Fatalf("narrowed-realm warning present = %v, want %v (warnings %v)", warned != nil, tc.warned, cfg.Warnings())
			}
			if warned != nil && !strings.Contains(warned.Problem, "example.com") {
				t.Errorf("the warning does not name the domain it lets in: %s", warned.Error())
			}
		})
	}
}

// TestTwoFactorPolicyWarnings: the loader says, where the deployment tooling
// reads it, what each 2FA knob does where it meets a surface that does not
// follow it — forced enrolment is trust on first use, and the identity
// provider's password-only /authorize refuses everyone under the policy.
// Neither is refused. The surfaces the policy must not miss are no longer
// warnings: the OAuth callback and the console credentials are refused
// (RS-20, TestTwoFactorRequiredRefusesOneFactorSignIns) and the passwordless
// logins and the console's login are held to the policy at request time
// (cmd/auth secondFactorGate), so they warn about nothing.
func TestTwoFactorPolicyWarnings(t *testing.T) {
	warningsFor := func(t *testing.T, mutate func(Document), env map[string]string) []Diagnostic {
		t.Helper()
		doc := baseDoc()
		mutate(doc)
		cfg, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env), AllowUnimplemented: true})
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return cfg.Warnings()
	}
	find := func(ws []Diagnostic, path, fragment string) *Diagnostic {
		for i := range ws {
			if ws[i].Path == path && strings.Contains(ws[i].Problem, fragment) {
				return &ws[i]
			}
		}
		return nil
	}

	t.Run("enrolOnLogin is trust on first use, under the policy", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "twoFactor.required", true)
			set(doc, "twoFactor.enrolOnLogin", true)
		}, baseEnv())
		w := find(ws, "twoFactor.enrolOnLogin", "trust on first use")
		if w == nil {
			t.Fatalf("no trust-on-first-use warning: %v", ws)
		}
		if !strings.Contains(w.Problem, "twoFactor.required") || !strings.Contains(w.Remedy, "reset the password together with the factor") {
			t.Errorf("the warning does not say whom it covers or what to do: %s", w.Error())
		}
	})
	t.Run("enrolOnLogin without the policy covers the flagged accounts, and loads", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) { set(doc, "twoFactor.enrolOnLogin", true) }, baseEnv())
		w := find(ws, "twoFactor.enrolOnLogin", "trust on first use")
		if w == nil || !strings.Contains(w.Problem, "own require2FA flag") {
			t.Fatalf("enrolOnLogin alone must load and say it applies to flagged accounts: %v", ws)
		}
	})
	t.Run("required beside the identity provider", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "deployment.environment", "development")
			set(doc, "twoFactor.required", true)
			set(doc, "idProvider.enabled", true)
		}, baseEnv())
		w := find(ws, "twoFactor.required", "POST <prefix>/authorize")
		if w == nil {
			t.Fatalf("no warning that the identity provider's /authorize refuses everyone under the policy: %v", ws)
		}
		if !strings.Contains(w.Problem, "invalid credentials") || !strings.Contains(w.Remedy, "idProvider") {
			t.Errorf("the warning does not say what a user sees or what to change: %s", w.Error())
		}
	})
	t.Run("the identity provider without the policy warns about nothing", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "deployment.environment", "development")
			set(doc, "idProvider.enabled", true)
		}, baseEnv())
		for _, w := range ws {
			if strings.HasPrefix(w.Path, "twoFactor.") {
				t.Errorf("an identity provider without twoFactor.required warned: %s", w.Error())
			}
		}
	})
	// The console the request-time gate holds to the policy loads without a
	// word: with its machine principal it is the org realm's shape, and its
	// cold-start line says what the gate refuses.
	t.Run("required beside the console warns about nothing", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "twoFactor.required", true)
			set(doc, "admin.enabled", true)
			set(doc, "admin.accessPolicy", "is-admin-flag")
			set(doc, "admin.machineAccess.iam.principals", []any{"arn:aws:iam::123456789012:role/plat-identity"})
		}, baseEnv())
		for _, w := range ws {
			if strings.HasPrefix(w.Path, "twoFactor.") {
				t.Errorf("the console under the policy warned: %s", w.Error())
			}
		}
	})

	// A transport is different: under the policy it stops carrying the
	// emailed link and the texted code, which is a change in what a block the
	// operator configured does — and the review that found a mailbox
	// answering both steps found it because nothing said so. Each transport
	// warns, naming what is refused and what the transport still carries.
	mailer := func(doc Document) {
		set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
		set(doc, "email.mailer.from", "no-reply@example.com")
	}
	webhook := func(doc Document) { set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook") }
	sms := func(doc Document) { set(doc, "sms.endpoint", "https://sms.example.com/send") }
	webhookEnv := func() map[string]string {
		env := baseEnv()
		env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = "delivery-webhook-signing-secret"
		return env
	}
	for _, tc := range []struct {
		name      string
		transport func(Document)
		env       func() map[string]string
		names     string
		carries   []string
	}{
		{"a mailer", mailer, baseEnv, "a mailer (email.mailer)", []string{"password-reset", "opens no session", "a mailbox or a phone number alone never opens one"}},
		{"the delivery webhook", webhook, webhookEnv, "the delivery webhook (email.deliveryWebhook)", []string{"password-reset", "opens no session"}},
		{"an SMS transport", sms, baseEnv, "an SMS transport (sms)", []string{"carries no credential", "a phone number alone never opens a session"}},
	} {
		t.Run("required beside "+tc.name+" says what is refused", func(t *testing.T) {
			ws := warningsFor(t, func(doc Document) {
				set(doc, "twoFactor.required", true)
				tc.transport(doc)
			}, tc.env())
			w := find(ws, "twoFactor.required", "the only second factor")
			if w == nil {
				t.Fatalf("no warning that the policy changes what %s carries: %v", tc.name, ws)
			}
			for _, want := range append([]string{
				tc.names, "TOTP code", "/magic-link/send, /magic-link/verify, /sms/send and /sms/verify", "403 2FA_REQUIRED",
				"every mode", `mode "2fa"`, "totp alone", "2FA_SETUP_REQUIRED",
			}, tc.carries...) {
				if !strings.Contains(w.Problem, want) {
					t.Errorf("the warning does not say %q:\n%s", want, w.Error())
				}
			}
			if strings.Contains(w.Problem, "enrolOnLogin") {
				t.Errorf("with forced enrolment off the warning names it:\n%s", w.Error())
			}
		})
		t.Run(tc.name+" without the policy warns about nothing of this", func(t *testing.T) {
			ws := warningsFor(t, tc.transport, tc.env())
			for _, w := range ws {
				if strings.HasPrefix(w.Path, "twoFactor.") {
					t.Errorf("%s without twoFactor.required warned: %s", tc.name, w.Error())
				}
			}
		})
	}

	// Forced enrolment beside the reset mail: the mailbox alone can set an
	// unenrolled account's password, and forced enrolment then lets it bind
	// the factor. Trust on first use, made reachable from the mailbox; both
	// warnings say so.
	t.Run("enrolOnLogin beside the reset mail names the mailbox", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "twoFactor.required", true)
			set(doc, "twoFactor.enrolOnLogin", true)
			mailer(doc)
		}, baseEnv())
		if w := find(ws, "twoFactor.enrolOnLogin", "trust on first use"); w == nil || !strings.Contains(w.Problem, "mailbox alone") {
			t.Errorf("the trust-on-first-use warning does not name the reset mail: %v", w)
		}
		if w := find(ws, "twoFactor.required", "the only second factor"); w == nil || !strings.Contains(w.Problem, "has not enrolled yet") {
			t.Errorf("the transport warning does not name the unenrolled account forced enrolment exposes: %v", w)
		}
	})
	t.Run("enrolOnLogin without a mail transport does not name the mailbox", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "twoFactor.required", true)
			set(doc, "twoFactor.enrolOnLogin", true)
		}, baseEnv())
		if w := find(ws, "twoFactor.enrolOnLogin", "trust on first use"); w == nil || strings.Contains(w.Problem, "mailbox") {
			t.Errorf("with no reset mail the warning names a mailbox: %v", w)
		}
	})
	t.Run("required alone warns about nothing", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) { set(doc, "twoFactor.required", true) }, baseEnv())
		for _, w := range ws {
			if strings.HasPrefix(w.Path, "twoFactor.") {
				t.Errorf("twoFactor.required alone warned: %s", w.Error())
			}
		}
	})
}

// TestTwoFactorRequiredRefusesOneFactorSignIns is RS-20. Under
// twoFactor.required a configuration is refused when it keeps a sign-in the
// policy cannot reach: an OAuth provider (the core's callback opens a session
// with no second-factor step), and the console's root user and bootstrap
// secret, whose one door — POST <admin>/login — the product does not serve
// under the policy. Every shape is refused in development too, and every one
// loads with the policy off, which is the control that the rule is the
// policy's and not the knob's.
func TestTwoFactorRequiredRefusesOneFactorSignIns(t *testing.T) {
	console := func(doc Document) {
		set(doc, "admin.enabled", true)
		set(doc, "admin.accessPolicy", "is-admin-flag")
	}
	const rootHash = "$2a$10$7EqJtq98hPqEX7fNZaFWoOhi5BWX4Z6aZ5S0Ls0cK1R3G7rU/0Tsy"
	cases := []struct {
		name    string
		mutate  func(Document)
		env     func(map[string]string)
		path    string
		mention []string
	}{
		{
			name:    "an OAuth provider",
			mutate:  googleProvider,
			env:     func(env map[string]string) { env["AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET"] = "google-client-secret" },
			path:    "oauth.providers",
			mention: []string{"google", "no second factor", "remove oauth.providers"},
		},
		{
			name: "an OAuth provider with autoCreate off still signs existing accounts in",
			mutate: func(doc Document) {
				googleProvider(doc)
				set(doc, "oauth.provisioning.autoCreate", false)
			},
			env:     func(env map[string]string) { env["AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_SECRET"] = "google-client-secret" },
			path:    "oauth.providers",
			mention: []string{"google"},
		},
		{
			name:    "the console's root user",
			mutate:  func(doc Document) { console(doc); set(doc, "admin.rootUser.email", "root@example.com") },
			env:     func(env map[string]string) { env["AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH"] = rootHash },
			path:    "admin.rootUser.email",
			mention: []string{"POST <admin>/login", "could never sign in"},
		},
		{
			name:    "the bootstrap secret beside a policy",
			mutate:  console,
			env:     func(env map[string]string) { env["AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET"] = strings.Repeat("s", 40) },
			path:    "admin.bootstrapSecret",
			mention: []string{"shared password", "POST <admin>/login"},
		},
		{
			name:    "the bootstrap secret as the console's whole guard",
			mutate:  func(doc Document) { set(doc, "admin.enabled", true) },
			env:     func(env map[string]string) { env["AWESOME_AUTH_ADMIN_BOOTSTRAP_SECRET"] = strings.Repeat("s", 40) },
			path:    "admin.bootstrapSecret",
			mention: []string{"whole guard"},
		},
		{
			name: "the bootstrap secret by store reference",
			mutate: func(doc Document) {
				console(doc)
				set(doc, "admin.bootstrapSecret", map[string]any{"secretsManager": "awesome-auth/admin-bootstrap"})
			},
			path: "admin.bootstrapSecret",
		},
		{
			// The reviewer's probe: GET /admin/api/users answered 200 with no
			// credential under the policy.
			name: "an open console",
			mutate: func(doc Document) {
				set(doc, "admin.enabled", true)
				set(doc, "admin.accessPolicy", "open")
			},
			path:    "admin.accessPolicy",
			mention: []string{"open", "no credential at all", "is-admin-flag"},
		},
	}
	for _, env := range []string{"development", "production"} {
		for _, tc := range cases {
			t.Run(env+"/"+tc.name, func(t *testing.T) {
				for _, required := range []bool{true, false} {
					doc := baseDoc()
					set(doc, "deployment.environment", env)
					tc.mutate(doc)
					set(doc, "twoFactor.required", required)
					vars := baseEnv()
					if tc.env != nil {
						tc.env(vars)
					}
					_, err := Load(t.Context(), Options{
						Document: doc, Getenv: getenvFrom(vars), AllowUnimplemented: true,
						Secrets: Resolvers{SecretsManager: fakeResolver{ResolverSecretsManager, map[string]string{"awesome-auth/admin-bootstrap": strings.Repeat("s", 40)}}},
					})
					if !required {
						requireNoRule(t, err, RuleTwoFactorRequiredSignIn)
						continue
					}
					d := requireRule(t, err, RuleTwoFactorRequiredSignIn, tc.path)
					for _, want := range append([]string{"twoFactor.required"}, tc.mention...) {
						if !strings.Contains(d.Error(), want) {
							t.Errorf("the RS-20 diagnostic does not mention %q:\n%s", want, d.Error())
						}
					}
				}
			})
		}
	}

	// What stays: the org realm's shape — the policy, a console under a
	// session policy with no root user, and a machine principal — and the
	// transports, whose passwordless seams cmd/auth withholds and the
	// request-time gate refuses under the policy (warned, not refused). A
	// root user and a provider with no console or policy around them are not
	// this rule's business either.
	t.Run("the console without its two credentials, a machine principal and both transports load", func(t *testing.T) {
		doc := baseDoc()
		console(doc)
		set(doc, "twoFactor.required", true)
		set(doc, "admin.machineAccess.iam.principals", []any{"arn:aws:iam::123456789012:role/plat-identity"})
		set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
		set(doc, "email.mailer.from", "no-reply@example.com")
		set(doc, "sms.endpoint", "https://sms.example.com/send")
		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(baseEnv()), AllowUnimplemented: true})
		requireNoRule(t, err, RuleTwoFactorRequiredSignIn)
		if err != nil {
			t.Fatalf("the org realm's shape must load:\n%v", err)
		}
	})
	t.Run("a root user with the console off is not this rule's", func(t *testing.T) {
		doc := baseDoc()
		set(doc, "twoFactor.required", true)
		set(doc, "admin.rootUser.email", "root@example.com")
		vars := baseEnv()
		vars["AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH"] = rootHash
		_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(vars), AllowUnimplemented: true})
		requireNoRule(t, err, RuleTwoFactorRequiredSignIn)
	})
}

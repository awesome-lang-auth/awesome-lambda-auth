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
// refused. Each other row takes one of the rule's conditions away.
func TestClosedRegistrationBesideOAuth(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(Document)
		env    map[string]string
		// refused is RS-19 on oauth.provisioning.autoCreate; warned is the
		// narrowed-realm warning on oauth.provisioning.allowedEmailDomains.
		refused, warned bool
	}{
		{
			name:    "closed, a provider, autoCreate by default and no domain list",
			mutate:  func(doc Document) { set(doc, "registration.closed", true); googleProvider(doc) },
			refused: true,
		},
		{
			name: "the same with autoCreate written true",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.autoCreate", true)
			},
			refused: true,
		},
		{
			name:   "the same, closed through the variable",
			mutate: googleProvider,
			env: func() map[string]string {
				env := googleEnv()
				env["AWESOME_AUTH_REGISTRATION_CLOSED"] = "true"
				return env
			}(),
			refused: true,
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
			name: "closed and narrowed to the company's domain: loads, and says so",
			mutate: func(doc Document) {
				set(doc, "registration.closed", true)
				googleProvider(doc)
				set(doc, "oauth.provisioning.allowedEmailDomains", []any{"example.com"})
			},
			warned: true,
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
			if tc.refused {
				d := requireRule(t, err, RuleClosedRegistrationOAuth, "oauth.provisioning.autoCreate")
				for _, want := range []string{"google", "registration.closed", "autoCreate: false", "allowedEmailDomains"} {
					if !strings.Contains(d.Error(), want) {
						t.Errorf("the RS-19 diagnostic does not mention %q:\n%s", want, d.Error())
					}
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
// follow it — forced enrolment is trust on first use, and the OAuth callback
// and the console's own login do not ask for the factor twoFactor.required
// demands at POST <prefix>/login. None of them is refused.
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
	t.Run("required beside an OAuth provider", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "twoFactor.required", true)
			googleProvider(doc)
		}, googleEnv())
		if find(ws, "twoFactor.required", "oauth-callback-skips-the-second-factor") == nil {
			t.Fatalf("no warning that the OAuth callback skips the factor: %v", ws)
		}
	})
	t.Run("required beside the admin console", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "twoFactor.required", true)
			set(doc, "admin.enabled", true)
			set(doc, "admin.accessPolicy", "is-admin-flag")
		}, baseEnv())
		w := find(ws, "twoFactor.required", "admin-login-skips-the-second-factor")
		if w == nil {
			t.Fatalf("no warning that the console's login skips the factor: %v", ws)
		}
		if !strings.Contains(w.Remedy, "admin.loginPath") {
			t.Errorf("the remedy does not name admin.loginPath: %s", w.Error())
		}
	})
	t.Run("required beside a mail or SMS transport", func(t *testing.T) {
		ws := warningsFor(t, func(doc Document) {
			set(doc, "twoFactor.required", true)
			set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
			set(doc, "email.mailer.from", "no-reply@example.com")
		}, baseEnv())
		w := find(ws, "twoFactor.required", "magic-link/verify")
		if w == nil {
			t.Fatalf("no warning that the magic-link login skips the factor: %v", ws)
		}
		if strings.Contains(w.Problem, "sms/verify") {
			t.Errorf("the warning names the SMS login with no SMS transport: %s", w.Error())
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

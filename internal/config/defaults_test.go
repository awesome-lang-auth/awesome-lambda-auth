package config

import (
	"reflect"
	"testing"
)

// TestDefaultsMatchSpec pins every default against docs/spec/config-schema.md §1,
// which in turn pins them against the reference's code (not its doc comments) at
// the recorded SHA. A default that drifts here is a silent behaviour change for
// every deployment that did not override it, so it has to break a test.
func TestDefaultsMatchSpec(t *testing.T) {
	c := Defaults()

	cases := []struct {
		path string
		got  any
		want any
	}{
		// §4 document versioning
		{"schemaVersion", c.SchemaVersion, 1},

		// deployment [new] — production by default so that an operator who
		// declares nothing gets the strict rules, not a memory store.
		{"deployment.environment", c.Deployment.Environment, EnvironmentProduction},

		// §1.1 tokens and secrets
		{"security.jwt.accessTokenTtl", c.Security.JWT.AccessTokenTTL.String(), "15m"},
		{"security.jwt.refreshTokenTtl", c.Security.JWT.RefreshTokenTTL.String(), "7d"},
		{"security.password.bcryptSaltRounds", c.Security.Password.BcryptSaltRounds, 12},
		{"tokens.passwordResetTtlMinutes", c.Tokens.PasswordResetTTLMinutes, 60},
		{"tokens.emailVerificationTtlMinutes", c.Tokens.EmailVerificationTTLMinutes, 1440},
		{"tokens.emailChangeTtlMinutes", c.Tokens.EmailChangeTTLMinutes, 60},
		{"tokens.accountLinkTtlMinutes", c.Tokens.AccountLinkTTLMinutes, 60},
		{"tokens.magicLinkTtlMinutes", c.Tokens.MagicLinkTTLMinutes, 15},

		// §1.2 cookies
		{"cookies.secure", c.Cookies.Secure, false},
		{"cookies.sameSite", c.Cookies.SameSite, SameSiteLax},
		{"cookies.domain", c.Cookies.Domain, ""},
		{"cookies.path", c.Cookies.Path, "/"},
		{"cookies.allowInsecureCookieMode", c.Cookies.AllowInsecureCookieMode, false},

		// §1.3 CSRF — deliberate hardening deviation: the reference defaults to
		// false (src/middleware/auth.middleware.ts:35).
		{"security.csrf.enabled", c.Security.CSRF.Enabled, true},

		// §1.4 sessions
		{"sessions.checkOn", c.Sessions.CheckOn, SessionCheckOnRefresh},

		// §1.5 email
		{"email.mailer.defaultLang", c.Email.Mailer.DefaultLang, "en"},
		{"email.verification.mode", c.Email.Verification.Mode, EmailVerificationNone},

		// §1.6 SMS
		{"sms.codeTtlMinutes", c.SMS.CodeTTLMinutes, 10},

		// §1.7 OAuth provisioning — the policy the imported core applies with no
		// policy at all (auth.DefaultOAuthProvisioning), spelled out because an
		// explicit policy is taken at its word and a zero AutoCreate would
		// refuse every first login through a provider.
		{"oauth.provisioning.autoCreate", c.OAuth.Provisioning.AutoCreate, true},
		{"oauth.provisioning.onEmailMatch", c.OAuth.Provisioning.OnEmailMatch, OAuthEmailMatchLink},
		{"oauth.provisioning.requireVerifiedEmail", c.OAuth.Provisioning.RequireVerifiedEmail, false},

		// §1.8 two-factor
		{"twoFactor.appName", c.TwoFactor.AppName, "awesome-node-auth"},

		// §1.10 identity provider
		{"idProvider.enabled", c.IDProvider.Enabled, false},
		{"idProvider.jwksPath", c.IDProvider.JWKSPath, "/.well-known/jwks.json"},
		{"idProvider.accessTokenTtl", c.IDProvider.AccessTokenTTL.String(), "30d"},
		{"idProvider.refreshTokenTtl", c.IDProvider.RefreshTokenTTL.String(), "90d"},
		{"idProvider.jwksCorsOrigins", c.IDProvider.JWKSCorsOrigins.Values, []string{"*"}},

		// §1.11 resource server
		{"resourceServer.enabled", c.ResourceServer.Enabled, false},
		{"resourceServer.jwksCacheTtlMs", c.ResourceServer.JWKSCacheTTLMs, 3_600_000},
		{"resourceServer.jwksFetchTimeoutMs", c.ResourceServer.JWKSFetchTimeoutMs, 5000},

		// §1.12 UI
		{"ui.enabled", c.UI.Enabled, false},
		{"ui.headless", c.UI.Headless, false},
		{"ui.branding.primaryColor", c.UI.Branding.PrimaryColor, "#4a90d9"},
		{"ui.branding.secondaryColor", c.UI.Branding.SecondaryColor, "#6c757d"},
		{"ui.branding.siteName", c.UI.Branding.SiteName, "Awesome Node Auth"},

		// §1.13 admin
		{"admin.basePath", c.Admin.BasePath, "/admin"},
		{"admin.sessionTtl", c.Admin.SessionTTL.String(), "24h"},
		{"admin.upload.maxFileSizeMb", c.Admin.Upload.MaxFileSizeMb, 5},

		// §1.14 tools
		{"tools.telemetry.enabled", c.Tools.Telemetry.Enabled, true},
		{"tools.notify.enabled", c.Tools.Notify.Enabled, true},
		{"tools.stream.enabled", c.Tools.Stream.Enabled, true},
		{"tools.basePath", c.Tools.BasePath, "/tools"},
		{"tools.sse.enabled", c.Tools.SSE.Enabled, false},
		{"tools.sse.heartbeatIntervalMs", c.Tools.SSE.HeartbeatIntervalMs, 30_000},
		{"tools.sse.deduplicate", c.Tools.SSE.Deduplicate, true},
		// D9c: the event log's two knobs, [new] and so the product's numbers.
		{"tools.sse.distributor.type", c.Tools.SSE.Distributor.Type, "none"},
		{"tools.sse.pollIntervalMs", c.Tools.SSE.PollIntervalMs, 1000},
		{"tools.sse.eventLogRetentionSeconds", c.Tools.SSE.EventLogRetentionSeconds, 86_400},

		// §1.15 webhooks
		{"tools.inboundWebhooks.enabled", c.Tools.InboundWebhooks.Enabled, true},
		{"tools.inboundWebhooks.scriptTimeoutMs", c.Tools.InboundWebhooks.ScriptTimeoutMs, 5000},
		{"tools.outboundWebhooks.payloadVersion", c.Tools.OutboundWebhooks.PayloadVersion, "1"},
		{"tools.outboundWebhooks.defaults.maxRetries", c.Tools.OutboundWebhooks.Defaults.MaxRetries, 3},
		{"tools.outboundWebhooks.defaults.retryDelayMs", c.Tools.OutboundWebhooks.Defaults.RetryDelayMs, 1000},
		{"tools.outboundWebhooks.queueUrl (D9b)", c.Tools.OutboundWebhooks.QueueURL, ""},

		// §1.17 stores
		{"stores.driver", c.Stores.Driver, StoreDriverMemory},
		{"stores.enable.users", c.Stores.Enable.Users, true},
		{"stores.enable.sessions", c.Stores.Enable.Sessions, true},
		{"stores.enable.tokens", c.Stores.Enable.Tokens, true},
		{"stores.enable.rbac", c.Stores.Enable.RBAC, false},

		// §1.18 HTTP and docs
		{"http.apiPrefix", c.HTTP.APIPrefix, "/auth"},
		{"docs.swagger", c.Docs.Swagger, SwaggerAuto},

		// §1.19 runtime settings
		{"runtimeSettings.lazyEmailVerificationGracePeriodDays", c.RuntimeSettings.LazyEmailVerificationGracePeriodDays, 7},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			if !reflect.DeepEqual(tc.got, tc.want) {
				t.Errorf("default for %s = %v, want %v", tc.path, tc.got, tc.want)
			}
		})
	}
}

// TestDefaultTTLsParse guards against a typo in a built-in default: mustDuration
// panics, but only when the value is actually reached, and a default that never
// parses would otherwise show up as an RS-9 refusal on a document that overrode
// nothing.
func TestDefaultTTLsParse(t *testing.T) {
	c := Defaults()
	for path, d := range map[string]Duration{
		"security.jwt.accessTokenTtl":  c.Security.JWT.AccessTokenTTL,
		"security.jwt.refreshTokenTtl": c.Security.JWT.RefreshTokenTTL,
		"idProvider.accessTokenTtl":    c.IDProvider.AccessTokenTTL,
		"idProvider.refreshTokenTtl":   c.IDProvider.RefreshTokenTTL,
		"admin.sessionTtl":             c.Admin.SessionTTL,
	} {
		if err := d.parseErr(); err != nil {
			t.Errorf("built-in default %s = %q does not parse: %v", path, d.String(), err)
		}
		if d.Duration() <= 0 {
			t.Errorf("built-in default %s = %q resolves to %v", path, d.String(), d.Duration())
		}
	}
}

// TestDefaultsAloneAreRefused documents that Defaults is a starting point and not
// a deployable configuration: a stack must declare its public URL, and the
// signing secrets have to come from somewhere.
func TestDefaultsAloneAreRefused(t *testing.T) {
	_, err := Load(t.Context(), Options{Getenv: getenvFrom(nil)})
	ve := validationError(t, err)
	if !ve.HasRule(RuleSecrets) {
		t.Errorf("expected RS-1 for the missing signing secrets, got:\n%v", ve)
	}
	if !ve.HasRule(RuleInsecureCookieMode) {
		t.Errorf("expected RS-2 for the undeclared public URL, got:\n%v", ve)
	}
	if !ve.HasRule(RuleMemoryStore) {
		t.Errorf("expected RS-12 for the memory driver in production, got:\n%v", ve)
	}
}

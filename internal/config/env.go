package config

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// envBinding ties one AWESOME_AUTH_* variable to one dotted path and knows how
// to apply it. Every override in spec §1 is a row in this table; nothing reads
// the process environment outside it, which is what makes the override surface
// enumerable (see EnvBindings) and testable.
type envBinding struct {
	env  string
	path string
	set  func(c *Config, raw string) error
}

// EnvBindings returns every AWESOME_AUTH_* variable this build honours, paired
// with the dotted path it overrides, sorted by variable name.
//
// It is exported because the deployment tooling needs it: a stack template that
// passes an environment variable no build reads is a misconfiguration the
// operator should hear about before the deploy, not after.
func EnvBindings() []struct{ Env, Path string } {
	rows := envBindings()
	out := make([]struct{ Env, Path string }, 0, len(rows))
	for _, b := range rows {
		out = append(out, struct{ Env, Path string }{b.env, b.path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env < out[j].Env })
	return out
}

// SecretEnvNames returns the AWESOME_AUTH_* variables that carry secret values
// for the fixed (non-oauth) secret knobs. These are resolved through the
// SecretResolver chain rather than the binding table, so they are listed
// separately; the deployment tooling needs both lists to validate a template.
func SecretEnvNames() []struct{ Env, Path string } {
	out := make([]struct{ Env, Path string }, 0, 16)
	for _, slot := range secretSlots(Defaults()) {
		out = append(out, struct{ Env, Path string }{slot.env, slot.path})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Env < out[j].Env })
	return out
}

// applyEnv layers the environment over whatever the document produced. Values
// that fail to parse are reported against their dotted path with the variable
// named as the source, not silently dropped: an operator who typed
// AWESOME_AUTH_COOKIES_SECURE=yes-please must not end up with an insecure
// cookie because a strconv call failed quietly.
func applyEnv(c *Config, getenv func(string) (string, bool), d *diagnostics) {
	for _, b := range envBindings() {
		raw, ok := getenv(b.env)
		if !ok {
			continue
		}
		// Record the source before applying, so a parse failure can still say
		// which variable it came from.
		c.sources[b.path] = b.env
		if err := b.set(c, raw); err != nil {
			d.errf("", b.path, err.Error(), "fix the value of "+b.env)
		}
	}
}

func envString(env, path string, set func(*Config, string)) envBinding {
	return envBinding{env, path, func(c *Config, raw string) error {
		set(c, strings.TrimSpace(raw))
		return nil
	}}
}

func envBool(env, path string, set func(*Config, bool)) envBinding {
	return envBinding{env, path, func(c *Config, raw string) error {
		v, err := parseBool(raw)
		if err != nil {
			return err
		}
		set(c, v)
		return nil
	}}
}

func envInt(env, path string, set func(*Config, int)) envBinding {
	return envBinding{env, path, func(c *Config, raw string) error {
		v, err := strconv.Atoi(strings.TrimSpace(raw))
		if err != nil {
			return fmt.Errorf("%q is not an integer", raw)
		}
		set(c, v)
		return nil
	}}
}

// envList splits on commas. Empty entries are dropped so that a trailing comma,
// which every hand-edited template eventually grows, does not become an empty
// allowed origin.
func envList(env, path string, set func(*Config, []string)) envBinding {
	return envBinding{env, path, func(c *Config, raw string) error {
		parts := strings.Split(raw, ",")
		out := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				out = append(out, p)
			}
		}
		set(c, out)
		return nil
	}}
}

// envDuration stores the raw string together with its parse outcome, so a
// malformed TTL is reported by RS-9 with its path rather than here with a
// strconv message.
func envDuration(env, path string, set func(*Config, Duration)) envBinding {
	return envBinding{env, path, func(c *Config, raw string) error {
		d, _ := ParseDuration(strings.TrimSpace(raw))
		set(c, d)
		return nil
	}}
}

// parseBool accepts the spellings that appear in CloudFormation templates and
// hand-written .env files. Anything else is an error, deliberately: silently
// treating an unrecognised value as false is how a security knob gets turned off
// by accident.
func parseBool(raw string) (bool, error) {
	switch normalizeEnum(raw) {
	case "true", "1", "yes", "y", "on":
		return true, nil
	case "false", "0", "no", "n", "off":
		return false, nil
	default:
		return false, fmt.Errorf("%q is not a boolean; use true or false", raw)
	}
}

// envBindings is the full override table of spec §1. Variable names are taken
// verbatim from the spec, including the places where they abbreviate the dotted
// path (AWESOME_AUTH_JWT_ACCESS_SECRET for security.jwt.accessTokenSecret), so
// that documents, documentation and templates agree.
func envBindings() []envBinding {
	bindings := []envBinding{
		// deployment (product-only; see the Deployment type comment)
		envString("AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT", "deployment.environment", func(c *Config, v string) { c.Deployment.Environment = v }),
		envString("AWESOME_AUTH_DEPLOYMENT_STAGE", "deployment.stage", func(c *Config, v string) { c.Deployment.Stage = v }),
		envString("AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL", "deployment.publicUrl", func(c *Config, v string) { c.Deployment.PublicURL = v }),

		// §1.1 tokens and secrets. The two signing secrets are absent on purpose:
		// they resolve through the SecretResolver chain (see SecretEnvNames).
		envDuration("AWESOME_AUTH_JWT_ACCESS_TTL", "security.jwt.accessTokenTtl", func(c *Config, v Duration) { c.Security.JWT.AccessTokenTTL = v }),
		envDuration("AWESOME_AUTH_JWT_REFRESH_TTL", "security.jwt.refreshTokenTtl", func(c *Config, v Duration) { c.Security.JWT.RefreshTokenTTL = v }),
		envString("AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_URL", "security.jwt.claimsWebhook.url", func(c *Config, v string) { c.Security.JWT.ClaimsWebhook.URL = v }),
		envInt("AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS", "security.jwt.claimsWebhook.timeoutMs", func(c *Config, v int) { c.Security.JWT.ClaimsWebhook.TimeoutMs = v }),
		envInt("AWESOME_AUTH_BCRYPT_SALT_ROUNDS", "security.password.bcryptSaltRounds", func(c *Config, v int) { c.Security.Password.BcryptSaltRounds = v }),
		envInt("AWESOME_AUTH_TOKENS_PASSWORD_RESET_TTL_MINUTES", "tokens.passwordResetTtlMinutes", func(c *Config, v int) { c.Tokens.PasswordResetTTLMinutes = v }),
		envInt("AWESOME_AUTH_TOKENS_EMAIL_VERIFICATION_TTL_MINUTES", "tokens.emailVerificationTtlMinutes", func(c *Config, v int) { c.Tokens.EmailVerificationTTLMinutes = v }),
		envInt("AWESOME_AUTH_TOKENS_EMAIL_CHANGE_TTL_MINUTES", "tokens.emailChangeTtlMinutes", func(c *Config, v int) { c.Tokens.EmailChangeTTLMinutes = v }),
		envInt("AWESOME_AUTH_TOKENS_ACCOUNT_LINK_TTL_MINUTES", "tokens.accountLinkTtlMinutes", func(c *Config, v int) { c.Tokens.AccountLinkTTLMinutes = v }),
		envInt("AWESOME_AUTH_TOKENS_MAGIC_LINK_TTL_MINUTES", "tokens.magicLinkTtlMinutes", func(c *Config, v int) { c.Tokens.MagicLinkTTLMinutes = v }),

		// §1.2 cookies
		envBool("AWESOME_AUTH_COOKIES_SECURE", "cookies.secure", func(c *Config, v bool) { c.Cookies.Secure = v }),
		envString("AWESOME_AUTH_COOKIES_SAMESITE", "cookies.sameSite", func(c *Config, v string) { c.Cookies.SameSite = v }),
		envString("AWESOME_AUTH_COOKIES_DOMAIN", "cookies.domain", func(c *Config, v string) { c.Cookies.Domain = v }),
		envString("AWESOME_AUTH_COOKIES_PATH", "cookies.path", func(c *Config, v string) { c.Cookies.Path = v }),
		envString("AWESOME_AUTH_COOKIES_REFRESH_PATH", "cookies.refreshTokenPath", func(c *Config, v string) { c.Cookies.RefreshTokenPath = v }),
		envBool("AWESOME_AUTH_COOKIES_ALLOW_INSECURE_COOKIE_MODE", "cookies.allowInsecureCookieMode", func(c *Config, v bool) { c.Cookies.AllowInsecureCookieMode = v }),

		// §1.3 CSRF
		envBool("AWESOME_AUTH_CSRF_ENABLED", "security.csrf.enabled", func(c *Config, v bool) { c.Security.CSRF.Enabled = v }),

		// §1.4 sessions
		envString("AWESOME_AUTH_SESSIONS_CHECK_ON", "sessions.checkOn", func(c *Config, v string) { c.Sessions.CheckOn = v }),

		// §1.5 email
		envList("AWESOME_AUTH_EMAIL_SITE_URLS", "email.siteUrls", func(c *Config, v []string) { c.Email.SiteURLs = v }),
		envString("AWESOME_AUTH_MAILER_ENDPOINT", "email.mailer.endpoint", func(c *Config, v string) { c.Email.Mailer.Endpoint = v }),
		envString("AWESOME_AUTH_MAILER_FROM", "email.mailer.from", func(c *Config, v string) { c.Email.Mailer.From = v }),
		envString("AWESOME_AUTH_MAILER_FROM_NAME", "email.mailer.fromName", func(c *Config, v string) { c.Email.Mailer.FromName = v }),
		envString("AWESOME_AUTH_MAILER_PROVIDER", "email.mailer.provider", func(c *Config, v string) { c.Email.Mailer.Provider = v }),
		envString("AWESOME_AUTH_MAILER_DEFAULT_LANG", "email.mailer.defaultLang", func(c *Config, v string) { c.Email.Mailer.DefaultLang = v }),
		envString("AWESOME_AUTH_EMAIL_VERIFICATION_MODE", "email.verification.mode", func(c *Config, v string) { c.Email.Verification.Mode = v }),
		envString("AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_URL", "email.deliveryWebhook.url", func(c *Config, v string) { c.Email.DeliveryWebhook.URL = v }),
		envInt("AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_TIMEOUT_MS", "email.deliveryWebhook.timeoutMs", func(c *Config, v int) { c.Email.DeliveryWebhook.TimeoutMs = v }),

		// §1.6 SMS
		envString("AWESOME_AUTH_SMS_ENDPOINT", "sms.endpoint", func(c *Config, v string) { c.SMS.Endpoint = v }),
		envInt("AWESOME_AUTH_SMS_CODE_TTL_MINUTES", "sms.codeTtlMinutes", func(c *Config, v int) { c.SMS.CodeTTLMinutes = v }),

		// §1.7 OAuth. Only the two built-in providers get documented variables;
		// generic providers are file-only, because a provider that exists solely
		// because an env var was set has no endpoints to talk to.
		envString("AWESOME_AUTH_OAUTH_GOOGLE_CLIENT_ID", "oauth.providers.google.clientId", func(c *Config, v string) { setProviderField(c, "google", func(p *OAuthProvider) { p.ClientID = v }) }),
		envString("AWESOME_AUTH_OAUTH_GOOGLE_CALLBACK_URL", "oauth.providers.google.callbackUrl", func(c *Config, v string) { setProviderField(c, "google", func(p *OAuthProvider) { p.CallbackURL = v }) }),
		envString("AWESOME_AUTH_OAUTH_GOOGLE_PROJECT_ID", "oauth.providers.google.projectId", func(c *Config, v string) { setProviderField(c, "google", func(p *OAuthProvider) { p.ProjectID = v }) }),
		envString("AWESOME_AUTH_OAUTH_GITHUB_CLIENT_ID", "oauth.providers.github.clientId", func(c *Config, v string) { setProviderField(c, "github", func(p *OAuthProvider) { p.ClientID = v }) }),
		envString("AWESOME_AUTH_OAUTH_GITHUB_CALLBACK_URL", "oauth.providers.github.callbackUrl", func(c *Config, v string) { setProviderField(c, "github", func(p *OAuthProvider) { p.CallbackURL = v }) }),
		envBool("AWESOME_AUTH_OAUTH_PROVISIONING_AUTO_CREATE", "oauth.provisioning.autoCreate", func(c *Config, v bool) { c.OAuth.Provisioning.AutoCreate = v }),
		envList("AWESOME_AUTH_OAUTH_PROVISIONING_ALLOWED_EMAIL_DOMAINS", "oauth.provisioning.allowedEmailDomains", func(c *Config, v []string) { c.OAuth.Provisioning.AllowedEmailDomains = v }),
		envBool("AWESOME_AUTH_OAUTH_PROVISIONING_REQUIRE_VERIFIED_EMAIL", "oauth.provisioning.requireVerifiedEmail", func(c *Config, v bool) { c.OAuth.Provisioning.RequireVerifiedEmail = v }),
		envString("AWESOME_AUTH_OAUTH_PROVISIONING_ON_EMAIL_MATCH", "oauth.provisioning.onEmailMatch", func(c *Config, v string) { c.OAuth.Provisioning.OnEmailMatch = v }),

		// §1.8 two-factor
		envString("AWESOME_AUTH_2FA_APP_NAME", "twoFactor.appName", func(c *Config, v string) { c.TwoFactor.AppName = v }),

		// §1.10 identity provider
		envBool("AWESOME_AUTH_IDP_ENABLED", "idProvider.enabled", func(c *Config, v bool) { c.IDProvider.Enabled = v }),
		envString("AWESOME_AUTH_IDP_PUBLIC_KEY", "idProvider.publicKey", func(c *Config, v string) { c.IDProvider.PublicKey = v }),
		envString("AWESOME_AUTH_IDP_JWKS_PATH", "idProvider.jwksPath", func(c *Config, v string) { c.IDProvider.JWKSPath = v }),
		envString("AWESOME_AUTH_IDP_ISSUER", "idProvider.issuer", func(c *Config, v string) { c.IDProvider.Issuer = v }),
		envDuration("AWESOME_AUTH_IDP_ACCESS_TTL", "idProvider.accessTokenTtl", func(c *Config, v Duration) { c.IDProvider.AccessTokenTTL = v }),
		envDuration("AWESOME_AUTH_IDP_REFRESH_TTL", "idProvider.refreshTokenTtl", func(c *Config, v Duration) { c.IDProvider.RefreshTokenTTL = v }),
		envList("AWESOME_AUTH_IDP_JWKS_CORS_ORIGINS", "idProvider.jwksCorsOrigins", func(c *Config, v []string) { c.IDProvider.JWKSCorsOrigins = StringList{Values: v} }),
		// The KMS signer (§1.10 addendum). Both are ordinary values, not
		// secrets: a key id is a pointer to a key nobody can export, which is
		// the whole reason it is preferable to a PEM. The stack template sets
		// them from a CloudFormation parameter.
		envString("AWESOME_AUTH_IDP_KMS_KEY_ID", "idProvider.kmsKeyId", func(c *Config, v string) { c.IDProvider.KMSKeyID = v }),
		envList("AWESOME_AUTH_IDP_KMS_PREVIOUS_KEY_IDS", "idProvider.kmsPreviousKeyIds", func(c *Config, v []string) { c.IDProvider.KMSPreviousKeyIDs = v }),

		// §1.11 resource server
		envBool("AWESOME_AUTH_RS_ENABLED", "resourceServer.enabled", func(c *Config, v bool) { c.ResourceServer.Enabled = v }),
		envString("AWESOME_AUTH_RS_JWKS_URL", "resourceServer.jwksUrl", func(c *Config, v string) { c.ResourceServer.JWKSURL = v }),
		envString("AWESOME_AUTH_RS_ISSUER", "resourceServer.issuer", func(c *Config, v string) { c.ResourceServer.Issuer = v }),
		envInt("AWESOME_AUTH_RS_JWKS_CACHE_TTL_MS", "resourceServer.jwksCacheTtlMs", func(c *Config, v int) { c.ResourceServer.JWKSCacheTTLMs = v }),
		envInt("AWESOME_AUTH_RS_JWKS_FETCH_TIMEOUT_MS", "resourceServer.jwksFetchTimeoutMs", func(c *Config, v int) { c.ResourceServer.JWKSFetchTimeoutMs = v }),

		// §1.12 UI
		envBool("AWESOME_AUTH_UI_ENABLED", "ui.enabled", func(c *Config, v bool) { c.UI.Enabled = v }),
		envBool("AWESOME_AUTH_UI_HEADLESS", "ui.headless", func(c *Config, v bool) { c.UI.Headless = v }),
		envString("AWESOME_AUTH_UI_LOGO_URL", "ui.branding.logoUrl", func(c *Config, v string) { c.UI.Branding.LogoURL = v }),
		envString("AWESOME_AUTH_UI_PRIMARY_COLOR", "ui.branding.primaryColor", func(c *Config, v string) { c.UI.Branding.PrimaryColor = v }),
		envString("AWESOME_AUTH_UI_SECONDARY_COLOR", "ui.branding.secondaryColor", func(c *Config, v string) { c.UI.Branding.SecondaryColor = v }),
		envString("AWESOME_AUTH_UI_SITE_NAME", "ui.branding.siteName", func(c *Config, v string) { c.UI.Branding.SiteName = v }),
		envString("AWESOME_AUTH_UI_BG_COLOR", "ui.branding.bgColor", func(c *Config, v string) { c.UI.Branding.BgColor = v }),
		envString("AWESOME_AUTH_UI_BG_IMAGE", "ui.branding.bgImage", func(c *Config, v string) { c.UI.Branding.BgImage = v }),
		envString("AWESOME_AUTH_UI_CARD_BG", "ui.branding.cardBg", func(c *Config, v string) { c.UI.Branding.CardBg = v }),
		envString("AWESOME_AUTH_UI_UPLOAD_DIR", "ui.uploadDir", func(c *Config, v string) { c.UI.UploadDir = v }),

		// §1.13 admin
		envBool("AWESOME_AUTH_ADMIN_ENABLED", "admin.enabled", func(c *Config, v bool) { c.Admin.Enabled = v }),
		envString("AWESOME_AUTH_ADMIN_ACCESS_POLICY", "admin.accessPolicy", func(c *Config, v string) { c.Admin.AccessPolicy = v }),
		envString("AWESOME_AUTH_ADMIN_ROOT_EMAIL", "admin.rootUser.email", func(c *Config, v string) { c.Admin.RootUser.Email = v }),
		envString("AWESOME_AUTH_ADMIN_COOKIE_PREFIX", "admin.cookiePrefix", func(c *Config, v string) { c.Admin.CookiePrefix = v }),
		envString("AWESOME_AUTH_ADMIN_LOGIN_PATH", "admin.loginPath", func(c *Config, v string) { c.Admin.LoginPath = v }),
		envString("AWESOME_AUTH_ADMIN_BASE_PATH", "admin.basePath", func(c *Config, v string) { c.Admin.BasePath = v }),
		envDuration("AWESOME_AUTH_ADMIN_SESSION_TTL", "admin.sessionTtl", func(c *Config, v Duration) { c.Admin.SessionTTL = v }),
		envInt("AWESOME_AUTH_ADMIN_UPLOAD_MAX_FILE_SIZE_MB", "admin.upload.maxFileSizeMb", func(c *Config, v int) { c.Admin.Upload.MaxFileSizeMb = v }),

		// §1.14 tools, telemetry, SSE
		envBool("AWESOME_AUTH_TOOLS_ENABLED", "tools.enabled", func(c *Config, v bool) { c.Tools.Enabled = v }),
		envBool("AWESOME_AUTH_TOOLS_TELEMETRY", "tools.telemetry.enabled", func(c *Config, v bool) { c.Tools.Telemetry.Enabled = v }),
		envBool("AWESOME_AUTH_TOOLS_NOTIFY", "tools.notify.enabled", func(c *Config, v bool) { c.Tools.Notify.Enabled = v }),
		envBool("AWESOME_AUTH_TOOLS_STREAM", "tools.stream.enabled", func(c *Config, v bool) { c.Tools.Stream.Enabled = v }),
		envString("AWESOME_AUTH_TOOLS_AUTH", "tools.auth", func(c *Config, v string) { c.Tools.Auth = v }),
		envString("AWESOME_AUTH_TOOLS_BASE_PATH", "tools.basePath", func(c *Config, v string) { c.Tools.BasePath = v }),
		envBool("AWESOME_AUTH_SSE_ENABLED", "tools.sse.enabled", func(c *Config, v bool) { c.Tools.SSE.Enabled = v }),
		envInt("AWESOME_AUTH_TOOLS_SSE_HEARTBEAT_INTERVAL_MS", "tools.sse.heartbeatIntervalMs", func(c *Config, v int) { c.Tools.SSE.HeartbeatIntervalMs = v }),
		envBool("AWESOME_AUTH_TOOLS_SSE_DEDUPLICATE", "tools.sse.deduplicate", func(c *Config, v bool) { c.Tools.SSE.Deduplicate = v }),

		// §1.15 webhooks
		envBool("AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS", "tools.inboundWebhooks.enabled", func(c *Config, v bool) { c.Tools.InboundWebhooks.Enabled = v }),
		envInt("AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_TIMEOUT_MS", "tools.inboundWebhooks.scriptTimeoutMs", func(c *Config, v int) { c.Tools.InboundWebhooks.ScriptTimeoutMs = v }),
		// D9d: the script runner's function.
		envString("AWESOME_AUTH_TOOLS_INBOUND_WEBHOOKS_SCRIPT_RUNNER_FUNCTION", "tools.inboundWebhooks.scriptRunnerFunction", func(c *Config, v string) { c.Tools.InboundWebhooks.ScriptRunnerFunction = v }),
		envString("AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_PAYLOAD_VERSION", "tools.outboundWebhooks.payloadVersion", func(c *Config, v string) { c.Tools.OutboundWebhooks.PayloadVersion = v }),
		envInt("AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_MAX_RETRIES", "tools.outboundWebhooks.defaults.maxRetries", func(c *Config, v int) { c.Tools.OutboundWebhooks.Defaults.MaxRetries = v }),
		envInt("AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_RETRY_DELAY_MS", "tools.outboundWebhooks.defaults.retryDelayMs", func(c *Config, v int) { c.Tools.OutboundWebhooks.Defaults.RetryDelayMs = v }),
		// D9b: the webhook queue.
		envString("AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_QUEUE_URL", "tools.outboundWebhooks.queueUrl", func(c *Config, v string) { c.Tools.OutboundWebhooks.QueueURL = v }),

		// §1.16 rate limiting
		envBool("AWESOME_AUTH_RATE_LIMIT_ENABLED", "rateLimit.enabled", func(c *Config, v bool) { c.RateLimit.Enabled = v }),
		envInt("AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS", "rateLimit.windowSeconds", func(c *Config, v int) { c.RateLimit.WindowSeconds = v }),
		envInt("AWESOME_AUTH_RATE_LIMIT_MAX", "rateLimit.max", func(c *Config, v int) { c.RateLimit.Max = v }),
		envString("AWESOME_AUTH_RATE_LIMIT_KEY_BY", "rateLimit.keyBy", func(c *Config, v string) { c.RateLimit.KeyBy = v }),
		// §1.16 left the scope file-only in Phase 0, on the assumption that a
		// list belongs in a document. Every other list in this schema has an
		// override anyway — siteUrls, cors.origins, the two IdP lists — and this
		// one has a reason of its own: the scope is the knob an operator reaches
		// for in an incident, to widen it while something is under attack or to
		// narrow it while a client is being fixed, and an environment variable is
		// the only change a Lambda takes without a redeploy of the artifact. Comma
		// separated, like the rest; an empty value is an empty scope and therefore
		// switches the limiter off, which is the same thing an empty list in the
		// document means.
		envList("AWESOME_AUTH_RATE_LIMIT_SCOPE", "rateLimit.scope", func(c *Config, v []string) { c.RateLimit.Scope = v }),

		// §1.17 stores
		envString("AWESOME_AUTH_STORES_DRIVER", "stores.driver", func(c *Config, v string) { c.Stores.Driver = v }),
		envString("AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", "stores.connection.tableName", func(c *Config, v string) { c.Stores.Connection.TableName = v }),
		envString("AWESOME_AUTH_STORES_CONNECTION_DSN", "stores.connection.dsn", func(c *Config, v string) { c.Stores.Connection.DSN = v }),
		envString("AWESOME_AUTH_STORES_CONNECTION_REGION", "stores.connection.region", func(c *Config, v string) { c.Stores.Connection.Region = v }),
		envString("AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", "stores.connection.endpoint", func(c *Config, v string) { c.Stores.Connection.Endpoint = v }),
		envString("AWESOME_AUTH_STORES_CONNECTION_USERNAME", "stores.connection.username", func(c *Config, v string) { c.Stores.Connection.Username = v }),

		// stores.migration.*: the block has no section in the extracted schema —
		// it has no counterpart in the reference at all — so the variable names
		// are invented to the same AWESOME_AUTH_ + upper-snaked-path convention
		// the §1.19 seeds use. Every knob of the block has one: a migration is
		// operated by changing a stack parameter and redeploying, and a block
		// that could only be configured from a baked-in document would mean
		// rebuilding the artifact to turn dual-read off.
		envString("AWESOME_AUTH_STORES_MIGRATION_SOURCE", "stores.migration.source", func(c *Config, v string) { c.Stores.Migration.Source = v }),
		envString("AWESOME_AUTH_STORES_MIGRATION_USER_POOL_ID", "stores.migration.userPoolId", func(c *Config, v string) { c.Stores.Migration.UserPoolID = v }),
		envString("AWESOME_AUTH_STORES_MIGRATION_CLIENT_ID", "stores.migration.clientId", func(c *Config, v string) { c.Stores.Migration.ClientID = v }),
		envString("AWESOME_AUTH_STORES_MIGRATION_REGION", "stores.migration.region", func(c *Config, v string) { c.Stores.Migration.Region = v }),
		envString("AWESOME_AUTH_STORES_MIGRATION_MODE", "stores.migration.mode", func(c *Config, v string) { c.Stores.Migration.Mode = v }),

		// §1.18 HTTP surface and docs
		envString("AWESOME_AUTH_HTTP_API_PREFIX", "http.apiPrefix", func(c *Config, v string) { c.HTTP.APIPrefix = v }),
		envList("AWESOME_AUTH_CORS_ORIGINS", "http.cors.origins", func(c *Config, v []string) { c.HTTP.CORS.Origins = v }),
		envString("AWESOME_AUTH_DOCS_SWAGGER", "docs.swagger", func(c *Config, v string) { c.Docs.Swagger = v }),
		envString("AWESOME_AUTH_DOCS_BASE_PATH", "docs.basePath", func(c *Config, v string) { c.Docs.BasePath = v }),

		// §1.19 runtime-mutable seeds. The spec says the boot seed comes from
		// "file/env" but names no variables, so these are invented to the
		// AWESOME_AUTH_ + upper-snaked-path convention.
		envBool("AWESOME_AUTH_RUNTIME_SETTINGS_REQUIRE_2FA", "runtimeSettings.require2fa", func(c *Config, v bool) { c.RuntimeSettings.Require2FA = v }),
		envList("AWESOME_AUTH_RUNTIME_SETTINGS_ENABLED_WEBHOOK_ACTIONS", "runtimeSettings.enabledWebhookActions", func(c *Config, v []string) { c.RuntimeSettings.EnabledWebhookActions = v }),
		envInt("AWESOME_AUTH_RUNTIME_SETTINGS_LAZY_EMAIL_VERIFICATION_GRACE_PERIOD_DAYS", "runtimeSettings.lazyEmailVerificationGracePeriodDays", func(c *Config, v int) {
			c.RuntimeSettings.LazyEmailVerificationGracePeriodDays = v
		}),
	}

	// stores.enable.<store>: one variable per store, generated from the single
	// table in config.go so that adding a store cannot leave a gap here.
	for _, f := range storeFields(&StoreEnable{}) {
		name := f.name
		bindings = append(bindings, envBool(
			"AWESOME_AUTH_STORES_ENABLE_"+upperSnake(name),
			"stores.enable."+name,
			func(c *Config, v bool) {
				for _, target := range storeFields(&c.Stores.Enable) {
					if target.name == name {
						*target.ptr = v
						return
					}
				}
			},
		))
	}

	return bindings
}

// setProviderField mutates one provider entry, creating the map and the entry if
// the operator configured a provider purely through the environment.
func setProviderField(c *Config, name string, mutate func(*OAuthProvider)) {
	if c.OAuth.Providers == nil {
		c.OAuth.Providers = make(map[string]OAuthProvider)
	}
	p := c.OAuth.Providers[name]
	mutate(&p)
	c.OAuth.Providers[name] = p
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

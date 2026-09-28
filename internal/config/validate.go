package config

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// validate checks types, ranges and enumerations. It is separate from checkRules
// because the two answer different questions: this file asks "is this value even
// a value", spec §2 asks "is this combination of valid values safe".
func validate(c *Config, d *diagnostics) {
	validateDeployment(c, d)
	validateJWT(c, d)
	validateTokens(c, d)
	validateCookies(c, d)
	validateSessions(c, d)
	validateEmail(c, d)
	validateSMS(c, d)
	validateOAuth(c, d)
	validateTwoFactor(c, d)
	validateIDProvider(c, d)
	validateResourceServer(c, d)
	validateUI(c, d)
	validateAdmin(c, d)
	validateTools(c, d)
	validateRateLimit(c, d)
	validateStores(c, d)
	validateHTTPAndDocs(c, d)
}

func validateDeployment(c *Config, d *diagnostics) {
	enum(d, "deployment.environment", c.Deployment.Environment, EnvironmentProduction, EnvironmentDevelopment)
	if c.Deployment.PublicURL != "" {
		absoluteURL(d, "deployment.publicUrl", c.Deployment.PublicURL, false)
	}
}

func validateJWT(c *Config, d *diagnostics) {
	// RS-9 is the rule that covers TTL syntax; report it here, where the parse
	// error is, rather than duplicating the walk in rules.go.
	ttl(d, "security.jwt.accessTokenTtl", c.Security.JWT.AccessTokenTTL, true)
	ttl(d, "security.jwt.refreshTokenTtl", c.Security.JWT.RefreshTokenTTL, true)

	if rounds := c.Security.Password.BcryptSaltRounds; rounds < 10 || rounds > 15 {
		d.errf("", "security.password.bcryptSaltRounds",
			fmt.Sprintf("bcrypt cost %d is outside the supported range 10-15", rounds),
			"use 12 unless a benchmark on the deployed memory size says otherwise")
	}

	// The six claims the reference always writes
	// (src/router/auth.router.ts:378-384). Overwriting one of them from a
	// mapping table would change what every client in the family reads out of a
	// token, so it is refused rather than merged.
	base := map[string]struct{}{
		"sub": {}, "email": {}, "role": {}, "loginProvider": {},
		"isEmailVerified": {}, "isTotpEnabled": {},
	}
	for _, name := range sortedKeys(c.Security.JWT.ExtraClaims) {
		path := "security.jwt.extraClaims." + name
		if _, clash := base[name]; clash {
			d.errf("", path,
				fmt.Sprintf("%q is one of the six base claims and cannot be redefined", name),
				"choose a different claim name, or use a namespaced one such as https://example.com/"+name)
		}
		claim := c.Security.JWT.ExtraClaims[name]
		if claim.FromUserField == "" && claim.Const == nil {
			d.errf("", path,
				"the claim defines neither fromUserField nor const",
				"set fromUserField to a user attribute, or const to a fixed value")
		}
		if claim.FromUserField != "" && claim.Const != nil {
			d.errf("", path,
				"the claim defines both fromUserField and const",
				"keep exactly one of them")
		}
	}

	validateSignedWebhook(c, d, signedWebhook{
		base: "security.jwt.claimsWebhook",
		hook: c.Security.JWT.ClaimsWebhook,
		noSecret: "the claims webhook has no signing secret, and every request to it carries the user profile while its answer decides " +
			"what the token authorises, which an unsigned receiver can neither attribute nor be attributed",
		noTimeout:     "the claims webhook has no positive timeout, so a slow endpoint would stall every login",
		timeoutRemedy: "set a timeout in milliseconds, e.g. 2000",
	})
}

func validateTokens(c *Config, d *diagnostics) {
	atLeast(d, "tokens.passwordResetTtlMinutes", c.Tokens.PasswordResetTTLMinutes, 5)
	atLeast(d, "tokens.emailVerificationTtlMinutes", c.Tokens.EmailVerificationTTLMinutes, 5)
	atLeast(d, "tokens.emailChangeTtlMinutes", c.Tokens.EmailChangeTTLMinutes, 5)
	atLeast(d, "tokens.accountLinkTtlMinutes", c.Tokens.AccountLinkTTLMinutes, 5)
	atLeast(d, "tokens.magicLinkTtlMinutes", c.Tokens.MagicLinkTTLMinutes, 1)
}

func validateCookies(c *Config, d *diagnostics) {
	enum(d, "cookies.sameSite", c.Cookies.SameSite, SameSiteStrict, SameSiteLax, SameSiteNone)
	absolutePath(d, "cookies.path", c.Cookies.Path)
	absolutePath(d, "cookies.refreshTokenPath", c.Cookies.RefreshTokenPath)

	if dom := c.Cookies.Domain; dom != "" {
		if strings.ContainsAny(dom, "/: ") || !strings.Contains(dom, ".") {
			d.errf("", "cookies.domain",
				fmt.Sprintf("%q is not a registrable domain", dom),
				"use a bare host such as example.com, with no scheme, port or path")
		}
	}
}

func validateSessions(c *Config, d *diagnostics) {
	enum(d, "sessions.checkOn", c.Sessions.CheckOn, SessionCheckOnAllCalls, SessionCheckOnRefresh, SessionCheckOnNone)
}

func validateEmail(c *Config, d *diagnostics) {
	enum(d, "email.verification.mode", c.Email.Verification.Mode, EmailVerificationNone, EmailVerificationLazy, EmailVerificationStrict)
	enum(d, "email.mailer.defaultLang", c.Email.Mailer.DefaultLang, "en", "it")

	for i, u := range c.Email.SiteURLs {
		absoluteURL(d, fmt.Sprintf("email.siteUrls[%d]", i), u, false)
	}

	mailerConfigured := c.Email.Mailer.Endpoint != "" || c.Email.Mailer.From != "" || c.Email.Mailer.APIKey.configured()
	if mailerConfigured {
		if c.Email.Mailer.Endpoint == "" {
			d.errf("", "email.mailer.endpoint",
				"the mailer block is configured but has no endpoint",
				"set the https URL the mailer posts to, or remove the whole email.mailer block")
		} else {
			absoluteURL(d, "email.mailer.endpoint", c.Email.Mailer.Endpoint, true)
		}
		if c.Email.Mailer.From == "" {
			d.errf("", "email.mailer.from",
				"the mailer block is configured but has no from address",
				"set email.mailer.from to the sender address the transport is allowed to use")
		} else {
			emailAddress(d, "email.mailer.from", c.Email.Mailer.From)
		}
	}
	validateSignedWebhook(c, d, signedWebhook{
		base: "email.deliveryWebhook",
		hook: c.Email.DeliveryWebhook,
		noSecret: "the delivery webhook has no signing secret, and every request to it carries a credential that an unsigned " +
			"receiver cannot tell from a replay",
	})
}

// signedWebhook is one of the schema's two outbound webhooks, with the wording
// the shared check cannot share: what the requests carry differs, and a
// diagnostic that said "a credential" about the claims webhook would be telling
// the operator something untrue about the knob they are fixing.
type signedWebhook struct {
	// base is the dotted prefix, e.g. "email.deliveryWebhook".
	base string
	hook Webhook
	// noSecret is the problem text of a url with no signing secret.
	noSecret string
	// noTimeout and timeoutRemedy replace the generic positive() diagnostic
	// when the block has something more useful to say about the deadline.
	// Empty leaves the generic one, which quotes the configured value.
	noTimeout, timeoutRemedy string
}

// maxWebhookTimeoutMs is the ceiling on both webhooks' timeoutMs.
//
// A floor alone is not the rule these knobs need. Every mint — login, refresh,
// the 2FA step-up — and every GET /me waits on the claims receiver inside the
// invocation, and four credential routes wait on the delivery one; the whole
// point of the knob, and of the sentence the SAM parameter uses to describe it,
// is that a slow receiver becomes a fast 500 rather than a hung function. A
// ten-minute deadline does not bound anything: it outlives the function Timeout
// (900 s at most, and far less in practice), so the invocation fails before the
// deadline fires and the route answers nothing at all rather than the 500 the
// design promises.
//
// The number is the MaxValue of the CFN parameter ClaimsWebhookTimeoutMs, and
// it lives here rather than only there because CloudFormation bounds one way of
// supplying the value. AWESOME_AUTH_JWT_CLAIMS_WEBHOOK_TIMEOUT_MS set on the
// function by any other means, or timeoutMs written into the configuration
// document, reaches the loader without passing a CFN parameter at all — so a
// rule that lived only in the template would be a rule the product does not
// actually have. email.deliveryWebhook.timeoutMs has no parameter of its own
// and arrives only by those two routes, which is exactly why it gets the same
// ceiling here.
const maxWebhookTimeoutMs = 10000

// validateSignedWebhook: a webhook is a url, a positive timeout and a signing
// secret, together or not at all.
//
// The secret is not optional the way the reference's outbound-webhook secret
// is, for the reasons the Webhook type records — one reason per block, which is
// why the problem text is a field here rather than a constant. The check runs
// after the secrets resolved, so it sees the value rather than the reference: a
// Secrets Manager entry that exists but is empty is refused too.
func validateSignedWebhook(c *Config, d *diagnostics, w signedWebhook) {
	urlPath, secretPath := w.base+".url", w.base+".secret"
	u := strings.TrimSpace(w.hook.URL)
	if u == "" {
		if w.hook.Secret.configured() {
			d.errf("", urlPath,
				secretPath+" references a signing secret but no url is set, so nothing would ever be signed",
				"set "+urlPath+" to the https receiver, or remove the secret reference")
		}
		return
	}
	// The origin-only variant, not the generic one: see absoluteURLOrigin.
	absoluteURLOrigin(d, urlPath, u, true)
	switch {
	case w.hook.TimeoutMs > maxWebhookTimeoutMs:
		d.errf("", w.base+".timeoutMs",
			fmt.Sprintf("%d ms is above the ceiling of %d ms, and a deadline longer than the invocation bounds nothing",
				w.hook.TimeoutMs, maxWebhookTimeoutMs),
			fmt.Sprintf("set a value between 1 and %d; a receiver that needs longer than that has to be asked asynchronously, not inside the request", maxWebhookTimeoutMs))
	case w.hook.TimeoutMs > 0:
	case w.noTimeout != "":
		d.errf("", w.base+".timeoutMs", w.noTimeout, w.timeoutRemedy)
	default:
		positive(d, w.base+".timeoutMs", w.hook.TimeoutMs)
	}
	if c.secretFailed(secretPath) {
		// The resolution failure is already reported against the knob.
		return
	}
	if c.SecretValue(secretPath) == "" {
		d.errf("", secretPath, w.noSecret,
			"reference it from a store -- "+secretPath+": {secretsManager: <id>} -- or set "+envNameFor(c, secretPath)+" for development")
	}
}

func validateSMS(c *Config, d *diagnostics) {
	configured := c.SMS.Endpoint != "" || c.SMS.APIKey.configured() || c.SMS.Username.configured() || c.SMS.Password.configured()
	if !configured {
		return
	}
	if c.SMS.Endpoint == "" {
		d.errf("", "sms.endpoint",
			"the sms block is configured but has no endpoint",
			"set the https URL of the SMS gateway, or remove the whole sms block")
	} else {
		absoluteURL(d, "sms.endpoint", c.SMS.Endpoint, true)
	}
	atLeast(d, "sms.codeTtlMinutes", c.SMS.CodeTTLMinutes, 1)
}

func validateOAuth(c *Config, d *diagnostics) {
	for _, name := range sortedKeys(c.OAuth.Providers) {
		p := c.OAuth.Providers[name]
		base := "oauth.providers." + name
		if p.CallbackURL != "" {
			absoluteURL(d, base+".callbackUrl", p.CallbackURL, false)
		}
		if isBuiltinOAuthProvider(name) {
			// Endpoints and scopes are hardcoded per built-in provider in the
			// reference; accepting overrides here would let a document silently
			// point "google" at somebody else's authorization server.
			for field, value := range map[string]string{
				".authorizationUrl": p.AuthorizationURL,
				".tokenUrl":         p.TokenURL,
				".userInfoUrl":      p.UserInfoURL,
			} {
				if value != "" {
					d.errf("", base+field,
						fmt.Sprintf("%s is a built-in provider whose endpoints are fixed", name),
						"remove the endpoint override, or configure a generic provider under a different name")
				}
			}
			continue
		}
		for field, value := range map[string]string{
			".authorizationUrl": p.AuthorizationURL,
			".tokenUrl":         p.TokenURL,
			".userInfoUrl":      p.UserInfoURL,
		} {
			if value == "" {
				d.errf("", base+field,
					fmt.Sprintf("generic provider %q is missing this endpoint", name),
					"supply authorizationUrl, tokenUrl and userInfoUrl, or use a built-in provider name")
				continue
			}
			// https, except on a loopback host outside production. The token
			// endpoint is posted the client secret and the userinfo endpoint is
			// sent the access token, so plaintext to anywhere reachable is a
			// credential on the wire — but a request to 127.0.0.1 never leaves
			// the host, and an identity provider running beside the process (a
			// dev Keycloak or Dex) has no certificate to present. That is the
			// carve-out RFC 8252 §8.3 makes for the same reason.
			//
			// It is gated on the environment because the premise fails in a
			// production deployment of this product: under Lambda no identity
			// provider can live beside the function, and 127.0.0.1 there is
			// where the runtime API listens — so a production document pointing
			// tokenUrl at loopback is not a dev convenience, it is a client
			// secret POSTed to the execution environment's own control plane.
			requireHTTPS := !(isLoopbackURL(value) && !c.IsProduction())
			absoluteURL(d, base+field, value, requireHTTPS)
		}
	}
	enum(d, "oauth.provisioning.onEmailMatch", c.OAuth.Provisioning.OnEmailMatch,
		OAuthEmailMatchLink, OAuthEmailMatchConflict, OAuthEmailMatchReject)
	for i, dom := range c.OAuth.Provisioning.AllowedEmailDomains {
		if strings.ContainsAny(dom, "@/: ") || !strings.Contains(dom, ".") {
			d.errf("", fmt.Sprintf("oauth.provisioning.allowedEmailDomains[%d]", i),
				fmt.Sprintf("%q is not a domain", dom),
				"list bare domains such as example.com, without the @")
		}
	}
}

func validateTwoFactor(c *Config, d *diagnostics) {
	if strings.TrimSpace(c.TwoFactor.AppName) == "" {
		d.errf("", "twoFactor.appName",
			"the TOTP issuer name is empty, which produces an otpauth URI no authenticator app can label",
			"set twoFactor.appName to the name users should see in their authenticator")
	}
}

func validateIDProvider(c *Config, d *diagnostics) {
	ttl(d, "idProvider.accessTokenTtl", c.IDProvider.AccessTokenTTL, c.IDProvider.active())
	ttl(d, "idProvider.refreshTokenTtl", c.IDProvider.RefreshTokenTTL, c.IDProvider.active())
	absolutePath(d, "idProvider.jwksPath", c.IDProvider.JWKSPath)
	if c.IDProvider.Issuer != "" {
		absoluteURL(d, "idProvider.issuer", c.IDProvider.Issuer, true)
	}
	if err := c.IDProvider.JWKSCorsOrigins.parseErr(); err != nil {
		d.errf("", "idProvider.jwksCorsOrigins", err.Error(),
			`use "*" or a list of origins such as ["https://app.example.com"]`)
	}
	for i, o := range c.IDProvider.JWKSCorsOrigins.Values {
		if o == "*" {
			continue
		}
		absoluteURL(d, fmt.Sprintf("idProvider.jwksCorsOrigins[%d]", i), o, false)
	}
	if key := c.IDProvider.PublicKey; key != "" && !strings.Contains(key, "-----BEGIN") {
		d.errf("", "idProvider.publicKey",
			"the public key is not in PEM form",
			"supply the PEM block, beginning with -----BEGIN PUBLIC KEY-----")
	}
	validateIDProviderKMS(c, d)
	validateIDProviderClients(c, d)
}

// validateIDProviderKMS checks the shape of the KMS key references (§1.10
// addendum). Which of privateKey and kmsKeyId may be set is RS-4's question,
// not this one's; this only asks whether the values are usable identifiers.
//
// The check is deliberately shallow. A KMS key can be named as a key id, an
// alias or an ARN, and the three have nothing in common but "no whitespace, not
// empty"; anything stricter would reject a legitimate ARN from a partition
// nobody here has seen. What is worth catching is the mistake that produces a
// silent failure: a duplicate between the primary key and the previous list,
// which would publish the same key twice in the JWKS document under one kid.
func validateIDProviderKMS(c *Config, d *diagnostics) {
	primary := strings.TrimSpace(c.IDProvider.KMSKeyID)
	if primary != c.IDProvider.KMSKeyID || strings.ContainsAny(c.IDProvider.KMSKeyID, " \t\n") {
		d.errf("", "idProvider.kmsKeyId",
			"the key reference carries whitespace",
			"use a bare key id, an alias such as alias/awesome-auth-idp, or the key's ARN")
	}
	seen := map[string]bool{}
	if primary != "" {
		seen[primary] = true
	}
	for i, raw := range c.IDProvider.KMSPreviousKeyIDs {
		path := fmt.Sprintf("idProvider.kmsPreviousKeyIds[%d]", i)
		id := strings.TrimSpace(raw)
		switch {
		case id == "":
			d.errf("", path,
				"the entry is empty",
				"remove it; an empty key reference publishes nothing and fails the JWKS build at cold start")
		case seen[id]:
			d.errf("", path,
				fmt.Sprintf("%q is already listed, or is idProvider.kmsKeyId itself", id),
				"list each retired key once; the primary key is published first and does not belong here")
		default:
			seen[id] = true
		}
	}
	if len(c.IDProvider.KMSPreviousKeyIDs) > 0 && primary == "" {
		d.errf("", "idProvider.kmsPreviousKeyIds",
			"retired KMS keys are listed but idProvider.kmsKeyId is unset, so there is no KMS signer to publish them alongside",
			"set idProvider.kmsKeyId to the key that signs now, or remove the retired list")
	}
}

// validateIDProviderClients checks the OIDC client registry (§1.10 addendum).
//
// Five things are refused, and each of them is a silent failure otherwise:
//
//   - a client with no secret, because the core's token endpoint compares the
//     posted client_secret against the configured one and an empty configured
//     value is satisfied by an empty posted one — anyone holding a stolen
//     authorization code could then redeem it;
//   - a client with no redirect URI, because the authorization endpoint
//     resolves redirect_uri against an exact-match allowlist and an empty one
//     matches nothing, so every authorization request answers 400;
//   - a duplicate client id, because the registry is a map in the core
//     (NewIDP) and the last entry would silently win, taking its secret and its
//     redirect allowlist with it;
//   - a client id outside [A-Za-z0-9_-], and
//   - two client ids that differ only in characters the environment-variable
//     name cannot keep apart.
//
// The last two are one problem. Each client's secret has its own variable,
// "AWESOME_AUTH_IDP_CLIENT_" + upperSnake(id) + "_SECRET" (secret.go), and
// upperSnake maps every byte that is not a letter or a digit to '_'. So
// "my-app", "my.app" and "my_app" are three registry entries — distinct to the
// core, distinct to the duplicate check above — that share one variable, and
// the value meant for one relying party would authenticate another at the token
// endpoint. Constraining the id keeps the two spellings that collide from
// being spellable at all, and the equality check below catches the pair that
// survives the constraint ("my-app" and "my_app").
//
// A redirect URI must be https, or http on a loopback host: that is RFC 8252
// §7.3 for native apps, and it is the only http exception, because the
// authorization code travels in the query string of whatever this names.
func validateIDProviderClients(c *Config, d *diagnostics) {
	seen := map[string]int{}
	envNames := map[string]int{}
	for i, client := range c.IDProvider.Clients {
		base := fmt.Sprintf("idProvider.clients[%d]", i)
		id := strings.TrimSpace(client.ClientID)
		if id == "" {
			d.errf("", base+".clientId",
				"the client entry has no clientId",
				"set clientId to the identifier the relying party sends, or remove the entry")
			continue
		}
		if first, dup := seen[id]; dup {
			d.errf("", base+".clientId",
				fmt.Sprintf("client id %q is already defined by idProvider.clients[%d]", id, first),
				"give each client its own id; the registry is keyed by id and the last entry would silently win")
			continue
		}
		seen[id] = i

		if !isClientIDSafe(id) {
			d.errf("", base+".clientId",
				fmt.Sprintf("client id %q contains a character outside A-Z a-z 0-9 _ -, and the client's secret is read from AWESOME_AUTH_IDP_CLIENT_<ID>_SECRET, where every such character becomes an underscore -- two ids that differ only there would share one secret", id),
				"use letters, digits, underscores and hyphens only, e.g. \"console\" or \"ops-console\"")
			continue
		}
		envName := "AWESOME_AUTH_IDP_CLIENT_" + upperSnake(id) + "_SECRET"
		if first, clash := envNames[envName]; clash {
			d.errf("", base+".clientId",
				fmt.Sprintf("client id %q and the id of idProvider.clients[%d] both derive the environment variable %s, so one relying party's secret would authenticate the other at the token endpoint", id, first, envName),
				"rename one of the two so the ids differ by more than a hyphen or an underscore")
			continue
		}
		envNames[envName] = i

		secretPath := "idProvider.clients." + id + ".clientSecret"
		if !c.secretFailed(secretPath) && c.SecretValue(secretPath) == "" {
			d.errf("", secretPath,
				fmt.Sprintf("client %q has no client secret, and the token endpoint would then accept an empty one from anybody holding an authorization code", id),
				"reference it from a store -- "+secretPath+": {secretsManager: <id>} -- or set "+envNameFor(c, secretPath)+" for development")
		}

		if len(client.RedirectURIs) == 0 {
			d.errf("", base+".redirectUris",
				fmt.Sprintf("client %q has no redirect URIs, and the authorization endpoint matches redirect_uri against this list exactly, so every request would be refused", id),
				"list the exact URIs the relying party redirects to")
			continue
		}
		for j, uri := range client.RedirectURIs {
			redirectURI(d, fmt.Sprintf("%s.redirectUris[%d]", base, j), uri)
		}
	}
}

// redirectURI accepts an https URL, or an http one on a loopback host. The
// authorization code is delivered in this URL's query string, so plain http to
// anywhere else puts a credential on the wire in clear; the loopback exception
// is RFC 8252 §7.3, where the "network" is the user's own machine.
func redirectURI(d *diagnostics, path, raw string) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		d.errf("", path,
			fmt.Sprintf("%q is not an absolute URL", raw),
			"use a full URL including the scheme, e.g. https://app.example.com/callback")
		return
	}
	if u.Scheme == "https" {
		return
	}
	if u.Scheme == "http" && isLoopbackHost(u.Hostname()) {
		return
	}
	d.errf("", path,
		fmt.Sprintf("%q is neither https nor http on a loopback address, and the authorization code arrives in this URL's query string", raw),
		"use https; plain http is accepted only for http://localhost or http://127.0.0.1, the native-app exception of RFC 8252 §7.3")
}

// isClientIDSafe reports whether a client id survives the trip through
// upperSnake unambiguously: letters, digits, '_' and '-' only. A hyphen is
// allowed because it is the conventional spelling of a client id and because
// the pair it can still collide with ("ops-console" and "ops_console") is
// caught by name, with both indices reported.
func isClientIDSafe(id string) bool {
	for i := 0; i < len(id); i++ {
		ch := id[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case ch == '_' || ch == '-':
		default:
			return false
		}
	}
	return true
}

func isLoopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}

func validateResourceServer(c *Config, d *diagnostics) {
	positive(d, "resourceServer.jwksCacheTtlMs", c.ResourceServer.JWKSCacheTTLMs)
	positive(d, "resourceServer.jwksFetchTimeoutMs", c.ResourceServer.JWKSFetchTimeoutMs)
}

func validateUI(c *Config, d *diagnostics) {
	if !c.UI.Enabled {
		return
	}
	if strings.TrimSpace(c.UI.Branding.SiteName) == "" {
		d.errf("", "ui.branding.siteName",
			"the UI is enabled with an empty site name",
			"set ui.branding.siteName, or leave it unset to inherit the default")
	}
	for path, colour := range map[string]string{
		"ui.branding.primaryColor":   c.UI.Branding.PrimaryColor,
		"ui.branding.secondaryColor": c.UI.Branding.SecondaryColor,
	} {
		if colour == "" {
			d.errf("", path, "the colour is empty", "set a CSS colour such as #4a90d9")
		}
	}
}

func validateAdmin(c *Config, d *diagnostics) {
	ttl(d, "admin.sessionTtl", c.Admin.SessionTTL, c.Admin.Enabled)
	absolutePath(d, "admin.basePath", c.Admin.BasePath)
	if c.Admin.LoginPath != "" && !strings.HasPrefix(c.Admin.LoginPath, "/") && !strings.HasPrefix(c.Admin.LoginPath, "http") {
		d.errf("", "admin.loginPath",
			fmt.Sprintf("%q is neither an absolute path nor a URL", c.Admin.LoginPath),
			"use /login or https://example.com/login")
	}
	if p := c.Admin.AccessPolicy; p != "" {
		switch {
		case p == AdminAccessPolicyFirstUser, p == AdminAccessPolicyIsAdmin, p == AdminAccessPolicyOpen:
		case strings.HasPrefix(p, AdminAccessPolicyRBACPrefix) && len(p) > len(AdminAccessPolicyRBACPrefix):
		case strings.HasPrefix(p, AdminAccessPolicyPermPrefix) && len(p) > len(AdminAccessPolicyPermPrefix):
		default:
			d.errf("", "admin.accessPolicy",
				fmt.Sprintf("%q is not a recognised access policy", p),
				"use first-user, is-admin-flag, open, rbac:<role> or permission:<permission>")
		}
	}
	if c.Admin.RootUser.Email != "" {
		emailAddress(d, "admin.rootUser.email", c.Admin.RootUser.Email)
	}
	if mb := c.Admin.Upload.MaxFileSizeMb; mb < 1 || mb > 50 {
		d.errf("", "admin.upload.maxFileSizeMb",
			fmt.Sprintf("%d MB is outside the supported range 1-50", mb),
			"use 5, the reference's own limit and the only value the core honours; the effective ceiling through this API is lower still, "+
				"about 4.4 MiB, because a multipart body arrives base64-encoded inside a 6 MB invocation event (config-reference.md §16.5)")
	}
}

func validateTools(c *Config, d *diagnostics) {
	if c.Tools.Auth != "" {
		enum(d, "tools.auth", c.Tools.Auth, ToolsAuthNone, ToolsAuthSession, ToolsAuthAPIKey, ToolsAuthAdmin)
	}
	absolutePath(d, "tools.basePath", c.Tools.BasePath)
	enum(d, "tools.sse.distributor.type", c.Tools.SSE.Distributor.Type, DistributorNone, DistributorRedis, DistributorSNS)
	switch c.Tools.SSE.Distributor.Type {
	case DistributorRedis:
		if c.Tools.SSE.Distributor.Endpoint == "" {
			d.errf("", "tools.sse.distributor.endpoint",
				"the redis distributor has no endpoint",
				"set the redis endpoint, host:port")
		}
	case DistributorSNS:
		if c.Tools.SSE.Distributor.TopicARN == "" {
			d.errf("", "tools.sse.distributor.topicArn",
				"the sns distributor has no topic",
				"set the ARN of the SNS topic the instances fan out through")
		}
	}
	if t := c.Tools.InboundWebhooks.ScriptTimeoutMs; t < 100 || t > 30000 {
		d.errf("", "tools.inboundWebhooks.scriptTimeoutMs",
			fmt.Sprintf("%d ms is outside the supported range 100-30000", t),
			"the reference hardcodes 5000; stay near it")
	}
	if r := c.Tools.OutboundWebhooks.Defaults.MaxRetries; r < 0 || r > 10 {
		d.errf("", "tools.outboundWebhooks.defaults.maxRetries",
			fmt.Sprintf("%d is outside the supported range 0-10", r),
			"use 3, the reference's per-webhook default")
	}
	atLeast(d, "tools.outboundWebhooks.defaults.retryDelayMs", c.Tools.OutboundWebhooks.Defaults.RetryDelayMs, 100)
}

func validateRateLimit(c *Config, d *diagnostics) {
	if !c.RateLimit.Enabled {
		return
	}
	positive(d, "rateLimit.windowSeconds", c.RateLimit.WindowSeconds)
	positive(d, "rateLimit.max", c.RateLimit.Max)
	enum(d, "rateLimit.keyBy", c.RateLimit.KeyBy, RateLimitKeyByIP, RateLimitKeyByEmail)
	for i, ep := range c.RateLimit.Scope {
		if !knownRateLimitEndpoint(ep) {
			d.errf("", fmt.Sprintf("rateLimit.scope[%d]", i),
				fmt.Sprintf("%q is not a rate-limitable endpoint", ep),
				"pick from "+strings.Join(rateLimitEndpoints, ", "))
		}
	}
}

// rateLimitEndpoints is the set of endpoints the built-in limiter can be pointed
// at. They are the unauthenticated, credential-guessable ones — a limiter on
// anything else would be theatre.
var rateLimitEndpoints = []string{
	"login", "register", "refresh", "forgot-password", "reset-password",
	"magic-link", "sms-code", "2fa-verify", "verify-email", "resend-verification",
}

// RateLimitEndpoints returns the vocabulary rateLimit.scope accepts.
//
// Exported for two readers and neither of them is the validator. The deployment
// tooling checks a document before an upload, the way it does with
// UnwiredDomains; and cmd/auth holds its own route table against this list
// (TestEveryScopeNameMapsToRoutes), because the two halves of "what a scope
// name means" live in different packages — this one says which names exist, that
// one says which routes each covers — and a name in only one of them is either a
// knob that validates and limits nothing or a limiter nobody can switch on.
//
// A copy, so a caller cannot edit the vocabulary by writing to the slice it was
// handed.
func RateLimitEndpoints() []string {
	return append([]string(nil), rateLimitEndpoints...)
}

func knownRateLimitEndpoint(name string) bool {
	for _, e := range rateLimitEndpoints {
		if e == name {
			return true
		}
	}
	return false
}

func validateStores(c *Config, d *diagnostics) {
	enum(d, "stores.driver", c.Stores.Driver, StoreDriverDynamoDB, StoreDriverPostgres, StoreDriverMemory)
	switch c.Stores.Driver {
	case StoreDriverDynamoDB:
		if c.Stores.Connection.TableName == "" {
			d.errf("", "stores.connection.tableName",
				"the dynamodb driver has no table name",
				"set stores.connection.tableName to the single-table name the stack creates")
		}
	case StoreDriverPostgres:
		if c.Stores.Connection.DSN == "" {
			d.errf("", "stores.connection.dsn",
				"the postgres driver has no DSN",
				"set stores.connection.dsn, keeping the password in stores.connection.password rather than in the DSN")
		}
	}
	if !c.Stores.Enable.Users {
		d.errf("", "stores.enable.users",
			"the users store is disabled, and nothing in the service works without it",
			"remove the override: stores.enable.users cannot be turned off")
	}
	validateMigration(c, d)
}

// validateMigration checks the vocabulary of stores.migration.*. Which
// combinations are usable is RS-13's question, in rules.go; this one only asks
// whether each value is a value.
//
// The empty source is accepted here rather than enumerated, because empty is the
// off switch and an enum listing it would read as though "" were a source.
func validateMigration(c *Config, d *diagnostics) {
	m := c.Stores.Migration
	if strings.TrimSpace(m.Source) != "" {
		enum(d, "stores.migration.source", m.Source, MigrationSourceCognito)
	}
	enum(d, "stores.migration.mode", m.Mode, MigrationModeImportOnly, MigrationModeDualRead)
}

func validateHTTPAndDocs(c *Config, d *diagnostics) {
	absolutePath(d, "http.apiPrefix", c.HTTP.APIPrefix)
	for i, o := range c.HTTP.CORS.Origins {
		absoluteURL(d, fmt.Sprintf("http.cors.origins[%d]", i), o, false)
	}
	enum(d, "docs.swagger", c.Docs.Swagger, SwaggerTrue, SwaggerFalse, SwaggerAuto)
	absolutePath(d, "docs.basePath", c.Docs.BasePath)
}

func isBuiltinOAuthProvider(name string) bool {
	return name == "google" || name == "github"
}

// enum reports a value that is not one of the allowed spellings, listing them.
func enum(d *diagnostics, path, got string, allowed ...string) {
	for _, a := range allowed {
		if got == a {
			return
		}
	}
	d.errf("", path,
		fmt.Sprintf("%q is not a valid value", got),
		"use one of "+strings.Join(allowed, ", "))
}

func atLeast(d *diagnostics, path string, got, floor int) {
	if got < floor {
		d.errf("", path,
			fmt.Sprintf("%d is below the minimum of %d", got, floor),
			fmt.Sprintf("set it to %d or more", floor))
	}
}

func positive(d *diagnostics, path string, got int) {
	if got <= 0 {
		d.errf("", path,
			fmt.Sprintf("%d is not a positive number", got),
			"set a value greater than zero")
	}
}

// ttl reports a TTL that does not parse as ms-syntax, and one that is required
// but absent. required is false for TTLs belonging to a block that is switched
// off, so an unset idProvider TTL is not an error on a deployment that has no
// identity-provider mode.
func ttl(d *diagnostics, path string, v Duration, required bool) {
	if v.IsZero() {
		if required {
			d.errf(RuleTTLSyntax, path,
				"the TTL is unset",
				`set an ms-syntax value such as "15m" or "7d"`)
		}
		return
	}
	if err := v.parseErr(); err != nil {
		d.errf(RuleTTLSyntax, path,
			fmt.Sprintf("%q is not a valid ms-syntax duration: %s", v.String(), err.Error()),
			`use a single number-and-unit term such as "15m", "24h" or "7d"`)
		return
	}
	if v.Duration() <= 0 {
		d.errf(RuleTTLSyntax, path,
			fmt.Sprintf("%q resolves to a non-positive duration", v.String()),
			"a token whose lifetime is zero or negative is never valid; use a positive span")
	}
}

func absolutePath(d *diagnostics, path, got string) {
	if got == "" {
		d.errf("", path, "the path is empty", "use an absolute path beginning with /")
		return
	}
	if !strings.HasPrefix(got, "/") {
		d.errf("", path,
			fmt.Sprintf("%q is not an absolute path", got),
			"prefix it with /")
	}
}

// absoluteURL checks that a value is a parsable absolute URL. requireHTTPS is
// set for the knobs the spec marks https-only: an outbound webhook or a token
// endpoint reached over plain http leaks whatever it carries.
func absoluteURL(d *diagnostics, path, got string, requireHTTPS bool) {
	u, err := url.Parse(got)
	if err != nil || u.Scheme == "" || u.Host == "" {
		d.errf("", path,
			fmt.Sprintf("%q is not an absolute URL", got),
			"use a full URL including the scheme, e.g. https://auth.example.com")
		return
	}
	if requireHTTPS && u.Scheme != "https" {
		d.errf("", path,
			fmt.Sprintf("%q does not use https", got),
			"use an https URL; this value carries credentials or token material")
	}
}

// isLoopbackURL reports whether a URL names a host on this machine: the two
// loopback literals, the literal "localhost", and anything in 127.0.0.0/8.
//
// It is what lets an OAuth provider endpoint be plain http outside production
// (validateOAuth): a request to a loopback address never reaches a network, so
// there is nothing for TLS to protect, and a provider that runs beside the
// process has no name to get a certificate for. Neither half of that is true of
// a production deployment of this product, which is why validateOAuth gates the
// carve-out on the environment rather than on this predicate alone. Nothing
// outside that carve-out uses it — a mail gateway, an SMS gateway or a webhook
// receiver on loopback would be a deployment that cannot work under Lambda
// anyway.
//
// A value that does not parse is not loopback, so the https requirement stays
// on and absoluteURL reports the malformed URL rather than waving it through.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || host == "::1" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// absoluteURLOrigin is absoluteURL for a knob whose value must not be echoed
// whole into a diagnostic.
//
// A cold-start failure is written to CloudWatch, and the two webhook urls —
// email.deliveryWebhook.url and security.jwt.claimsWebhook.url — are the knobs
// in this schema whose *path* may itself be a secret: a receiver behind a
// gateway that cannot check an HMAC is commonly given a capability token in the
// path as well, which is why cmd/auth logs only the origin of either
// (webhookOrigin, delivery.go). A refusal that printed the whole value would
// undo that for exactly the deployments most likely to hit it. So https is
// reported against the origin, and a value too malformed to have an origin is
// reported without quoting it at all — there is nothing safe to quote and the
// path already says which knob to look at.
func absoluteURLOrigin(d *diagnostics, path, got string, requireHTTPS bool) {
	u, err := url.Parse(got)
	if err != nil || u.Scheme == "" || u.Host == "" {
		d.errf("", path,
			"the configured value is not an absolute URL (it is not repeated here: this knob's path may carry a capability token)",
			"use a full URL including the scheme, e.g. https://hooks.example.com/auth-delivery")
		return
	}
	if requireHTTPS && u.Scheme != "https" {
		d.errf("", path,
			fmt.Sprintf("%s does not use https", u.Scheme+"://"+u.Host),
			"use an https URL; this value carries credentials or token material")
	}
}

// emailAddress is a deliberately shallow check. Rejecting a deploy over an
// address a mail server would have accepted is worse than letting the transport
// reject it, so only the unambiguous mistakes are caught.
func emailAddress(d *diagnostics, path, got string) {
	at := strings.IndexByte(got, '@')
	if at <= 0 || at == len(got)-1 || strings.ContainsAny(got, " \t") || !strings.Contains(got[at:], ".") {
		d.errf("", path,
			fmt.Sprintf("%q is not an email address", got),
			"use a single address such as no-reply@example.com")
	}
}

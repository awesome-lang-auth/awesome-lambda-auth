package config

import (
	"fmt"
	"net"
	"net/textproto"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// validate checks types, ranges and enumerations. It is separate from checkRules
// because the two answer different questions: this file asks "is this value even
// a value", spec §2 asks "is this combination of valid values safe".
func validate(c *Config, d *diagnostics) {
	validateDeployment(c, d)
	validateJWT(c, d)
	validateForgotPassword(c, d)
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
	// Last, because it reads three paths the validators above have already
	// checked for shape.
	validateMounts(c, d)
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
	// The core refuses to start on an entry that is not a language tag
	// (auth.Config.validate), with a message that names neither the key nor
	// the index; refusing here first does both.
	for i, lang := range c.Email.Languages {
		if !isLanguageTag(lang) {
			d.errf("", fmt.Sprintf("email.languages[%d]", i),
				fmt.Sprintf("%q is not a language tag: one or more subtags of letters and digits separated by - or _, the first of 2 to 8 letters and each at most 8 characters, %d characters in all at most", lang, maxLanguageTagLen),
				`list the languages your senders render, such as ["it", "en"]`)
		}
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
	// 0 is off, and the one way to say it; a negative count is a typo, not a
	// lockout.
	atLeast(d, "twoFactor.lockout.maxFailures", c.TwoFactor.Lockout.MaxFailures, 0)
	if c.TwoFactor.Lockout.MaxFailures > 0 {
		windowSeconds(d, "twoFactor.lockout.windowSeconds", c.TwoFactor.Lockout.WindowSeconds)
	}

	// The enrolment window: 0 keeps the core's TempTokenTTL, anything else is
	// the core's own range, which it would refuse at New with no key named.
	// And only beside enrolOnLogin, the one mode that mints an enrolment
	// token: without it a 2FA_SETUP_REQUIRED tempToken is the step-up token,
	// which keeps TempTokenTTL, so the knob would validate and bound nothing.
	switch ttl := c.TwoFactor.EnrolmentTokenTTLMinutes; {
	case ttl == 0:
	case ttl < MinEnrolmentTokenTTLMinutes || ttl > MaxEnrolmentTokenTTLMinutes:
		d.errf("", "twoFactor.enrolmentTokenTtlMinutes",
			fmt.Sprintf("%d minutes is outside the %d-%d the core accepts for the enrolment token", ttl, MinEnrolmentTokenTTLMinutes, MaxEnrolmentTokenTTLMinutes),
			fmt.Sprintf("set a value between %d and %d, or 0 to keep the default of %d minutes", MinEnrolmentTokenTTLMinutes, MaxEnrolmentTokenTTLMinutes, DefaultEnrolmentTokenTTLMinutes))
	case !c.TwoFactor.EnrolOnLogin:
		d.errf("", "twoFactor.enrolmentTokenTtlMinutes",
			"is set while twoFactor.enrolOnLogin is off: no enrolment token is minted, so the window bounds nothing -- the 2FA_SETUP_REQUIRED tempToken is then the step-up token, which keeps its own five minutes",
			"set twoFactor.enrolOnLogin: true, or remove this key")
	}
}

// MinEnrolmentTokenTTLMinutes and MaxEnrolmentTokenTTLMinutes bound
// twoFactor.enrolmentTokenTtlMinutes. They are the core's own
// auth.MinEnrolmentTokenTTL and auth.MaxEnrolmentTokenTTL in minutes, written
// out because this package does not import the core; cmd/auth
// TestTheLoaderAcceptsOnlyWhatTheCoreAccepts holds the two to each other.
// DefaultEnrolmentTokenTTLMinutes is what 0 keeps: the core's default
// TempTokenTTL, which this product does not configure.
const (
	MinEnrolmentTokenTTLMinutes     = 1
	MaxEnrolmentTokenTTLMinutes     = 30
	DefaultEnrolmentTokenTTLMinutes = 5
)

// MaxForgotPasswordMinResponseMs is the ceiling on
// security.forgotPassword.minResponseMs.
//
// A floor holds every POST <prefix>/forgot-password inside a Lambda invocation
// that bills the time and keeps an execution environment for it, so the ceiling
// is set by the function it runs in rather than by the threat: half the SAM
// template's default Timeout (10 s), and well under its DurationAlarmThresholdMs
// (8000), which a floor near it would trip on ordinary traffic. A floor has to
// exceed the slow branch — the lookup, the delivery and the token write — and
// what bounds the delivery is email.deliveryWebhook.timeoutMs, so a deployment
// that wants a longer floor than this lowers that timeout instead: the floor
// then needs no more. The core ends the hold 100 ms before the invocation's
// deadline whatever the value.
const MaxForgotPasswordMinResponseMs = 5000

// forgotPasswordFloorAllowanceMs is what the slow branch of
// POST <prefix>/forgot-password adds to its delivery, for the warning that
// compares the floor with the delivery webhook's timeout: the account lookup —
// the email pointer, then the profile — the invitation check when invitations
// are on, and the token write, a handful of DynamoDB requests at a few
// milliseconds each, with room for a retry. It is an estimate the warning
// states, not a bound anything enforces.
const forgotPasswordFloorAllowanceMs = 250

// validateForgotPassword checks security.forgotPassword.minResponseMs: 0 is
// off and the one way to say it, a negative floor is refused by the core at
// New with no key named, and the ceiling is MaxForgotPasswordMinResponseMs.
func validateForgotPassword(c *Config, d *diagnostics) {
	const path = "security.forgotPassword.minResponseMs"
	switch floor := c.Security.ForgotPassword.MinResponseMs; {
	case floor < 0:
		d.errf("", path,
			fmt.Sprintf("%d is negative, and the core refuses a negative floor", floor),
			"set 0 to leave the floor off, or a positive number of milliseconds")
	case floor > MaxForgotPasswordMinResponseMs:
		d.errf("", path,
			fmt.Sprintf("%d ms is above the ceiling of %d ms: every request would be held at least that long inside an invocation that bills it, and a floor only has to exceed the delivery, which email.deliveryWebhook.timeoutMs bounds",
				floor, MaxForgotPasswordMinResponseMs),
			fmt.Sprintf("set a value between 0 and %d; to hide a slower delivery, lower email.deliveryWebhook.timeoutMs rather than raising the floor", MaxForgotPasswordMinResponseMs))
	}
}

// maxLanguageTagLen is the longest email.languages entry: the core's own
// bound, the length RFC 5646 §4.4.1 asks every implementation to support.
const maxLanguageTagLen = 35

// isLanguageTag is the core's own shape rule for an EmailLangs entry
// (awesome-go-auth config.go, isLanguageTag, unexported there): one or more
// subtags of ASCII letters and digits separated by '-' or '_', the first of
// two to eight letters and each of one to eight characters, maxLanguageTagLen
// in all. It checks the shape and not the registry, as the core does. Copied
// rather than approximated, because a value this accepts and the core refuses
// is a deployment that validates and then fails its cold start; cmd/auth
// TestTheLoaderAcceptsOnlyWhatTheCoreAccepts runs both over one table.
func isLanguageTag(s string) bool {
	if s == "" || len(s) > maxLanguageTagLen {
		return false
	}
	start := 0
	for i := 0; i <= len(s); i++ {
		if i < len(s) && s[i] != '-' && s[i] != '_' {
			c := s[i] | 0x20 // ASCII lower case; leaves digits as they are
			letter := c >= 'a' && c <= 'z'
			digit := s[i] >= '0' && s[i] <= '9'
			if !letter && (!digit || start == 0) {
				return false
			}
			continue
		}
		n := i - start
		if n < 1 || n > 8 || (start == 0 && n < 2) {
			return false
		}
		start = i + 1
	}
	return true
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
	validateAdminMachineAccess(c, d)
	validateInvitations(c, d)
}

// iamPrincipalARN is an IAM role or user ARN: a partition, a twelve-digit
// account, the resource type, an optional path and a name in IAM's own
// character set. Nothing looser: the value decides who is let into the admin
// API without a session, so a shape this cannot read is refused rather than
// guessed at.
var iamPrincipalARN = regexp.MustCompile(`^arn:[a-z0-9-]+:iam::[0-9]{12}:(role|user)/(?:[!-~]*/)?[A-Za-z0-9+=,.@_-]+$`)

// iamRoleSessionARN is the caller ARN API Gateway reports for a session of a
// role: no path, the role's name and a session name, both in IAM's character
// set.
var iamRoleSessionARN = regexp.MustCompile(`^arn:[a-z0-9-]+:sts::[0-9]{12}:assumed-role/[A-Za-z0-9+=,.@_-]+/[A-Za-z0-9+=,.@_-]+$`)

// IAMPrincipalKey is the identity admin.machineAccess.iam.principals matches
// on, for a configured ARN or for the caller API Gateway reports, and false
// for anything that is neither.
//
// A role is its partition, account and name: a configured
// arn:<p>:iam::<acct>:role/[<path>/]<name> and a caller
// arn:<p>:sts::<acct>:assumed-role/<name>/<session> are the same key, because
// API Gateway reports a role's caller as the session ARN, which drops the
// role's path and carries a session name whoever assumed the role chose. Role
// names are unique within an account whatever their path, so the three parts
// name one role. A user is its whole ARN, path included, which is how both
// sides spell it. Comparison is exact: IAM reports the name as it was created.
//
// Exported because cmd/auth matches callers with it, and a second reading of
// the same ARN grammar there could drift from the one that validated the
// document.
func IAMPrincipalKey(arn string) (string, bool) {
	parts := strings.SplitN(strings.TrimSpace(arn), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || parts[1] == "" || parts[3] != "" || !isAccountID(parts[4]) {
		return "", false
	}
	partition, service, account, resource := parts[1], parts[2], parts[4], parts[5]
	switch {
	case service == "iam" && strings.HasPrefix(resource, "role/"):
		if !iamPrincipalARN.MatchString(strings.TrimSpace(arn)) {
			return "", false
		}
		name := resource[strings.LastIndex(resource, "/")+1:]
		return "role:" + partition + ":" + account + ":" + name, true
	case service == "iam" && strings.HasPrefix(resource, "user/"):
		if !iamPrincipalARN.MatchString(strings.TrimSpace(arn)) {
			return "", false
		}
		return "user:" + strings.TrimSpace(arn), true
	case service == "sts" && strings.HasPrefix(resource, "assumed-role/"):
		if !iamRoleSessionARN.MatchString(strings.TrimSpace(arn)) {
			return "", false
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(resource, "assumed-role/"), "/")
		return "role:" + partition + ":" + account + ":" + name, true
	}
	return "", false
}

// isAccountID reports whether s is a twelve-digit AWS account id.
func isAccountID(s string) bool {
	if len(s) != 12 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// validateAdminMachineAccess checks admin.machineAccess.*.
//
// Every entry has to be an IAM role or user ARN, and the refusals name the
// three near-misses an operator actually writes: a session ARN copied from a
// log line (its session name is the assumer's choice and identifies nothing),
// the account's root user, and a wildcard. A duplicate is refused like a
// duplicate KMS key: two entries for one principal mean one of them was meant
// to be something else. And the block is refused while admin.enabled is off,
// for the reason validateOriginVerify refuses a header without a secret: an
// operator who listed a principal believes a machine can reach the console,
// and with no console mounted nothing can.
func validateAdminMachineAccess(c *Config, d *diagnostics) {
	principals := c.Admin.MachineAccess.IAM.Principals
	if len(principals) == 0 {
		return
	}
	const path = "admin.machineAccess.iam.principals"
	if !c.Admin.Enabled {
		d.errf("", path,
			"is set while admin.enabled is off, so no console is mounted and no machine can be admitted to one",
			"set admin.enabled: true with an access policy, or remove this key")
	}
	seen := map[string]int{}
	for i, raw := range principals {
		entry := fmt.Sprintf("%s[%d]", path, i)
		arn := strings.TrimSpace(raw)
		switch {
		case arn == "" || strings.Contains(arn, "*"):
			d.errf("", entry,
				fmt.Sprintf("%q is empty or a wildcard, and this list admits callers to the admin API with no session", raw),
				"name each role or user, arn:<partition>:iam::<account>:role/<name>")
			continue
		case strings.Contains(arn, ":sts::") && strings.Contains(arn, ":assumed-role/"):
			d.errf("", entry,
				fmt.Sprintf("%q is a role session, whose session name is chosen by whoever assumes the role and identifies nothing", arn),
				"name the role instead, arn:<partition>:iam::<account>:role/<name>, which admits every session of it")
			continue
		case strings.HasSuffix(arn, ":root"):
			d.errf("", entry,
				fmt.Sprintf("%q is an account's root user, which must never be an admin machine principal", arn),
				"create a role for the service that calls the admin API and name it here")
			continue
		}
		key, ok := IAMPrincipalKey(arn)
		if !ok || !strings.Contains(arn, ":iam::") {
			d.errf("", entry,
				fmt.Sprintf("%q is not an IAM role or user ARN", arn),
				"use arn:<partition>:iam::<account>:role/[<path>/]<name> or arn:<partition>:iam::<account>:user/[<path>/]<name>")
			continue
		}
		if first, dup := seen[key]; dup {
			d.errf("", entry,
				fmt.Sprintf("%q names the principal %s[%d] already names", arn, path, first),
				"list each role or user once; a role is matched by account and name, whatever its path")
			continue
		}
		seen[key] = i
	}
}

func validateTools(c *Config, d *diagnostics) {
	if c.Tools.Auth != "" {
		enum(d, "tools.auth", c.Tools.Auth, ToolsAuthNone, ToolsAuthSession, ToolsAuthAPIKey, ToolsAuthAdmin)
	}
	// An enabled tools block has to say who may reach it. There is no default,
	// on purpose: the only value the reference would supply for a silent
	// document is its own — no authMiddleware, the open door — and the house
	// rule that forgetting tightens rather than loosens (Defaults) has no
	// tighter reading of an absent guard than refusing to guess one.
	// Defaulting to `session` instead was considered and rejected: the posture
	// decides whether a server-to-server caller can reach track at all, so a
	// silent default is a silent 403 for the deployment that meant apiKey, and
	// the imported core takes the same view of its own zero value
	// (tools-router-requires-an-explicit-guard-decision mounts nothing until
	// the host has chosen). `none` stays available, by name and only by name.
	// With the block off the knob is inert and an empty one is left alone.
	if c.Tools.Enabled && c.Tools.Auth == "" {
		d.errf(RuleToolsAuthUnset, "tools.auth",
			"tools.enabled is on and tools.auth is not set, so nothing says who may reach POST <tools>/track, POST <tools>/notify and GET <tools>/telemetry",
			fmt.Sprintf("write tools.auth: %s, %s or %s -- or tools.auth: %s to get the reference's unguarded routes, by name",
				ToolsAuthSession, ToolsAuthAPIKey, ToolsAuthAdmin, ToolsAuthNone))
	}
	// The admin posture puts the tools routes behind the admin console's own
	// guard, and that guard exists only when the console is configured: it is
	// built from admin.accessPolicy and the admin session cookie, neither of
	// which has a value without admin.enabled. A posture naming a guard that
	// is not there would have to fall back to something — open, or nothing —
	// and both are the silent degradation tools.auth exists to rule out.
	if c.Tools.Enabled && c.Tools.Auth == ToolsAuthAdmin && !c.Admin.Enabled {
		d.errf("", "tools.auth",
			fmt.Sprintf("tools.auth is %q, but admin.enabled is off, so there is no admin guard to put the tools routes behind", ToolsAuthAdmin),
			"enable the admin surface (admin.enabled: true with an access policy), or choose tools.auth: session or apiKey")
	}
	absolutePath(d, "tools.basePath", c.Tools.BasePath)
	enum(d, "tools.sse.distributor.type", c.Tools.SSE.Distributor.Type, DistributorNone, DistributorRedis, DistributorSNS, DistributorDynamoDB)
	// D9c: the event log's two knobs, bounded where a value outside the range
	// would quietly change what the log means rather than only what it costs.
	//
	// The poll interval's ceiling is the back-off's own: after a minute of
	// silence the loop polls every five seconds, so a base above five would
	// make an idle connection poll faster than a busy one. Its floor is a
	// tenth of a second, and it is a floor on latency, not a point of
	// balance: by docs/cost-model.md §3.1's own prices the poll already
	// costs more than a 128 MB connection's GB-seconds below about 150 ms on
	// two topics and 225 ms on three — at 100 ms it is 1.5 to 2.25 times the
	// compute — and the default of a second is where it is a few percent of
	// it.
	//
	// The retention's floor is half an hour because a connection is a
	// sequence of fifteen-minute segments: a client whose last event is a
	// segment old reconnects with a cursor that old, and a retention shorter
	// than a segment would answer an ordinary quiet reconnect with "replay
	// truncated" when nothing was lost. The ceiling is a week, past which a
	// replay is a backfill and not a resume.
	if v := c.Tools.SSE.PollIntervalMs; v < 100 || v > 5000 {
		d.errf("", "tools.sse.pollIntervalMs",
			fmt.Sprintf("%d ms is outside the supported range 100-5000", v),
			"use 1000, the default; the loop backs off to 5000 by itself after a minute of silence")
	}
	if v := c.Tools.SSE.EventLogRetentionSeconds; v < 1800 || v > 604_800 {
		d.errf("", "tools.sse.eventLogRetentionSeconds",
			fmt.Sprintf("%d s is outside the supported range 1800-604800", v),
			"use 86400, the default: a day of replay, and at least two fifteen-minute connection segments")
	}
	// The replay limit's floor is one event, because zero would be "resume
	// replays nothing", which is the reference's behaviour and not this
	// knob's to switch on; its ceiling is ten thousand, about three hundred
	// pages of reads for one connection, past which a replay is a backfill.
	if v := c.Tools.SSE.ReplayLimit; v < 1 || v > 10_000 {
		d.errf("", "tools.sse.replayLimit",
			fmt.Sprintf("%d events is outside the supported range 1-10000", v),
			"use 100, the default: the few seconds a reconnect misses on a busy topic, and a bound on what a cursor anybody can write costs")
	}
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
	// D9d. Shape only: whether the function exists, and whether this
	// function's role may invoke it, is something only the first webhook can
	// find out, and the answer then is the core's 400 and a redelivery.
	if fn := c.Tools.InboundWebhooks.ScriptRunnerFunction; fn != "" && (strings.TrimSpace(fn) != fn || strings.ContainsAny(fn, " \t\r\n")) {
		d.errf("", "tools.inboundWebhooks.scriptRunnerFunction",
			fmt.Sprintf("%q contains whitespace, which no Lambda function name or ARN does", fn),
			"write the function's name or ARN exactly, as the SAM template's ScriptRunnerFunction does")
	}
	if r := c.Tools.OutboundWebhooks.Defaults.MaxRetries; r < 0 || r > 10 {
		d.errf("", "tools.outboundWebhooks.defaults.maxRetries",
			fmt.Sprintf("%d is outside the supported range 0-10", r),
			"use 3, the reference's per-webhook default")
	}
	atLeast(d, "tools.outboundWebhooks.defaults.retryDelayMs", c.Tools.OutboundWebhooks.Defaults.RetryDelayMs, 100)
	// D9b. An SQS queue URL is https://sqs.<region>.amazonaws.com/<account>/<name>;
	// only its shape is checked, because the region and the account are the
	// template's to supply and a mistyped one is SendMessage's to refuse. The
	// value is echoed: a queue URL is an address, not a capability — sending
	// to it needs sqs:SendMessage on the queue.
	if raw := strings.TrimSpace(c.Tools.OutboundWebhooks.QueueURL); raw != "" {
		if u, err := url.Parse(raw); err != nil || u.Scheme != "https" || u.Host == "" || strings.Trim(u.Path, "/") == "" {
			d.errf("", "tools.outboundWebhooks.queueUrl",
				fmt.Sprintf("%q is not an https SQS queue URL", raw),
				"use the queue's URL as SQS reports it, https://sqs.<region>.amazonaws.com/<account>/<name>, or leave it empty to deliver in process")
		}
	}
}

func validateRateLimit(c *Config, d *diagnostics) {
	if !c.RateLimit.Enabled {
		return
	}
	windowSeconds(d, "rateLimit.windowSeconds", c.RateLimit.WindowSeconds)
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
// anything else would be theatre. accept-invitation names a route that exists
// only with invitations.enabled; naming it without them watches a path nothing
// serves, which costs nothing.
var rateLimitEndpoints = []string{
	"login", "register", "refresh", "forgot-password", "reset-password",
	"magic-link", "sms-code", "2fa-verify", "verify-email", "resend-verification",
	"accept-invitation",
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
	validateOriginVerify(c, d)
}

// originVerifySecretARN is a Secrets Manager secret ARN with an optional
// #<jsonKey> selector: the name characters Secrets Manager allows
// (alphanumerics and /_+=.@-, which covers the six-character suffix it
// appends), and a selector that is not empty and holds no second '#', since
// the reader splits on the last one. An ARN and not a bare name, because the
// stack template's IAM statement scopes the read to this exact resource, and
// because the region the secret is read from is the ARN's.
var originVerifySecretARN = regexp.MustCompile(`^arn:[a-z0-9-]+:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[A-Za-z0-9/_+=.@-]+(#[^#]+)?$`)

// originVerifyReservedHeaders are the request headers http.originVerify.header
// may not name: every one this binary, the imported core or the event adapter
// reads, plus the framing headers no proxy lets an application own. The check
// strips its header before anything else sees the request, so naming one of
// these would take Authorization from every bearer client, the Origin from
// every redirect check or the client address from the rate limiter — and
// would make the front door's secret the value a route reads as a token.
// The second group are headers a proxy or the platform sets, which a request
// handler, a log line or the language negotiation may read: stripping one
// would only degrade what they do, but a secret in one of them is a secret
// something else reads too. Compared in canonical form.
var originVerifyReservedHeaders = map[string]struct{}{
	"Accept": {}, "Authorization": {}, "Connection": {}, "Content-Length": {},
	"Content-Type": {}, "Cookie": {}, "Host": {}, "Last-Event-Id": {},
	"Origin": {}, "Referer": {}, "Transfer-Encoding": {}, "User-Agent": {},
	"X-Api-Key": {}, "X-Auth-Strategy": {}, "X-Correlation-Id": {},
	"X-Csrf-Token": {}, "X-Forwarded-For": {}, "X-Forwarded-Proto": {},

	"Accept-Language": {}, "Forwarded": {}, "X-Amzn-Trace-Id": {},
	"X-Forwarded-Host": {}, "X-Forwarded-Port": {}, "X-Real-Ip": {},
}

// validateOriginVerify checks http.originVerify.*.
//
// With no secretArn the block is off, and the other two knobs then do nothing
// at all; writing either of them is refused rather than accepted, because an
// operator who set a header name believes the origin is checked. The source
// decides, not the value: a template that passes the default header name with
// a forgotten ARN is exactly the deployment this catches.
func validateOriginVerify(c *Config, d *diagnostics) {
	ov := c.HTTP.OriginVerify
	if !ov.Enabled() {
		for _, path := range []string{"http.originVerify.header", "http.originVerify.exemptHealthz"} {
			if c.Source(path) == SourceDefault {
				continue
			}
			d.errf("", path,
				"is set while http.originVerify.secretArn is not, so the origin check is off and no request is refused for lacking the header",
				"set http.originVerify.secretArn to the Secrets Manager secret the front door's header value is kept in, or remove this key")
		}
		return
	}
	if !originVerifySecretARN.MatchString(ov.SecretARN) {
		d.errf("", "http.originVerify.secretArn",
			"is not a Secrets Manager secret ARN",
			"use arn:<partition>:secretsmanager:<region>:<account>:secret:<name>, optionally followed by #<jsonKey> to select one key of a JSON secret")
	}
	if !isHTTPToken(ov.Header) {
		d.errf("", "http.originVerify.header",
			fmt.Sprintf("%q is not a valid HTTP header name", ov.Header),
			"use letters, digits and hyphens, e.g. "+DefaultOriginVerifyHeader)
		return
	}
	if _, reserved := originVerifyReservedHeaders[textproto.CanonicalMIMEHeaderKey(ov.Header)]; reserved {
		d.errf("", "http.originVerify.header",
			fmt.Sprintf("%q is a header the auth surface reads, and the origin check removes its header from every request before anything else sees it", ov.Header),
			"choose a header nothing else uses, e.g. "+DefaultOriginVerifyHeader)
	}
}

// isHTTPToken reports whether s is an RFC 9110 token: the characters a header
// field name may contain. Bounded at 128 bytes, which is longer than any name
// a front door is configured with.
func isHTTPToken(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9':
		case strings.IndexByte("!#$%&'*+-.^_`|~", ch) >= 0:
		default:
			return false
		}
	}
	return true
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

// MaxWindowSeconds bounds every counting window (rateLimit.windowSeconds,
// twoFactor.lockout.windowSeconds) at one year. A window is multiplied by
// time.Second where it is used, and a value above ~292 years overflows int64:
// the cap would silently turn into a sub-second window. A year is far beyond any
// sensible lockout or rate window, so the ceiling refuses only typos.
const MaxWindowSeconds = 365 * 24 * 60 * 60

// windowSeconds reports a counting window that is not positive or exceeds
// MaxWindowSeconds.
func windowSeconds(d *diagnostics, path string, got int) {
	if got <= 0 {
		positive(d, path, got)
		return
	}
	if got > MaxWindowSeconds {
		d.errf("", path,
			fmt.Sprintf("%d seconds exceeds the %d-second (one year) ceiling for a counting window", got, MaxWindowSeconds),
			"set a window of at most one year; to keep an account locked, raise the window up to that ceiling or disable the account")
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

// validateMounts is the one place the three path-bearing knobs — http.apiPrefix,
// admin.basePath and tools.basePath — are checked against each other. It refuses
// the values that make two routers one subtree, or one router the whole server.
//
// The auth router is a set of method-bearing routes under the api prefix. The
// admin console and the tools router are each registered as a subtree — the
// mount and everything below it — and each may sit *under* the prefix: the
// Angular demo mounts the tools router at <apiPrefix>/tools, the contract suite
// has a knob for exactly that, and http.ServeMux resolves the overlap the right
// way round, because every auth route is a more specific pattern than the
// subtree. What a subtree mount may not be is:
//
//   - "/": the router becomes the deployment's catch-all, so every path no other
//     route claims is answered by a router that was asked for none of them.
//   - http.apiPrefix itself: the same happens to the api prefix — a misspelled
//     or wrong-method auth request stops being the mux's own 404 or 405 and
//     becomes that router's 404.
//   - above http.apiPrefix (/api under /api/auth): the same, for every path
//     under the prefix, and the CORS exemption a subtree mount beside the
//     prefix gets would take the auth routes out of the CORS layer with it.
//   - equal to, above or below the other subtree mount: equal is a duplicate
//     ServeMux pattern, which is a panic inside the adapter at cold start with a
//     stack trace and no knob named; nested is one router swallowing part of the
//     other. Checked only when both blocks are on, since a mount that is not
//     registered collides with nothing.
//
// One validator for the three rather than one per block, because a collision
// has two sides and a diagnostic that named only the knob its block happened to
// own would send the operator to whichever side was written second. Compared
// after trimming slashes, which is how the core resolves a mount
// (HTTPConfig.ToolsPath), so "/tools/" and "/tools" are one value here as there.
// A value that is not an absolute path is left to absolutePath, which has
// already refused it.
func validateMounts(c *Config, d *diagnostics) {
	norm := func(p string) string { return "/" + strings.Trim(strings.TrimSpace(p), "/") }
	prefix := norm(c.HTTP.APIPrefix)

	type subtree struct {
		knob, raw, mount string
	}
	var mounts []subtree
	if c.Admin.Enabled && strings.HasPrefix(c.Admin.BasePath, "/") {
		mounts = append(mounts, subtree{"admin.basePath", c.Admin.BasePath, norm(c.Admin.BasePath)})
	}
	if c.Tools.Enabled && strings.HasPrefix(c.Tools.BasePath, "/") {
		mounts = append(mounts, subtree{"tools.basePath", c.Tools.BasePath, norm(c.Tools.BasePath)})
	}

	for _, m := range mounts {
		switch m.mount {
		case "/":
			d.errf("", m.knob,
				"the router cannot be mounted at the root: it would answer every path no other route claims",
				fmt.Sprintf("use a path of its own, for example %s", Defaults().mountDefault(m.knob)))
		case prefix:
			d.errf("", m.knob,
				fmt.Sprintf("%q is http.apiPrefix itself, so this router would answer every path under the api prefix that no auth route claims", m.raw),
				fmt.Sprintf("mount it beside the prefix (%s) or below it (%s%s)", Defaults().mountDefault(m.knob), prefix, Defaults().mountDefault(m.knob)))
		default:
			if m.mount != "/" && strings.HasPrefix(prefix, m.mount+"/") {
				d.errf("", m.knob,
					fmt.Sprintf("%q is above http.apiPrefix %q, so this router would answer every path under the api prefix that no auth route claims, and the CORS exemption this router's mount gets (cmd/auth corsExemptMounts) would lift the CORS layer from every auth route as well", m.raw, prefix),
					fmt.Sprintf("mount it beside the prefix (%s) or below it (%s%s)", Defaults().mountDefault(m.knob), prefix, Defaults().mountDefault(m.knob)))
			}
		}
	}
	if len(mounts) == 2 {
		a, b := mounts[0], mounts[1]
		if a.mount == b.mount || strings.HasPrefix(a.mount, b.mount+"/") || strings.HasPrefix(b.mount, a.mount+"/") {
			// Reported once, on the tools knob: the admin console is the older
			// mount and the one the hosted UI's pages are written against, so
			// it is the tools router that moves.
			d.errf("", b.knob,
				fmt.Sprintf("%q and %s %q are the same subtree or one inside the other, so two routers would claim the same paths", b.raw, a.knob, a.raw),
				fmt.Sprintf("give each its own mount, for example %s and %s", Defaults().mountDefault(a.knob), Defaults().mountDefault(b.knob)))
		}
	}
}

// mountDefault is the schema default of a subtree mount, by knob, for the
// remedy text of validateMounts.
func (c *Config) mountDefault(knob string) string {
	switch knob {
	case "admin.basePath":
		return c.Admin.BasePath
	case "tools.basePath":
		return c.Tools.BasePath
	}
	return "/" + strings.TrimSuffix(knob, ".basePath")
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

// maxInvitationTTL is the ceiling on invitations.ttl. An unredeemed invitation
// is a credential for an account with no password, so it is bounded the way a
// counting window is: generous, and not indefinite.
const maxInvitationTTL = 30 * 24 * time.Hour

// validateInvitations checks invitations.* and admin.revealInvitationToken.
//
// Each refusal is a configuration that validates and then does nothing, or
// does something other than the operator believes:
//
//   - invitations.enabled without admin.enabled: the invite route is on the
//     admin router, so nothing could ever create an invitation.
//   - invitations.enabled behind admin.accessPolicy: open: the invite route is
//     behind the console's guard, and that guard admits everyone. An anonymous
//     caller would invite a mailbox of their own with the role they name,
//     accept and sign in: self-registration with a chosen role, on a realm whose
//     registration.closed says there is none. It is refused for the reason
//     RS-19 refuses an OAuth callback that still signs anyone up to a closed
//     realm. The open console is the reference's default, and it is only
//     warned about elsewhere (collectWarnings). This refusal is narrower: it
//     covers the one route through which that console creates accounts.
//   - invitations.enabled in resource-server mode: the accept route is never
//     mounted there (the core gates every credential route).
//   - invitations.enabled with no way to deliver a token — no mailer, no
//     delivery webhook, no admin.revealInvitationToken: the invite route
//     answers 501 to every call.
//   - admin.revealInvitationToken beside a mailer or the delivery webhook: the
//     core ignores the flag when it has a sender, so tokens would be mailed
//     while the operator believes the caller receives them — and a deployment
//     that has a sender must never hand a token to an HTTP caller.
//   - admin.revealInvitationToken or invitations.reinvite without
//     invitations.enabled: knobs of a feature that is off.
func validateInvitations(c *Config, d *diagnostics) {
	inv := c.Invitations
	sender := c.MailerConfigured() || c.DeliveryWebhookConfigured()
	if inv.Enabled {
		ttl(d, "invitations.ttl", inv.TTL, true)
		if inv.TTL.parseErr() == nil && inv.TTL.Duration() > maxInvitationTTL {
			d.errf("", "invitations.ttl",
				fmt.Sprintf("%q is longer than %s: an unredeemed invitation is a credential for an account with no password", inv.TTL.String(), "30d"),
				`use at most "30d"; revoke and invite again to extend an offer`)
		}
		if !c.Admin.Enabled {
			d.errf("", "invitations.enabled",
				"is on while admin.enabled is off: POST <admin>/api/users/invitations is the only route that creates an invitation, and no console is mounted",
				"set admin.enabled: true with an access policy (admin.machineAccess for a back office), or turn invitations off")
		}
		if c.Admin.Enabled && c.Admin.AccessPolicy == AdminAccessPolicyOpen {
			d.errf("", "invitations.enabled",
				"is on while admin.accessPolicy is open: the console admits every request with no credential, so anyone can invite an address of their own with the role of their choosing, accept it and sign in -- "+
					"an account-creating route open to the internet, which registration.closed then does not close",
				"set admin.accessPolicy to is-admin-flag, rbac:<role> or permission:<perm> (admin.machineAccess for a back office), or turn invitations off")
		}
		if c.ResourceServer.Enabled {
			d.errf("", "invitations.enabled",
				"is on in resource-server mode, which mounts no credential route: POST <prefix>/invitations/accept would answer 404",
				"turn invitations on in the issuing deployment, not in the resource server")
		}
		if !sender && !c.Admin.RevealInvitationToken {
			d.errf("", "invitations.enabled",
				"is on with no way to deliver a token: neither email.mailer nor email.deliveryWebhook is configured, and admin.revealInvitationToken is off, so POST <admin>/api/users/invitations answers 501 to every call",
				"configure email.mailer (the invitation template) or email.deliveryWebhook (kind \"invitation\"); or, for a back office that delivers the token itself, set admin.revealInvitationToken: true")
		}
	} else {
		if inv.Reinvite {
			d.errf("", "invitations.reinvite",
				"is on while invitations.enabled is off, so no invitation route is mounted",
				"set invitations.enabled: true, or remove this key")
		}
		if c.Admin.RevealInvitationToken {
			d.errf("", "admin.revealInvitationToken",
				"is on while invitations.enabled is off, so no invitation route is mounted",
				"set invitations.enabled: true, or remove this key")
		}
	}
	if c.Admin.RevealInvitationToken && sender {
		d.errf("", "admin.revealInvitationToken",
			"is on beside a configured sender (email.mailer or email.deliveryWebhook): the core mails the token and ignores the flag, and a deployment that mails tokens must not also hand them to an HTTP caller",
			"remove admin.revealInvitationToken; it is for a deployment with no sender, whose back office delivers the token itself")
	}
}

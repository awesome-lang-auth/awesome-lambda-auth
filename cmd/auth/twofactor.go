package main

import (
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The second factor's one configurable thing: the name an authenticator app
// shows against an enrolment. It is the P3 half of the schema that has no
// webhook in it — twoFactor.appName — which internal/config/phases.go no longer
// refuses.
//
// ── what the knob does ───────────────────────────────────────────────────────
//
// POST <prefix>/2fa/setup answers with a base32 secret and an otpauth:// URI,
// and the URI carries an issuer twice: once as the label prefix and once as the
// issuer parameter. That string is what Google Authenticator, 1Password and the
// rest print above the six digits, so it is the only part of TOTP a user ever
// reads, and getting it wrong shows up as "which of these three accounts is the
// one I want".
//
// The reference takes it from `config.twoFactor?.appName ?? 'awesome-node-auth'`
// (auth.router.ts:830, totp.strategy.ts:11). The core takes it from
// Config.TwoFactorAppName and falls back to Config.Issuer rather than to that
// literal — a registered core deviation, totp-issuer-defaults-to-config-issuer,
// whose own text says WithTwoFactorAppName matches the reference exactly. Since
// the schema's default for twoFactor.appName IS the reference's literal and
// validate.go refuses an empty one, passing it unconditionally is what retires
// the fallback: this deployment always sends the option, so Config.Issuer never
// decides the label and the URI is the reference's on every stack.
//
// ── the iss claim ────────────────────────────────────────────────────────────
//
// Config.Issuer is therefore left at the core's own default, and that is a
// decision rather than an omission. auth.WithIssuer exists in v0.6.0 and would
// take any string; the plan's suggestion was the canonical site URL. It is not
// wired, for two reasons that hold together:
//
//   - Nothing configures it. There is no issuer knob in any domain this build
//     wires: idProvider.issuer and resourceServer.issuer are the only two in
//     the schema and both belong to P5, which phases.go still refuses. Deriving
//     iss from deployment.publicUrl or email.siteUrls[0] would invent a value
//     the operator never wrote for a claim every token carries.
//   - It is not a label, it is a check. Service.parseToken refuses a token
//     whose iss differs from Config.Issuer (token.go), so the issuer is part of
//     the verification key material in practice. Bound to the site URL, editing
//     email.siteUrls — a knob whose documented job is where a mailed link
//     points — would invalidate every outstanding access and refresh token and
//     log out every session, with nothing in the diagnostics connecting the two.
//
// So iss stays the core's constant, unwiredKnobs reports nothing for it because
// no knob is being ignored, and the contract suite pins that the claim is
// present and stable rather than pinning a value. An issuer knob lands with the
// identity-provider block in P5, which is where a deployment first has a reason
// to name itself on the wire.

// ── the policy: twoFactor.required and twoFactor.enrolOnLogin ────────────────
//
// Two booleans, both off by default, both handed to the core as written.
//
// twoFactor.required is the core's Config.Require2FA (WithRequire2FA). Since
// v0.14.0 the core enforces it at login: an account with a factor it can
// present gets the challenge — an enrolled TOTP, or the emailed link or texted
// code where a mail or SMS transport is wired — and one with none gets the
// reference's 403 {"requires2FASetup":true,"tempToken":…,"code":"2FA_SETUP_REQUIRED"}
// and no session. It is also a term of POST <prefix>/2fa/disable's refusal, with
// or without a settings store. Before this knob the product could not ask for
// either: runtimeSettings.require2fa seeds the settings store, which the core
// reads on /2fa/disable and nowhere else, so "require2fa" in a document
// switched off the off-switch and left the login asking for nothing. The two
// stay distinct — the seed is the run-time switch an administrator flips in
// the console, and this is the deployment's policy — and config-reference §7
// says which does what.
//
// twoFactor.enrolOnLogin is Config.EnrolOnLogin (WithEnrolOnLogin): the
// 2FA_SETUP_REQUIRED tempToken becomes an enrolment token that
// POST <prefix>/2fa/setup and POST <prefix>/2fa/verify-setup accept, and the
// verify-setup it completes opens the session (core deviation
// forced-enrolment-opens-a-session). Without it the token completes nothing
// and an account under the policy has to be enrolled out of band — which is
// the safe default, because the option is trust on first use: whoever holds
// the password binds the factor. The loader warns whenever it is on.
//
// What neither reaches, stated here because the operator who turns them on
// will assume otherwise: the OAuth callback issues a session with no second
// factor (oauth-callback-skips-the-second-factor), the console's own
// POST <admin>/login is password-only (admin-login-skips-the-second-factor),
// and the passwordless logins — magic-link and SMS in login mode — open a
// session on the one factor they delivered, as the reference's do. The loader
// warns on each combination; realm_test.go pins that all three still hold
// with twoFactor.required on.

// twoFactorOptions hands the core the TOTP issuer and the second-factor
// policy.
//
// Unconditional, unlike the delivery and claims option sets: there is no "off"
// for the issuer. Every deployment mounts /2fa/setup, the schema default is a
// real value rather than a zero one, and validate.go refuses an empty appName —
// so there is no configuration in which passing it is wrong, and a gate here
// would only be able to disagree with validation. The two policy options are
// passed as written for the same reason: false is the core's own default, so a
// document that sets neither builds the core it built before they existed, and
// a gate could only make the deployed value differ from the configured one.
func twoFactorOptions(cfg *config.Config) []auth.Option {
	return []auth.Option{
		auth.WithTwoFactorAppName(cfg.TwoFactor.AppName),
		auth.WithRequire2FA(cfg.TwoFactor.Required),
		auth.WithEnrolOnLogin(cfg.TwoFactor.EnrolOnLogin),
	}
}

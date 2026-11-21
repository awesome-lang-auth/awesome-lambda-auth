package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// twoFactor.required, held at every door: the request-time half.
//
// The policy is that every session proved a TOTP code. The core enforces
// Config.Require2FA at POST <prefix>/login and nowhere else, and there it
// counts an emailed link or a texted code as a second factor wherever it can
// deliver one. Every other way into a session was walked — each caller of the
// core's issueSession, and the console's mintAdminToken — and sorted by what
// can be done about it from outside the core, which this product does not
// fork:
//
//   - The OAuth callback completes with a session and no second-factor step,
//     and nothing in front of it can turn that into a challenge. A configured
//     provider is refused at start (RS-20, internal/config).
//   - admin.rootUser and admin.bootstrapSecret sign in at POST <admin>/login
//     and nowhere else, so they die with it, and admin.accessPolicy: open asks
//     for nothing at all. Refused at start (RS-20).
//   - The emailed link and the texted code as the SECOND step: the core offers
//     them in the login challenge (availableTwoFactorMethods) and completes
//     the challenge with either — and the mailbox that receives the link also
//     receives the password-reset link, so the mailbox alone answers both
//     steps, and a phone number answers the second. Under the policy they are
//     not factors: delivery.go does not hand the core the magic-link and
//     SMS-code senders, so the challenge lists "totp" alone and an account
//     with no TOTP is answered 2FA_SETUP_REQUIRED; and the gate below refuses
//     the step-up mode of the four routes, which also covers a link or a code
//     minted before the policy was switched on.
//   - Four doors are one request each that the gate below can recognise and
//     refuse before the core acts on it, without taking anything else away:
//
//     POST <prefix>/magic-link/{send,verify} and POST <prefix>/sms/{send,verify},
//     in EVERY mode — the login mode, where the link or the code alone opens a
//     session, as in the reference, and the step-up mode (mode "2fa", with the
//     login's tempToken), where it stands in for the factor. The body is not
//     read: no mode is admitted, so there is nothing in it to decide on;
//
//     POST <prefix>/link-verify with loginAfterLinking — the core opens a
//     session for the linked account on the emailed link-token alone
//     (IssueTokensForUser), and with the OAuth callback refused the token
//     comes from POST <prefix>/link-request with any access token, mailed to
//     whatever address the body names. Linking without logging in passes;
//
//     POST <admin>/login — a 24-hour console token on a password alone. The
//     console still accepts the access token of a session that came through
//     POST <prefix>/login and its TOTP code (the core's admin guard reads it),
//     and admin.loginPath sends a browser to the hosted login that asks for
//     it; and machine access (admin.machineAccess) is IAM, not a sign-in.
//
//   - Everything else was already held: /register opens a session only when
//     /login would (core registerIssuesSession), /reset-password changes a
//     password and opens nothing — the next login still asks for TOTP —
//     the forced enrolment of twoFactor.enrolOnLogin opens a session only on
//     the TOTP factor it has just bound, the identity provider's /authorize
//     calls the core's Service.Login, which refuses every account under the
//     policy, and /refresh continues a session that one of these doors opened
//     — or one opened before the policy was switched on, which it does not end
//     (config-reference §7.1).
//
// The gate answers the core's own envelope for the requirement it enforces,
// 403 {"error":"Two-factor authentication required","code":"2FA_REQUIRED"}
// (auth.HTTPErrTwoFactorRequired), on the passwordless and linking routes,
// and the router's bare 404 on the console's login — what the core answers
// for that route wherever it is not mounted (AdminGuard.LoginRoutesMounted).
// Registered as the product deviation two-factor-required-refuses-one-factor-sign-ins.
//
// ── agreeing with the router and with the handler ────────────────────────────
//
// A gate that matched paths its own way would be bypassed by every spelling
// the router resolves differently — the router serves POST /auth/%72egister
// as /auth/register. So it does not match paths: it asks the mux the core
// mounted onto which pattern would serve the request (ServeMux.Handler, the
// same lookup ServeHTTP makes) and acts on the pattern. The console's login
// is the exception, because the mux sees only the console's subtree there;
// the core's admin router picks the login out of r.URL.Path itself
// (adminRouterPath), and the gate makes the same comparison on the same
// field, as newAdminLoginLimiter does.
//
// And a gate that read the body its own way would be bypassed by every body
// the handler reads differently — which is why the passwordless routes are
// refused without reading theirs. The one body it does read is
// /link-verify's, for loginAfterLinking. The core decodes it with
// json.NewDecoder into a struct (auth.DecodeOptionalJSON): one value, keys
// matched case-insensitively, the last duplicate winning, an empty body read
// as {}. The gate decodes the same bytes the same way into a struct carrying
// the core's own tag for the one field it reads, so
// {"loginAfterLinking":false,"LOGINAFTERLINKING":true} is a login to both. It
// refuses whatever it cannot read, an oversized body included; the core would
// answer a malformed body 400 INVALID_BODY, so failing closed costs a client
// nothing it could have used. The bytes are put back for the handler
// unchanged.

// maxSecondFactorGateBody bounds what the gate reads of a body. The body of
// /link-verify is a token and a flag — a few hundred bytes — so 64 KiB is room
// for any client and a ceiling for the rest; a larger body is refused rather
// than half-read.
const maxSecondFactorGateBody = 64 << 10

// secondFactorGate returns the middleware that holds the one-factor sign-ins
// to twoFactor.required, or the identity when the policy is off. mux is the
// router the core was mounted on, read only to classify a request; next is
// what the request is handed to.
func secondFactorGate(cfg *config.Config, mux *http.ServeMux) func(http.Handler) http.Handler {
	if !cfg.TwoFactor.Required {
		return func(next http.Handler) http.Handler { return next }
	}
	hc := httpConfig(cfg)
	prefix := hc.Prefix()
	// The patterns exactly as the core registers them (adapter/nethttp
	// mountCredentialRoutes and Mount): a method, a space, the prefixed path.
	passwordless := map[string]bool{
		http.MethodPost + " " + prefix + "/magic-link/send":   true,
		http.MethodPost + " " + prefix + "/magic-link/verify": true,
		http.MethodPost + " " + prefix + "/sms/send":          true,
		http.MethodPost + " " + prefix + "/sms/verify":        true,
	}
	linkVerify := http.MethodPost + " " + prefix + "/link-verify"
	adminLogin := ""
	if hc.AdminMounted() {
		adminLogin = hc.AdminPath() + auth.AdminLoginPath
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if adminLogin != "" && r.Method == http.MethodPost && r.URL.Path == adminLogin {
				http.NotFound(w, r)
				return
			}
			_, pattern := mux.Handler(r)
			switch {
			case passwordless[pattern]:
				// Every mode: the login mode is one factor, and the step-up
				// mode would make the mailbox or the phone the second.
				auth.WriteHTTPError(w, auth.HTTPErrTwoFactorRequired)
				return
			case pattern == linkVerify:
				// linkVerifyBody's tag. Refused before the core reads the token,
				// so the link survives for a request without the flag.
				var body struct {
					LoginAfterLinking bool `json:"loginAfterLinking"`
				}
				if !decodeGatedBody(r, &body) || body.LoginAfterLinking {
					auth.WriteHTTPError(w, auth.HTTPErrTwoFactorRequired)
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// decodeGatedBody reads the request body whole, decodes it into dst as
// auth.DecodeOptionalJSON does — one JSON value, an empty body being no
// fields at all — and puts the same bytes back for the handler. false means
// the body could not be read the way the handler will read it, and the gate
// refuses.
func decodeGatedBody(r *http.Request, dst any) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxSecondFactorGateBody+1))
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(raw))
	if err != nil || len(raw) > maxSecondFactorGateBody {
		return false
	}
	if err := json.NewDecoder(bytes.NewReader(raw)).Decode(dst); err != nil && !errors.Is(err, io.EOF) {
		return false
	}
	return true
}

// logSecondFactorSurface says at cold start what the policy enforces and how,
// once, beside the other surface lines: that a TOTP code is the only second
// factor, which doors are refused, and what a password reset still does.
// Nothing when the policy is off: every door then answers as the core does.
func logSecondFactorSurface(cfg *config.Config, log *slog.Logger) {
	if !cfg.TwoFactor.Required {
		return
	}
	hc := httpConfig(cfg)
	prefix := hc.Prefix()
	enrol := "is answered 403 2FA_SETUP_REQUIRED and enrolled out of band (twoFactor.enrolOnLogin is off)"
	if cfg.TwoFactor.EnrolOnLogin {
		enrol = "is answered 403 2FA_SETUP_REQUIRED and enrols TOTP with that answer's tempToken at POST " + prefix +
			"/2fa/setup and /2fa/verify-setup (twoFactor.enrolOnLogin: trust on first use)"
	}
	admin := "no console is mounted"
	if hc.AdminMounted() {
		admin = "POST " + hc.AdminPath() + auth.AdminLoginPath + " answers 404; the console admits a session from POST " + prefix +
			"/login and its TOTP code, and machine access"
	}
	attrs := []any{
		slog.String("secondFactor", "totp alone: the login challenge lists totp and completes at POST "+prefix+"/2fa/verify; an account without TOTP "+enrol),
		slog.String("passwordless", "POST "+prefix+"/magic-link/send, /magic-link/verify, /sms/send and /sms/verify answer 403 2FA_REQUIRED in every mode, "+
			"the step-up (mode \"2fa\") included; their senders are not handed to the core, so no link or code is minted and ui/config reports neither"),
		slog.String("linkVerify", "POST "+prefix+"/link-verify with loginAfterLinking answers 403 2FA_REQUIRED; linking alone passes"),
		slog.String("adminLogin", admin),
	}
	if cfg.MailerConfigured() || cfg.DeliveryWebhookConfigured() {
		reset := "POST " + prefix + "/forgot-password delivers the reset link and /reset-password changes the password and opens no session: the next login still asks for TOTP"
		if cfg.TwoFactor.EnrolOnLogin {
			reset += "; an account that has not enrolled TOTP yet is claimed by whoever resets its password, through forced enrolment"
		}
		attrs = append(attrs, slog.String("passwordReset", reset))
	}
	log.Info("twoFactor.required: every session proves a TOTP code", append(attrs,
		slog.String("deviation", "two-factor-required-refuses-one-factor-sign-ins"))...)
}

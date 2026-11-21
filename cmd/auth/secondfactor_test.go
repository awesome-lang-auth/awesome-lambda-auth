package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// twoFactor.required at every door (secondfactor.go, delivery.go, RS-20).
//
// Each test below presents, under the policy, a credential that opened a
// session through the same door on an earlier build — b20ef56 pinned three of
// them as TestOAuthCallbackSkipsTheFactorTheRealmRequires,
// TestAdminLoginSkipsTheFactorTheRealmRequires and
// TestMagicLinkLoginSkipsTheFactorTheRealmRequires, the review that followed
// reached the SMS login and /link-verify the same way, and the review of
// 872008e opened a TOTP-enrolled account with its mailbox alone: a password
// reset, then the emailed link as the second step — and asserts that it opens
// nothing now. Then, as the control, it completes the same credential through
// the door that does ask for the factor, so a refusal cannot pass on a
// credential that was never good.

// requireNoSession fails when a response carries a session in either delivery
// mode: an access or refresh cookie, or a token in the body.
func requireNoSession(t *testing.T, what string, resp events.APIGatewayV2HTTPResponse) {
	t.Helper()
	if got := sessionCookies(resp); len(got) > 0 {
		t.Errorf("%s set %v", what, got)
	}
	if strings.Contains(resp.Body, "accessToken") || strings.Contains(resp.Body, "refreshToken") {
		t.Errorf("%s answered a token: %s", what, resp.Body)
	}
}

// requireTwoFactorRequired is the gate's refusal: the core's own envelope for
// the requirement, 403 {"error":"Two-factor authentication required",
// "code":"2FA_REQUIRED"}, and no session.
func requireTwoFactorRequired(t *testing.T, what string, resp events.APIGatewayV2HTTPResponse) {
	t.Helper()
	requireNoSession(t, what, resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("%s answered %d %s, want 403 2FA_REQUIRED", what, resp.StatusCode, resp.Body)
		return
	}
	if body := decodeBody(t, resp); body["code"] != "2FA_REQUIRED" || body["error"] != "Two-factor authentication required" {
		t.Errorf("%s answered %s, want the core's {\"error\":\"Two-factor authentication required\",\"code\":\"2FA_REQUIRED\"}", what, resp.Body)
	}
}

// withoutRootUser is adminEnv with the root user taken out: RS-20 refuses it
// beside twoFactor.required, because its one door is POST <admin>/login.
func withoutRootUser(env map[string]string) map[string]string {
	delete(env, "AWESOME_AUTH_ADMIN_ROOT_EMAIL")
	delete(env, "AWESOME_AUTH_ADMIN_ROOT_PASSWORD_HASH")
	return env
}

// TestTwoFactorRequiredRefusesAnOAuthProvider: the callback is the one door
// nothing can stand in front of — the core opens the session and sets the
// cookies on the 302 with no second-factor step — so a deployment that
// combines the two does not start (RS-20). On b20ef56 it started, and the
// callback signed in an account whose password login answered
// 2FA_SETUP_REQUIRED. The same provider without the policy is the control.
func TestTwoFactorRequiredRefusesAnOAuthProvider(t *testing.T) {
	t.Parallel()
	p := newFakeOAuthProvider(t)
	for _, required := range []bool{true, false} {
		var extra []string
		if required {
			extra = []string{"AWESOME_AUTH_2FA_REQUIRED", "true"}
		}
		app, err := New(context.Background(), Options{
			Getenv: envFunc(oauthEnv(t, oauthDoc(p), extra...)),
			Logger: discardLogger(),
			Stores: newOAuthStores().factory(),
		})
		if !required {
			if err != nil {
				t.Fatalf("the same provider without the policy refused to start: %v", err)
			}
			if resp := signIn(t, app, p, nil); resp.StatusCode != http.StatusFound || cookieValue(t, resp, auth.AccessTokenCookieName) == "" {
				t.Errorf("the control's callback answered %d %v, want the 302 with a session", resp.StatusCode, resp.Cookies)
			}
			app.Close()
			continue
		}
		if err == nil {
			app.Close()
			t.Fatal("twoFactor.required beside an OAuth provider started: its callback opens a session with no second factor")
		}
		for _, want := range []string{config.RuleTwoFactorRequiredSignIn, "oauth.providers", testProvider} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not mention %q: %v", want, err)
			}
		}
	}
}

// requireTOTPChallenge is the policy's answer to an enrolled account's
// password: the reference's challenge, listing totp and nothing else, and no
// session. It returns the step-up token.
func requireTOTPChallenge(t *testing.T, what string, resp events.APIGatewayV2HTTPResponse) string {
	t.Helper()
	requireNoSession(t, what, resp)
	body := decodeBody(t, resp)
	methods, _ := body["available2faMethods"].([]any)
	if resp.StatusCode != http.StatusOK || body["requiresTwoFactor"] != true || len(methods) != 1 || methods[0] != auth.TwoFactorMethodTOTP {
		t.Fatalf("%s answered %d %s, want the challenge offering totp alone", what, resp.StatusCode, resp.Body)
	}
	temp, _ := body["tempToken"].(string)
	if temp == "" {
		t.Fatalf("%s: the challenge carries no tempToken: %s", what, resp.Body)
	}
	return temp
}

// requireSetupRequired is the policy's answer to an account with no TOTP,
// whatever else it has: 403 2FA_SETUP_REQUIRED and no session.
func requireSetupRequired(t *testing.T, what string, resp events.APIGatewayV2HTTPResponse) {
	t.Helper()
	requireNoSession(t, what, resp)
	if body := decodeBody(t, resp); resp.StatusCode != http.StatusForbidden || body["code"] != auth.CodeTwoFactorSetupRequired || body["requires2FASetup"] != true {
		t.Errorf("%s answered %d %s, want 403 2FA_SETUP_REQUIRED", what, resp.StatusCode, resp.Body)
	}
}

// policyTwins builds one deployment twice over one store bundle, with the same
// transports: now, under twoFactor.required, and before, without it — the
// stack before the deploy that switched the policy on. A link or a code that
// before mints is a real credential in the store now reads, which is what the
// refusals below are presented with; and before accepting it afterwards is the
// proof that it was good and that the refusal did not spend it.
func policyTwins(t *testing.T, transports func(map[string]string) map[string]string) (now, before *deliveryApp, users memoryStoreBundle) {
	t.Helper()
	users = newMemoryStoreBundle()
	sessions := auth.NewMemorySessionStore()
	shared := func(o *Options) { o.Stores = storeFactory(users, sessions) }
	now = newDeliveryAppWith(t, transports(with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true")), shared)
	before = newDeliveryAppWith(t, transports(baseEnv()), shared)
	t.Cleanup(now.app.Close)
	t.Cleanup(before.app.Close)
	return now, before, users
}

// seedTOTPAccount writes an account with an enrolled TOTP factor.
func seedTOTPAccount(t *testing.T, users memoryStoreBundle, id, email, secret string) {
	t.Helper()
	seedAccount(t, users, id, email)
	if err := users.UpdateTOTPSecret(context.Background(), id, "", secret, true); err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}
}

// TestTwoFactorRequiredKeepsTheMailboxFromAnsweringBothSteps is the review of
// 872008e, five requests long. Under the policy with a mailer, a TOTP-enrolled
// account was opened by whoever controls its mailbox and nothing else: POST
// /forgot-password mailed the reset link, /reset-password took a password of
// their choosing, /login answered the challenge offering
// ["totp","magic-link"], and /magic-link/send then /magic-link/verify in mode
// "2fa" opened the session — the TOTP code never presented. Now the reset
// still works and still opens nothing, the challenge offers totp alone, the
// step-up send is refused with nothing mailed, and the verify is refused even
// with a link that is genuinely good, minted by the same deployment before
// the policy was switched on. The controls: that link still signs in where the
// policy is off, and the TOTP code completes the very challenge the link was
// refused for.
func TestTwoFactorRequiredKeepsTheMailboxFromAnsweringBothSteps(t *testing.T) {
	t.Parallel()
	now, before, users := policyTwins(t, func(env map[string]string) map[string]string { return mailerEnv(env) })
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	const id, owner, secret = "usr_00000000000000000000mailbox1", "mailbox@example.test", "JBSWY3DPEHPK3PXP"
	seedTOTPAccount(t, users, id, owner, secret)

	// 1. The reset mail still goes out under the policy.
	if forgot := invoke(t, now.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil, fmt.Sprintf(`{"email":%q}`, owner)); forgot.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password answered %d %s", forgot.StatusCode, forgot.Body)
	}
	resetToken := tokenIn(t, linkIn(t, now.mail.only(t).Body))
	now.mail.reset()

	// 2. And it works, for a password of the mailbox holder's choosing — and
	// opens nothing.
	const chosen = "the-mailbox-holders-password-0123"
	reset := invoke(t, now.app, http.MethodPost, "/auth/reset-password", bearerJSON, nil, fmt.Sprintf(`{"token":%q,"password":%q}`, resetToken, chosen))
	if reset.StatusCode != http.StatusOK {
		t.Fatalf("reset-password answered %d %s, want 200: the reset flow must keep working under the policy", reset.StatusCode, reset.Body)
	}
	requireNoSession(t, "reset-password", reset)

	// 3. The new password is challenged for TOTP and for nothing else.
	temp := requireTOTPChallenge(t, "the login with the reset password",
		invoke(t, now.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, chosen)))

	// 4. The emailed step-up is refused before a link is minted or mailed.
	for _, body := range []string{
		fmt.Sprintf(`{"mode":"2fa","tempToken":%q}`, temp),
		fmt.Sprintf(`{"email":%q}`, owner),
		fmt.Sprintf(`{"email":%q,"mode":"login"}`, owner),
	} {
		requireTwoFactorRequired(t, "magic-link/send "+body, invoke(t, now.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, body))
	}
	if n := len(now.mail.messages()); n != 0 {
		t.Fatalf("the refused sends mailed %d message(s)", n)
	}

	// 5. The verify, with a link that is good: minted before the policy was on.
	if send := invoke(t, before.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, fmt.Sprintf(`{"email":%q}`, owner)); send.StatusCode != http.StatusOK {
		t.Fatalf("the twin without the policy answered magic-link/send %d %s", send.StatusCode, send.Body)
	}
	link := tokenIn(t, linkIn(t, before.mail.only(t).Body))
	for name, body := range map[string]string{
		"the step-up, with the login's tempToken": fmt.Sprintf(`{"token":%q,"mode":"2fa","tempToken":%q}`, link, temp),
		"no mode":                       fmt.Sprintf(`{"token":%q}`, link),
		"mode login":                    fmt.Sprintf(`{"token":%q,"mode":"login"}`, link),
		"the step-up value in capitals": fmt.Sprintf(`{"token":%q,"mode":"2FA","tempToken":%q}`, link, temp),
		"an empty body":                 "",
		"a body that is not JSON":       "token=" + link,
	} {
		for _, headers := range []map[string]string{jsonHeaders(), bearerJSON} {
			requireTwoFactorRequired(t, "magic-link/verify with "+name, invoke(t, now.app, http.MethodPost, "/auth/magic-link/verify", headers, nil, body))
		}
	}
	// A spelling the router resolves to the same route is the same route.
	requireTwoFactorRequired(t, "magic-link/verify at /auth/magic-link/verif%79",
		invoke(t, now.app, http.MethodPost, "/auth/magic-link/verif%79", bearerJSON, nil, fmt.Sprintf(`{"token":%q,"mode":"2fa","tempToken":%q}`, link, temp)))

	// The controls. The link was good, and no refusal spent it.
	if ok := invoke(t, before.app, http.MethodPost, "/auth/magic-link/verify", bearerJSON, nil, fmt.Sprintf(`{"token":%q}`, link)); ok.StatusCode != http.StatusOK || decodeBody(t, ok)["accessToken"] == nil {
		t.Fatalf("the twin without the policy answered the same link %d %s, want a session: the refusals must have been presented with a good link and left it unspent", ok.StatusCode, ok.Body)
	}
	// And the factor the policy asks for completes the challenge the link was
	// refused for.
	done := invoke(t, now.app, http.MethodPost, "/auth/2fa/verify", bearerJSON, nil,
		fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, temp, totpCodeNow(t, secret)))
	access, _ := decodeBody(t, done)["accessToken"].(string)
	if done.StatusCode != http.StatusOK || access == "" {
		t.Fatalf("POST /auth/2fa/verify answered %d %s, want the session", done.StatusCode, done.Body)
	}
	if me := invoke(t, now.app, http.MethodGet, "/auth/me", bearer(access), nil, ""); me.StatusCode != http.StatusOK || decodeBody(t, me)["isTotpEnabled"] != true {
		t.Errorf("GET /auth/me with the TOTP session answered %d %s", me.StatusCode, me.Body)
	}
}

// TestTwoFactorRequiredKeepsThePhoneFromAnsweringTheSecondStep: the texted
// code, on the same terms as the emailed link. With an SMS transport the core
// offers "sms" in the challenge of every account with a number on file, so a
// phone stood in for the TOTP code; on b20ef56 the code alone also signed in.
// The numbers are written through the store, as provisioning would.
func TestTwoFactorRequiredKeepsThePhoneFromAnsweringTheSecondStep(t *testing.T) {
	t.Parallel()
	now, before, users := policyTwins(t, smsEnv)
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	const id, owner, secret = "usr_000000000000000000000texted1", "texted@example.test", "JBSWY3DPEHPK3PXP"
	seedTOTPAccount(t, users, id, owner, secret)
	if _, err := users.UpdatePhoneNumber(context.Background(), id, "", testPhone); err != nil {
		t.Fatalf("write the number: %v", err)
	}
	// An account whose only second step was the texted code is told to enrol.
	const phoneOnly, phoneOnlyEmail = "usr_0000000000000000000phoneonly", "phone-only@example.test"
	seedAccount(t, users, phoneOnly, phoneOnlyEmail)
	if _, err := users.UpdatePhoneNumber(context.Background(), phoneOnly, "", testPhone); err != nil {
		t.Fatalf("write the number: %v", err)
	}
	requireSetupRequired(t, "the login of an account with a number and no TOTP",
		invoke(t, now.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(phoneOnlyEmail, testPassword)))

	temp := requireTOTPChallenge(t, "the login of an account with TOTP and a number",
		invoke(t, now.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, testPassword)))

	for _, body := range []string{
		fmt.Sprintf(`{"mode":"2fa","tempToken":%q}`, temp),
		fmt.Sprintf(`{"email":%q}`, owner),
		fmt.Sprintf(`{"userId":%q}`, id),
	} {
		requireTwoFactorRequired(t, "sms/send "+body, invoke(t, now.app, http.MethodPost, "/auth/sms/send", jsonHeaders(), nil, body))
	}
	if n := len(now.sms.messages()); n != 0 {
		t.Fatalf("the refused sends texted %d message(s)", n)
	}

	// A code that is good: minted before the policy was on.
	if send := invoke(t, before.app, http.MethodPost, "/auth/sms/send", jsonHeaders(), nil, fmt.Sprintf(`{"userId":%q}`, id)); send.StatusCode != http.StatusOK || len(before.sms.messages()) != 1 {
		t.Fatalf("the twin without the policy answered sms/send %d %s with %d text(s)", send.StatusCode, send.Body, len(before.sms.messages()))
	}
	code := strings.TrimPrefix(before.sms.messages()[0].message, "Your verification code is: ")
	for name, body := range map[string]string{
		"the step-up, with the login's tempToken": fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"code":%q}`, temp, code),
		"userId and code":                         fmt.Sprintf(`{"userId":%q,"code":%q}`, id, code),
		"mode login":                              fmt.Sprintf(`{"userId":%q,"code":%q,"mode":"login"}`, id, code),
	} {
		requireTwoFactorRequired(t, "sms/verify with "+name, invoke(t, now.app, http.MethodPost, "/auth/sms/verify", bearerJSON, nil, body))
	}
	requireTwoFactorRequired(t, "sms/verify at /auth/sms/verif%79",
		invoke(t, now.app, http.MethodPost, "/auth/sms/verif%79", bearerJSON, nil, fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"code":%q}`, temp, code)))

	if ok := invoke(t, before.app, http.MethodPost, "/auth/sms/verify", bearerJSON, nil, fmt.Sprintf(`{"userId":%q,"code":%q}`, id, code)); ok.StatusCode != http.StatusOK || decodeBody(t, ok)["accessToken"] == nil {
		t.Fatalf("the twin without the policy answered the same code %d %s, want a session: the refusals must have been presented with a good code and left it unspent", ok.StatusCode, ok.Body)
	}
	done := invoke(t, now.app, http.MethodPost, "/auth/2fa/verify", bearerJSON, nil,
		fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, temp, totpCodeNow(t, secret)))
	if done.StatusCode != http.StatusOK || decodeBody(t, done)["accessToken"] == nil {
		t.Fatalf("POST /auth/2fa/verify answered %d %s, want the session", done.StatusCode, done.Body)
	}
}

// TestTwoFactorRequiredOffersTOTPAlone: whatever transport is wired, the
// policy's challenge lists totp and nothing else, an account without TOTP is
// told to enrol rather than challenged for a link or a code, the hosted UI is
// told neither passwordless sign-in exists, and the cold start says so. The
// same deployment without the policy is the control: there the core offers
// the link and the code as the reference does.
func TestTwoFactorRequiredOffersTOTPAlone(t *testing.T) {
	t.Parallel()
	for name, transports := range map[string]func(map[string]string) map[string]string{
		"a mailer":             func(env map[string]string) map[string]string { return mailerEnv(env) },
		"an SMS transport":     smsEnv,
		"a mailer and SMS":     func(env map[string]string) map[string]string { return smsEnv(mailerEnv(env)) },
		"the delivery webhook": func(env map[string]string) map[string]string { return webhookEnv(env, testWebhookURL) },
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, required := range []bool{true, false} {
				users := newMemoryStoreBundle()
				env := with(transports(baseEnv()), "AWESOME_AUTH_UI_ENABLED", "true")
				if required {
					env = with(env, "AWESOME_AUTH_2FA_REQUIRED", "true")
				}
				d := newDeliveryAppWith(t, env, func(o *Options) { o.Stores = storeFactory(users, auth.NewMemorySessionStore()) })
				t.Cleanup(d.app.Close)
				const id, email, bare, bareEmail = "usr_0000000000000000000000offers1", "offers@example.test", "usr_0000000000000000000000offers2", "bare@example.test"
				seedTOTPAccount(t, users, id, email, "JBSWY3DPEHPK3PXP")
				seedAccount(t, users, bare, bareEmail)
				for _, uid := range []string{id, bare} {
					if _, err := users.UpdatePhoneNumber(context.Background(), uid, "", testPhone); err != nil {
						t.Fatalf("write the number: %v", err)
					}
				}
				bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
				login := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, testPassword))
				uiCfg := invoke(t, d.app, http.MethodGet, "/auth/ui/config", nil, nil, "")
				features, _ := decodeBody(t, uiCfg)["features"].(map[string]any)

				if required {
					requireTOTPChallenge(t, "the enrolled account's login", login)
					requireSetupRequired(t, "the login of an account with no TOTP", invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(bareEmail, testPassword)))
					if features["magicLink"] != false || features["sms"] != false {
						t.Errorf("GET /auth/ui/config features = %v, want magicLink and sms false: the hosted page must not offer what the policy refuses", features)
					}
					log := d.log.String()
					// The log is JSON (newLogger), so the fields are matched as
					// JSON members.
					for _, want := range []string{
						`"msg":"twoFactor.required: every session proves a TOTP code"`, `"secondFactor":"totp alone`, "in every mode",
						`"magicLinkAndSMSCode":"withheld under twoFactor.required`,
					} {
						if !strings.Contains(log, want) {
							t.Errorf("the cold start does not say %s:\n%s", want, log)
						}
					}
					for _, stale := range []string{"one-factor sign-ins refused", `"smsTransport":"sns"`, `"smsTransport":"webhook"`} {
						if strings.Contains(log, stale) {
							t.Errorf("the cold start says %s, as if the texted code or the old gate were in force:\n%s", stale, log)
						}
					}
					continue
				}
				// The control: the core's own list, the deliverable factors.
				body := decodeBody(t, login)
				methods := fmt.Sprint(body["available2faMethods"])
				mail := name != "an SMS transport"
				texts := name != "a mailer"
				if strings.Contains(methods, auth.TwoFactorMethodMagicLink) != mail || strings.Contains(methods, auth.TwoFactorMethodSMS) != texts {
					t.Errorf("without the policy the challenge offered %s; the control must show the factors the policy withholds", methods)
				}
				if features["magicLink"] != mail || features["sms"] != texts {
					t.Errorf("without the policy GET /auth/ui/config features = %v", features)
				}
			}
		})
	}
}

// TestTwoFactorRequiredEnrolsBesideAMailer: forced enrolment under the policy
// with a mail transport wired. On 872008e the fresh account was challenged for
// the emailed link — a factor the core counted — instead of being told to
// enrol, so twoFactor.enrolOnLogin never ran on a realm that sends mail; and
// the link then opened the session. Now it walks the whole enrolment.
func TestTwoFactorRequiredEnrolsBesideAMailer(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(with(baseEnv(),
		"AWESOME_AUTH_2FA_REQUIRED", "true",
		"AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true",
	)))
	t.Cleanup(d.app.Close)
	forcedEnrolment(t, d.app, "forced-mailer@example.test")
}

// TestTwoFactorRequiredEnrolOnLoginLetsTheMailboxClaimAnUnenrolledAccount
// pins the one way a mailbox still reaches a session under the policy, so that
// it stays exactly what the warnings say and nothing wider. With forced
// enrolment on and the reset mail wired, an account that has not enrolled TOTP
// yet is claimed through its mailbox: forgot-password, reset-password, the
// login's 2FA_SETUP_REQUIRED, then /2fa/setup and /2fa/verify-setup with a
// factor of the resetter's choosing — trust on first use, which is why
// twoFactor.enrolOnLogin is off by default and warned about. The control is a
// TOTP-enrolled account on the same deployment: the same walk reaches the TOTP
// challenge and no further — its tempToken enrols nothing, the emailed step-up
// is refused, and only its own code completes the challenge.
func TestTwoFactorRequiredEnrolOnLoginLetsTheMailboxClaimAnUnenrolledAccount(t *testing.T) {
	t.Parallel()
	users := newMemoryStoreBundle()
	d := newDeliveryAppWith(t, mailerEnv(with(baseEnv(),
		"AWESOME_AUTH_2FA_REQUIRED", "true",
		"AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true",
	)), func(o *Options) { o.Stores = storeFactory(users, auth.NewMemorySessionStore()) })
	t.Cleanup(d.app.Close)
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	const chosen = "the-mailbox-holders-password-0123"
	// The mailbox walk: forgot-password, reset-password to a password of the
	// mailbox holder's choosing, and the login with it.
	throughTheMailbox := func(t *testing.T, email string) events.APIGatewayV2HTTPResponse {
		t.Helper()
		d.mail.reset()
		if forgot := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil, fmt.Sprintf(`{"email":%q}`, email)); forgot.StatusCode != http.StatusOK {
			t.Fatalf("forgot-password for %s answered %d %s", email, forgot.StatusCode, forgot.Body)
		}
		token := tokenIn(t, linkIn(t, d.mail.only(t).Body))
		reset := invoke(t, d.app, http.MethodPost, "/auth/reset-password", bearerJSON, nil, fmt.Sprintf(`{"token":%q,"password":%q}`, token, chosen))
		if reset.StatusCode != http.StatusOK {
			t.Fatalf("reset-password for %s answered %d %s", email, reset.StatusCode, reset.Body)
		}
		requireNoSession(t, "reset-password", reset)
		return invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, chosen))
	}

	// The residual: an account with no factor yet is claimed.
	const unenrolled = "not-yet-enrolled@example.test"
	seedAccount(t, users, "usr_00000000000000000notenrolled1", unenrolled)
	login := throughTheMailbox(t, unenrolled)
	requireSetupRequired(t, "the unenrolled account's login with the reset password", login)
	temp, _ := decodeBody(t, login)["tempToken"].(string)
	withTemp := jsonHeaders("authorization", "Bearer "+temp, auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	setup := invoke(t, d.app, http.MethodPost, "/auth/2fa/setup", withTemp, nil, "{}")
	secret, _ := decodeBody(t, setup)["secret"].(string)
	if setup.StatusCode != http.StatusOK || secret == "" {
		t.Fatalf("POST /auth/2fa/setup with the enrolment token answered %d %s", setup.StatusCode, setup.Body)
	}
	claimed := invoke(t, d.app, http.MethodPost, "/auth/2fa/verify-setup", withTemp, nil,
		fmt.Sprintf(`{"secret":%q,"token":%q}`, secret, totpCodeNow(t, secret)))
	if claimed.StatusCode != http.StatusOK || decodeBody(t, claimed)["accessToken"] == nil {
		t.Fatalf("verify-setup answered %d %s, want the session forced enrolment opens: the residual the warnings disclose is this, and the test pins it as it is", claimed.StatusCode, claimed.Body)
	}

	// The control: an enrolled account, the same walk, and no further.
	const enrolled, ownSecret = "enrolled-owner@example.test", "JBSWY3DPEHPK3PXP"
	seedTOTPAccount(t, users, "usr_0000000000000000enrolledown1", enrolled, ownSecret)
	stepUp := requireTOTPChallenge(t, "the enrolled account's login with the reset password", throughTheMailbox(t, enrolled))
	stepUpBearer := jsonHeaders("authorization", "Bearer "+stepUp, auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	if s := invoke(t, d.app, http.MethodPost, "/auth/2fa/setup", stepUpBearer, nil, "{}"); s.StatusCode == http.StatusOK {
		t.Errorf("the enrolled account's step-up token started an enrolment of the resetter's choosing: %s", s.Body)
	}
	requireTwoFactorRequired(t, "the emailed step-up for the enrolled account",
		invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, fmt.Sprintf(`{"mode":"2fa","tempToken":%q}`, stepUp)))
	done := invoke(t, d.app, http.MethodPost, "/auth/2fa/verify", bearerJSON, nil,
		fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, stepUp, totpCodeNow(t, ownSecret)))
	if done.StatusCode != http.StatusOK || decodeBody(t, done)["accessToken"] == nil {
		t.Fatalf("the enrolled account's own code answered %d %s, want the session", done.StatusCode, done.Body)
	}
}

// TestTwoFactorRequiredRefusesLoginAfterLinking: POST <prefix>/link-verify
// with loginAfterLinking opens a session for the linked account on the emailed
// link-token alone (the core's IssueTokensForUser). With the OAuth callback
// refused there is no conflict stash to mint one from, but POST
// <prefix>/link-request mints one for any access token — mailed to whatever
// address the body names — so whoever holds an access token for fifteen
// minutes could turn it into a session of their own with a refresh token.
// Refused before the core reads the token; linking alone, on the same token,
// is the control.
func TestTwoFactorRequiredRefusesLoginAfterLinking(t *testing.T) {
	t.Parallel()
	users := newMemoryStoreBundle()
	d := newDeliveryAppWith(t, mailerEnv(with(baseEnv(),
		"AWESOME_AUTH_2FA_REQUIRED", "true",
		"AWESOME_AUTH_STORES_ENABLE_LINKED_ACCOUNTS", "true",
		"AWESOME_AUTH_STORES_ENABLE_PENDING_LINKS", "true",
	)), func(o *Options) {
		o.Stores = storeFactory(users, auth.NewMemorySessionStore())
	})
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	const id, owner, secret = "usr_00000000000000000000000linker", "linker@example.test", "JBSWY3DPEHPK3PXP"
	seedAccount(t, users, id, owner)
	if err := users.UpdateTOTPSecret(context.Background(), id, "", secret, true); err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}
	login := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, testPassword))
	temp, _ := decodeBody(t, login)["tempToken"].(string)
	verified := invoke(t, d.app, http.MethodPost, "/auth/2fa/verify", bearerJSON, nil,
		fmt.Sprintf(`{"tempToken":%q,"totpCode":%q}`, temp, totpCodeNow(t, secret)))
	access, _ := decodeBody(t, verified)["accessToken"].(string)
	if access == "" {
		t.Fatalf("the factor opened no session (%d %s); this test proves nothing without an access token", verified.StatusCode, verified.Body)
	}

	d.mail.reset()
	const elsewhere = "elsewhere@example.test"
	if req := invoke(t, d.app, http.MethodPost, "/auth/link-request", bearer(access), nil, fmt.Sprintf(`{"email":%q,"provider":"email"}`, elsewhere)); req.StatusCode != http.StatusOK {
		t.Fatalf("link-request with an access token answered %d %s", req.StatusCode, req.Body)
	}
	mail := d.mail.only(t)
	if mail.To != elsewhere {
		t.Errorf("the link token went to %v; the body named %s", mail.To, elsewhere)
	}
	token := tokenIn(t, linkIn(t, mail.Body))

	for name, body := range map[string]string{
		"loginAfterLinking":                 fmt.Sprintf(`{"token":%q,"loginAfterLinking":true}`, token),
		"the key in capitals":               fmt.Sprintf(`{"token":%q,"LOGINAFTERLINKING":true}`, token),
		"the last of two keys wins":         fmt.Sprintf(`{"token":%q,"loginAfterLinking":false,"loginAfterLinking":true}`, token),
		"a body that is not JSON":           "token=" + token + "&loginAfterLinking=true",
		"a flag that is not a JSON boolean": fmt.Sprintf(`{"token":%q,"loginAfterLinking":"true"}`, token),
	} {
		for _, headers := range []map[string]string{jsonHeaders(), bearerJSON} {
			requireTwoFactorRequired(t, "link-verify with "+name, invoke(t, d.app, http.MethodPost, "/auth/link-verify", headers, nil, body))
		}
	}
	requireTwoFactorRequired(t, "link-verify at /auth/link-verif%79",
		invoke(t, d.app, http.MethodPost, "/auth/link-verif%79", bearerJSON, nil, fmt.Sprintf(`{"token":%q,"loginAfterLinking":true}`, token)))

	linked := invoke(t, d.app, http.MethodPost, "/auth/link-verify", bearerJSON, nil, fmt.Sprintf(`{"token":%q}`, token))
	if linked.StatusCode != http.StatusOK || decodeBody(t, linked)["success"] != true {
		t.Fatalf("linking alone, on the same token, answered %d %s, want 200: the refusals must not have consumed it", linked.StatusCode, linked.Body)
	}
	requireNoSession(t, "link-verify without loginAfterLinking", linked)
}

// TestTwoFactorRequiredUnmountsTheAdminLogin: POST <admin>/login is not served
// under the policy. On b20ef56 an administrator's password alone got a
// 24-hour console token there; now it is the router's 404, as the core answers
// wherever the route is not mounted — and the console still admits that
// administrator on a session from POST <prefix>/login and its factor.
func TestTwoFactorRequiredUnmountsTheAdminLogin(t *testing.T) {
	t.Parallel()
	s := newAdminSurface(t, loadAdmin(t, withoutRootUser(adminEnv(config.AdminAccessPolicyIsAdmin, "AWESOME_AUTH_2FA_REQUIRED", "true"))), Options{}, nil)
	const id, email, secret = "usr_000000000000000000000operator", "operator@example.test", "JBSWY3DPEHPK3PXP"
	seedAccount(t, s.stores, id, email)
	ctx := context.Background()
	if err := s.stores.UpdateTOTPSecret(ctx, id, "", secret, true); err != nil {
		t.Fatalf("enable TOTP: %v", err)
	}
	if err := s.stores.UpdateIsAdmin(ctx, id, "", true); err != nil {
		t.Fatalf("flag the administrator: %v", err)
	}

	for _, path := range []string{"/admin/login", "/admin/%6Cogin"} {
		rec := s.call(t, http.MethodPost, path, map[string]string{"email": email, "password": testPassword})
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST %s with an administrator's password answered %d %s under twoFactor.required, want the router's 404", path, rec.Code, rec.Body.String())
		}
		for _, c := range rec.Result().Cookies() {
			if strings.HasSuffix(c.Name, "accessToken") && c.Value != "" {
				t.Errorf("POST %s set %s", path, c.Name)
			}
		}
	}

	bearerMode := func(r *http.Request) { r.Header.Set(auth.AuthStrategyHeader, auth.AuthStrategyBearer) }
	login := s.call(t, http.MethodPost, "/auth/login", map[string]string{"email": email, "password": testPassword}, bearerMode)
	if login.Code != http.StatusOK || decodeJSON(t, login)["requiresTwoFactor"] != true {
		t.Fatalf("POST /auth/login answered %d %s, want the challenge", login.Code, login.Body.String())
	}
	temp, _ := decodeJSON(t, login)["tempToken"].(string)
	verified := s.call(t, http.MethodPost, "/auth/2fa/verify", map[string]string{"tempToken": temp, "totpCode": totpCodeNow(t, secret)}, bearerMode)
	access, _ := decodeJSON(t, verified)["accessToken"].(string)
	if access == "" {
		t.Fatalf("POST /auth/2fa/verify answered %d %s, want a session", verified.Code, verified.Body.String())
	}
	if rec := s.call(t, http.MethodGet, "/admin/api/ping", nil, withBearer(access)); rec.Code != http.StatusOK {
		t.Errorf("the administrator's two-factor session answered %d on GET /admin/api/ping, want 200: the console's door under the policy", rec.Code)
	}
}

// TestTwoFactorRequiredKeepsMachineAccess: IAM machine access is not a sign-in
// and the policy leaves it alone — the org realm's shape, a console only a
// back-office service calls — while the console's login is refused on the
// internal API too.
func TestTwoFactorRequiredKeepsMachineAccess(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, withoutRootUser(adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_2FA_REQUIRED", "true",
		"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS", testMachineRole)))
	t.Cleanup(app.Close)
	if got := invokeIAM(t, app, http.MethodGet, "/admin/api/users", jsonHeaders(), testMachineCaller, ""); got.StatusCode != http.StatusOK {
		t.Errorf("the listed role's GET /admin/api/users answered %d %s under twoFactor.required, want 200", got.StatusCode, got.Body)
	}
	if got := invokeIAM(t, app, http.MethodPost, "/admin/login", jsonHeaders(), testMachineCaller, `{"email":"x@example.test","password":"y"}`); got.StatusCode != http.StatusNotFound {
		t.Errorf("POST /admin/login on the internal API answered %d, want 404", got.StatusCode)
	}
}

// TestTwoFactorRequiredLeavesTheIdPNoCodeToIssue: the identity provider's
// POST <prefix>/authorize signs in through the core's Service.Login, which has
// no second-factor step and refuses every account under the policy. It fails
// closed — 401 "invalid credentials", no code, so no /token pair — and the
// loader warns that no relying party can sign anyone in. The same request
// without the policy is the control.
func TestTwoFactorRequiredLeavesTheIdPNoCodeToIssue(t *testing.T) {
	t.Parallel()
	const redirect = "https://console.example.test/callback"
	for _, required := range []bool{true, false} {
		kv := []string{ConfigJSONEnv, clientDocument("console", redirect), "AWESOME_AUTH_IDP_CLIENT_CONSOLE_SECRET", "console-client-secret"}
		if required {
			kv = append(kv, "AWESOME_AUTH_2FA_REQUIRED", "true")
		}
		app := newIDPApp(t, newFakeKeyring(t, "current"), idpEnv(kv...))
		email := fmt.Sprintf("oidc-%v@example.test", required)
		if reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email)); reg.StatusCode != http.StatusCreated {
			t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
		}
		form := url.Values{"email": {email}, "password": {testPassword}}
		authorize := invoke(t, app, http.MethodPost,
			"/auth/authorize?client_id=console&redirect_uri="+url.QueryEscape(redirect)+"&state=xyz&nonce=n-1",
			map[string]string{"content-type": "application/x-www-form-urlencoded"}, nil, form.Encode())
		issued := strings.Contains(authorize.Headers["Location"], "code=")
		switch {
		case required && (authorize.StatusCode != http.StatusUnauthorized || issued):
			t.Errorf("POST /auth/authorize under twoFactor.required answered %d (Location %q), want 401 and no code", authorize.StatusCode, authorize.Headers["Location"])
		case !required && (authorize.StatusCode != http.StatusFound || !issued):
			t.Errorf("the control's POST /auth/authorize answered %d %s, want the 302 with a code", authorize.StatusCode, authorize.Body)
		}
		app.Close()
	}
}

// TestSecondFactorGateIsIdentityWithoutThePolicy: with twoFactor.required off
// the gate is not in the chain at all and the senders are wired, so the
// passwordless routes answer as the core does — the emailed link signs in on
// its own, the reference's passwordless login, and answers an enrolled
// account's challenge as the second step — and the console's login is served.
func TestSecondFactorGateIsIdentityWithoutThePolicy(t *testing.T) {
	t.Parallel()
	users := newMemoryStoreBundle()
	d := newDeliveryAppWith(t, mailerEnv(baseEnv()), func(o *Options) { o.Stores = storeFactory(users, auth.NewMemorySessionStore()) })
	t.Cleanup(d.app.Close)
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	const owner = "optional@example.test"
	if reg := invoke(t, d.app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(owner)); reg.StatusCode != http.StatusCreated {
		t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
	}
	if send := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, fmt.Sprintf(`{"email":%q}`, owner)); send.StatusCode != http.StatusOK {
		t.Fatalf("magic-link/send answered %d %s", send.StatusCode, send.Body)
	}
	verify := invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q}`, tokenIn(t, linkIn(t, d.mail.only(t).Body))))
	if verify.StatusCode != http.StatusOK || decodeBody(t, verify)["accessToken"] == nil {
		t.Errorf("without the policy the login-mode link answered %d %s, want the session", verify.StatusCode, verify.Body)
	}

	// The step-up: an enrolled account is offered the link beside its TOTP
	// code, and the link completes the challenge.
	d.mail.reset()
	const id, enrolled = "usr_00000000000000000000optional", "optional-totp@example.test"
	seedTOTPAccount(t, users, id, enrolled, "JBSWY3DPEHPK3PXP")
	login := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(enrolled, testPassword))
	if methods := fmt.Sprint(decodeBody(t, login)["available2faMethods"]); login.StatusCode != http.StatusOK || !strings.Contains(methods, auth.TwoFactorMethodMagicLink) {
		t.Fatalf("without the policy the enrolled account's login answered %d %s, want the challenge offering the link", login.StatusCode, login.Body)
	}
	temp, _ := decodeBody(t, login)["tempToken"].(string)
	if step := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, fmt.Sprintf(`{"mode":"2fa","tempToken":%q}`, temp)); step.StatusCode != http.StatusOK {
		t.Fatalf("without the policy the step-up send answered %d %s", step.StatusCode, step.Body)
	}
	stepped := invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"mode":"2fa","tempToken":%q}`, tokenIn(t, linkIn(t, d.mail.only(t).Body)), temp))
	if stepped.StatusCode != http.StatusOK || decodeBody(t, stepped)["accessToken"] == nil {
		t.Errorf("without the policy the step-up link answered %d %s, want the session", stepped.StatusCode, stepped.Body)
	}

	s := newAdminSurface(t, loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin)), Options{}, nil)
	s.rootLogin(t)
}

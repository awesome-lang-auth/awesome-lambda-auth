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

// twoFactor.required at every door (secondfactor.go, RS-20).
//
// Each test below presents, under the policy, a credential that opened a
// session through the same door on the build before the gate — b20ef56 pinned
// three of them as TestOAuthCallbackSkipsTheFactorTheRealmRequires,
// TestAdminLoginSkipsTheFactorTheRealmRequires and
// TestMagicLinkLoginSkipsTheFactorTheRealmRequires, and the review that
// followed reached the SMS login and /link-verify the same way — and asserts
// that it opens nothing now. Then, as the control, it completes the same
// credential through the door that does ask for the factor, so a refusal
// cannot pass on a credential that was never good.

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

// TestTwoFactorRequiredRefusesTheMagicLinkLogin: the emailed link alone opens
// nothing. The login mode's send is refused before a link is minted or mailed;
// the step-up mode's send mails one, because under the policy the link is a
// second factor; and that link, presented without the login's tempToken in
// every shape the core reads as login mode, is refused before the core
// consumes it — so the control, the same link in step-up mode, still opens
// the session.
func TestTwoFactorRequiredRefusesTheMagicLinkLogin(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true")))
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	const owner = "passwordless@example.test"
	if reg := invoke(t, d.app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(owner)); reg.StatusCode != http.StatusCreated {
		t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
	}
	login := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, testPassword))
	if login.StatusCode != http.StatusOK || decodeBody(t, login)["requiresTwoFactor"] != true {
		t.Fatalf("the password login answered %d %s, want the challenge; the policy is not on and this test proves nothing", login.StatusCode, login.Body)
	}
	temp, _ := decodeBody(t, login)["tempToken"].(string)

	for _, body := range []string{fmt.Sprintf(`{"email":%q}`, owner), fmt.Sprintf(`{"email":%q,"mode":"login"}`, owner)} {
		requireTwoFactorRequired(t, "magic-link/send "+body, invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, body))
	}
	if n := len(d.mail.messages()); n != 0 {
		t.Fatalf("the refused login-mode sends mailed %d message(s)", n)
	}

	step := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, fmt.Sprintf(`{"mode":"2fa","tempToken":%q}`, temp))
	if step.StatusCode != http.StatusOK {
		t.Fatalf("the step-up send answered %d %s, want 200: under the policy the link is the second factor", step.StatusCode, step.Body)
	}
	token := tokenIn(t, linkIn(t, d.mail.only(t).Body))

	// The link alone: a session on b20ef56, in either delivery mode.
	for name, body := range map[string]string{
		"no mode":                       fmt.Sprintf(`{"token":%q}`, token),
		"mode login":                    fmt.Sprintf(`{"token":%q,"mode":"login"}`, token),
		"the step-up value in capitals": fmt.Sprintf(`{"token":%q,"mode":"2FA"}`, token),
		"the last of two keys wins":     fmt.Sprintf(`{"token":%q,"mode":"2fa","MODE":""}`, token),
		"an empty body":                 "",
		"a body that is not JSON":       "token=" + token,
	} {
		for _, headers := range []map[string]string{jsonHeaders(), bearerJSON} {
			requireTwoFactorRequired(t, "magic-link/verify with "+name, invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify", headers, nil, body))
		}
	}
	// A spelling the router resolves to the same route is the same route.
	requireTwoFactorRequired(t, "magic-link/verify at /auth/magic-link/verif%79",
		invoke(t, d.app, http.MethodPost, "/auth/magic-link/verif%79", bearerJSON, nil, fmt.Sprintf(`{"token":%q}`, token)))
	// A key the core matches case-insensitively is the step-up to both
	// readers, and the core then asks for the tempToken it lacks: the gate
	// passes it, and nothing opens.
	folded := invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify", bearerJSON, nil, fmt.Sprintf(`{"token":%q,"MODE":"2fa"}`, token))
	requireNoSession(t, "magic-link/verify with MODE 2fa and no tempToken", folded)
	if folded.StatusCode != http.StatusBadRequest || decodeBody(t, folded)["code"] != auth.CodeTempTokenRequired {
		t.Errorf("magic-link/verify with MODE 2fa and no tempToken answered %d %s, want the core's 400 TEMP_TOKEN_REQUIRED", folded.StatusCode, folded.Body)
	}

	done := invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"mode":"2fa","tempToken":%q}`, token, temp))
	if done.StatusCode != http.StatusOK || decodeBody(t, done)["accessToken"] == nil {
		t.Fatalf("the same link in step-up mode answered %d %s, want the session: the refusals must not have consumed it", done.StatusCode, done.Body)
	}
}

// TestTwoFactorRequiredRefusesTheSMSLogin: the texted code alone opens
// nothing, on the same terms as the emailed link. The account's number is
// written through the store, as provisioning would: under the policy an
// account with no factor cannot get the session /add-phone needs.
func TestTwoFactorRequiredRefusesTheSMSLogin(t *testing.T) {
	t.Parallel()
	users := newMemoryStoreBundle()
	d := newDeliveryAppWith(t, smsEnv(with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true")), func(o *Options) {
		o.Stores = storeFactory(users, auth.NewMemorySessionStore())
	})
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	const id, owner = "usr_000000000000000000000000texted", "texted@example.test"
	seedAccount(t, users, id, owner)
	if _, err := users.UpdatePhoneNumber(context.Background(), id, "", testPhone); err != nil {
		t.Fatalf("write the number: %v", err)
	}
	login := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, testPassword))
	methods, _ := decodeBody(t, login)["available2faMethods"].([]any)
	if login.StatusCode != http.StatusOK || len(methods) != 1 || methods[0] != auth.TwoFactorMethodSMS {
		t.Fatalf("the password login answered %d %s, want the challenge for the texted code; this test proves nothing without it", login.StatusCode, login.Body)
	}
	temp, _ := decodeBody(t, login)["tempToken"].(string)

	for _, body := range []string{fmt.Sprintf(`{"email":%q}`, owner), fmt.Sprintf(`{"userId":%q}`, id)} {
		requireTwoFactorRequired(t, "sms/send "+body, invoke(t, d.app, http.MethodPost, "/auth/sms/send", jsonHeaders(), nil, body))
	}
	if n := len(d.sms.messages()); n != 0 {
		t.Fatalf("the refused login-mode sends texted %d message(s)", n)
	}

	step := invoke(t, d.app, http.MethodPost, "/auth/sms/send", jsonHeaders(), nil, fmt.Sprintf(`{"mode":"2fa","tempToken":%q}`, temp))
	if step.StatusCode != http.StatusOK || len(d.sms.messages()) != 1 {
		t.Fatalf("the step-up send answered %d %s with %d text(s), want 200 and one", step.StatusCode, step.Body, len(d.sms.messages()))
	}
	code := strings.TrimPrefix(d.sms.messages()[0].message, "Your verification code is: ")

	// The code alone: a session on b20ef56 (the review's probe).
	for name, body := range map[string]string{
		"userId and code":           fmt.Sprintf(`{"userId":%q,"code":%q}`, id, code),
		"mode login":                fmt.Sprintf(`{"userId":%q,"code":%q,"mode":"login"}`, id, code),
		"the last of two keys wins": fmt.Sprintf(`{"userId":%q,"code":%q,"mode":"2fa","Mode":""}`, id, code),
	} {
		requireTwoFactorRequired(t, "sms/verify with "+name, invoke(t, d.app, http.MethodPost, "/auth/sms/verify", bearerJSON, nil, body))
	}
	requireTwoFactorRequired(t, "sms/verify at /auth/sms/verif%79",
		invoke(t, d.app, http.MethodPost, "/auth/sms/verif%79", bearerJSON, nil, fmt.Sprintf(`{"userId":%q,"code":%q}`, id, code)))

	done := invoke(t, d.app, http.MethodPost, "/auth/sms/verify", bearerJSON, nil,
		fmt.Sprintf(`{"mode":"2fa","tempToken":%q,"code":%q}`, temp, code))
	if done.StatusCode != http.StatusOK || decodeBody(t, done)["accessToken"] == nil {
		t.Fatalf("the same code in step-up mode answered %d %s, want the session: the refusals must not have consumed it", done.StatusCode, done.Body)
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
// the gate is not in the chain at all, so the login modes answer as the core
// does — the emailed link signs in on its own, the reference's passwordless
// login — and the console's login is served.
func TestSecondFactorGateIsIdentityWithoutThePolicy(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(baseEnv()))
	const owner = "optional@example.test"
	if reg := invoke(t, d.app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(owner)); reg.StatusCode != http.StatusCreated {
		t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
	}
	if send := invoke(t, d.app, http.MethodPost, "/auth/magic-link/send", jsonHeaders(), nil, fmt.Sprintf(`{"email":%q}`, owner)); send.StatusCode != http.StatusOK {
		t.Fatalf("magic-link/send answered %d %s", send.StatusCode, send.Body)
	}
	verify := invoke(t, d.app, http.MethodPost, "/auth/magic-link/verify", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"token":%q}`, tokenIn(t, linkIn(t, d.mail.only(t).Body))))
	if verify.StatusCode != http.StatusOK || decodeBody(t, verify)["accessToken"] == nil {
		t.Errorf("without the policy the login-mode link answered %d %s, want the session", verify.StatusCode, verify.Body)
	}

	s := newAdminSurface(t, loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin)), Options{}, nil)
	s.rootLogin(t)
}

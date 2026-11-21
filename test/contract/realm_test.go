package contract

// Realm modes: a deployment whose registration is closed, or whose login
// demands a second factor, or both — the invite-only staff realm. The suite
// provisions itself through POST <prefix>/register and signs its accounts in
// with a password alone, and neither works there, so the operator declares the
// realm and an account in it, the way the admin credential is declared:
//
//	AWESOME_AUTH_CONTRACT_REGISTRATION=closed
//	AWESOME_AUTH_CONTRACT_2FA=required
//	AWESOME_AUTH_CONTRACT_REALM_EMAIL=…  AWESOME_AUTH_CONTRACT_REALM_PASSWORD=…
//	AWESOME_AUTH_CONTRACT_REALM_TOTP_SECRET=…   (the account's enrolled factor)
//
// What changes with a declaration, and nothing changes without one:
//
//   - The probe pass signs the declared account in — completing its TOTP
//     challenge — instead of registering one, so every capability is still
//     probed.
//   - registration-closed is the declared closure, verified: POST /register
//     must answer 404. 2fa-required is the declared policy, verified as far as
//     the realm lets it be seen: on an open realm a fresh account's password
//     must open no session — 403 2FA_SETUP_REQUIRED, or the challenge where a
//     mail or SMS transport makes a factor deliverable; on a closed one the
//     declared account must be challenged rather than logged straight in.
//     2fa-enrol-on-login is probed on an open realm whose fresh account is
//     told to enrol, with that account's token.
//   - Every case that provisions an account of its own (Env.NewAccount, and
//     LoginCookie and LoginBearer through it) skips, with that reason, because
//     it registers through the closed route or signs in with a password alone.
//     The cases below are the ones written for these realms.
//
// The declared account is shared and is never mutated: nothing here enrols it,
// disables its factor, changes its password or its email, or deletes it — a
// case that needs to do any of that runs on a fresh account, on an open realm.
// And it is signed in as few times as the pass allows, because the login route
// is rate limited per account (10 a minute by default).

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	// RegistrationEnv declares the realm's registration: "open" (the default)
	// or "closed".
	RegistrationEnv = "AWESOME_AUTH_CONTRACT_REGISTRATION"

	// TwoFactorEnv declares the realm's second-factor policy at login:
	// "optional" (the default) or "required".
	TwoFactorEnv = "AWESOME_AUTH_CONTRACT_2FA"

	// RealmEmailEnv, RealmPasswordEnv and RealmTOTPSecretEnv declare the account
	// a closed or 2FA-required realm is checked through. The secret is the
	// base32 TOTP secret the account is enrolled with, and is required when
	// the realm challenges it.
	RealmEmailEnv      = "AWESOME_AUTH_CONTRACT_REALM_EMAIL"
	RealmPasswordEnv   = "AWESOME_AUTH_CONTRACT_REALM_PASSWORD"
	RealmTOTPSecretEnv = "AWESOME_AUTH_CONTRACT_REALM_TOTP_SECRET"
)

// realm is what the operator declared about the deployment's policy.
type realm struct {
	closed        bool
	twoFARequired bool
	account       Account
}

// restricted reports whether the realm is one the suite cannot provision
// itself in: closed, or demanding a second factor of a password login.
func (r realm) restricted() bool { return r.closed || r.twoFARequired }

// describe names the declarations, for a skip reason.
func (r realm) describe() string {
	switch {
	case r.closed && r.twoFARequired:
		return "closed and 2FA-required"
	case r.closed:
		return "closed"
	case r.twoFARequired:
		return "2FA-required"
	}
	return "open"
}

// readRealm reads the declarations. A misconfigured run — an unknown value, a
// half-declared account, a restricted realm with no account, an account with
// nothing to use it for — is a fault and fails the run, as a half-declared
// admin credential does: a suite that guessed would report on a realm nobody
// described.
func readRealm(t *testing.T) realm {
	t.Helper()
	var r realm
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(RegistrationEnv))); v {
	case "", "open":
	case "closed":
		r.closed = true
	default:
		t.Fatalf("%s=%q: want open or closed", RegistrationEnv, v)
	}
	switch v := strings.ToLower(strings.TrimSpace(os.Getenv(TwoFactorEnv))); v {
	case "", "optional":
	case "required":
		r.twoFARequired = true
	default:
		t.Fatalf("%s=%q: want optional or required", TwoFactorEnv, v)
	}
	email := strings.TrimSpace(os.Getenv(RealmEmailEnv))
	password := os.Getenv(RealmPasswordEnv)
	secret := strings.TrimSpace(os.Getenv(RealmTOTPSecretEnv))
	switch {
	case (email == "") != (password == ""):
		t.Fatalf("only one of %s and %s is set; a half-declared realm account is a misconfigured run", RealmEmailEnv, RealmPasswordEnv)
	case secret != "" && email == "":
		t.Fatalf("%s is set with no account to use it for; declare %s and %s too", RealmTOTPSecretEnv, RealmEmailEnv, RealmPasswordEnv)
	case r.restricted() && email == "":
		t.Fatalf(`%s/%s declare a realm the suite cannot provision itself in, and no account is declared.

A closed realm refuses POST <prefix>/register and a 2FA-required one refuses a
password alone, so the probe pass signs in an account the operator created:
set %s and %s, and %s when the realm challenges it.`, RegistrationEnv, TwoFactorEnv, RealmEmailEnv, RealmPasswordEnv, RealmTOTPSecretEnv)
	case !r.restricted() && email != "":
		t.Fatalf("%s is set and neither %s=closed nor %s=required is: the realm account is used only by a realm the suite cannot provision itself in",
			RealmEmailEnv, RegistrationEnv, TwoFactorEnv)
	}
	r.account = Account{Email: email, Password: password, TOTPSecret: secret}
	return r
}

// signIn logs acct in on c and returns the response that carries the session:
// the login itself, or — for an account the deployment challenges — the
// POST /2fa/verify that completes the challenge with acct.TOTPSecret. Any other
// answer is returned as it is, for the caller to judge.
func (e *Env) signIn(t *testing.T, c *Client, acct Account, opts ...reqOpt) *Resp {
	t.Helper()
	login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, opts...)
	if login.Status != 200 || login.obj(t)["requiresTwoFactor"] != true {
		return login
	}
	if acct.TOTPSecret == "" {
		t.Fatalf("%s is challenged for a second factor and no TOTP secret is declared for it: set %s\n  %s",
			acct.Email, RealmTOTPSecretEnv, login.where())
	}
	return c.POST(t, "/2fa/verify", body{"tempToken": login.str(t, "tempToken"), "totpCode": totpNow(t, acct.TOTPSecret)}, opts...)
}

// registerFresh registers a throwaway account directly, for the realm probes
// and cases that need an account with no factor on an open realm.
// Env.NewAccount skips on a restricted realm; this does not, so it is only for
// the code that knows the realm is open.
func (e *Env) registerFresh(t *testing.T) Account {
	t.Helper()
	acct := randomAccount()
	e.NewClient().POST(t, "/register", body{"email": acct.Email, "password": acct.Password}).mustStatusIn(t, 200, 201)
	return acct
}

// ── the capabilities ─────────────────────────────────────────────────────────

// CapRegistrationClosed is the declared closure of POST <prefix>/register,
// verified. It is settled by CapRegister's probe, from the same request.
const CapRegistrationClosed Capability = "registration-closed"

// Cap2FARequired is the declared second-factor policy at login, verified as
// far as the realm lets it be seen.
const Cap2FARequired Capability = "2fa-required"

// Cap2FAEnrolOnLogin is forced enrolment: the tempToken of a
// 2FA_SETUP_REQUIRED answer enrols through POST /2fa/setup and
// /2fa/verify-setup. Probed on an open realm with a fresh account's token.
const Cap2FAEnrolOnLogin Capability = "2fa-enrol-on-login"

func init() {
	registerCapability(capabilityDecl{
		Name:    Cap2FARequired,
		Settles: []Capability{Cap2FAEnrolOnLogin},
		Stage:   stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			r := p.Env.Realm
			if !r.twoFARequired {
				why := fmt.Sprintf("not declared: set %s=required for a realm that demands a second factor at login", TwoFactorEnv)
				p.Set(Cap2FARequired, capability{state: capAbsent, why: why})
				p.Set(Cap2FAEnrolOnLogin, capability{state: capAbsent, why: "probed only on a realm declared 2FA-required"})
				return
			}
			// The declared account first, on a fresh client: a password alone
			// must not sign it in. Its own sign-in, factor included, is
			// LoggedIn's business and is not repeated here.
			login := p.Env.NewClient().POST(t, "/login", body{"email": r.account.Email, "password": r.account.Password})
			switch {
			case login.Status == 200 && login.obj(t)["requiresTwoFactor"] == true:
			case login.Status == 200:
				p.Set(Cap2FARequired, capability{state: capBroken, why: "declared required, and the realm account's password alone opened a session: " + login.where()})
				p.Set(Cap2FAEnrolOnLogin, capability{state: capBroken, why: "the policy itself is broken; see 2fa-required"})
				return
			default:
				p.Set(Cap2FARequired, capability{state: capBroken, why: "the realm account is not challenged for its factor — enrol it out of band and declare its secret: " + login.where()})
				p.Set(Cap2FAEnrolOnLogin, capability{state: capBroken, why: "the realm account cannot sign in; see 2fa-required"})
				return
			}
			if r.closed {
				p.Set(Cap2FARequired, capability{state: capOn, why: "the realm account is challenged for its factor; what an account with none is answered cannot be seen on a closed realm"})
				p.Set(Cap2FAEnrolOnLogin, capability{state: capAbsent, why: "a closed realm has no unenrolled account to probe forced enrolment with"})
				return
			}

			// An open realm: a fresh account has no TOTP, so its login is the
			// policy's own answer, and it has two right ones. Where no factor
			// is deliverable it is told to enrol: 403 2FA_SETUP_REQUIRED.
			// Where a mail or SMS transport is wired the emailed link or the
			// texted code is a factor the core counts (the core's
			// advertised-2fa-methods-require-store-support), so it is
			// challenged instead. Either way a password alone opens nothing,
			// which is the claim; a session is the fault.
			fresh := p.Env.registerFresh(t)
			gated := p.Env.NewClient().POST(t, "/login", body{"email": fresh.Email, "password": fresh.Password})
			m := map[string]any{}
			if gated.Status == 403 || gated.Status == 200 {
				m = gated.obj(t)
			}
			_, session := m["accessToken"]
			if gated.Status == 200 && m["requiresTwoFactor"] == true && !session && gated.cookie(cookieAccess) == nil {
				p.Set(Cap2FARequired, capability{state: capOn, why: fmt.Sprintf(
					"a fresh account's login answered the challenge for a factor the deployment delivers (available2faMethods %v), and the realm account is challenged", m["available2faMethods"])})
				p.Set(Cap2FAEnrolOnLogin, capability{state: capAbsent, why: "a fresh account here is challenged for a mailed or texted factor rather than told to enrol, so forced enrolment cannot be probed"})
				return
			}
			temp, _ := m["tempToken"].(string)
			if gated.Status != 403 || m["code"] != "2FA_SETUP_REQUIRED" || m["requires2FASetup"] != true || temp == "" {
				p.Set(Cap2FARequired, capability{state: capBroken, why: "declared required, and a fresh account's password login is neither 403 2FA_SETUP_REQUIRED nor the challenge: " + gated.where()})
				p.Set(Cap2FAEnrolOnLogin, capability{state: capBroken, why: "the policy itself is broken; see 2fa-required"})
				return
			}
			p.Set(Cap2FARequired, capability{state: capOn, why: "a fresh account's login answered 403 2FA_SETUP_REQUIRED and the realm account is challenged"})

			// Forced enrolment: does the token enrol? POST /2fa/setup with it
			// answers a secret and stores nothing, so the probe costs nothing
			// but the throwaway account.
			setup := p.Env.NewClient().POST(t, "/2fa/setup", body{}, Bearer(temp))
			switch {
			case setup.Status == 200 && setup.hasKey(t, "secret"):
				p.Set(Cap2FAEnrolOnLogin, capability{state: capOn, why: "POST /2fa/setup accepted the setup-required token and answered a secret"})
			case setup.Status == 401 || setup.Status == 403:
				p.Set(Cap2FAEnrolOnLogin, capability{state: capAbsent, why: fmt.Sprintf(
					"POST /2fa/setup refused the setup-required token (%d): the realm enrols out of band (twoFactor.enrolOnLogin off)", setup.Status)})
			default:
				p.Set(Cap2FAEnrolOnLogin, capability{state: capBroken, why: "POST /2fa/setup answered the setup-required token with neither a secret nor a refusal: " + setup.where()})
			}
		},
	})
}

// ── the cases ────────────────────────────────────────────────────────────────

func init() {
	register(
		Case{
			Name: "registration/closed-realm-refuses-self-registration",
			Doc: "core register-route-is-always-mounted, with HTTPConfig.ClosedRegistration (registration.closed here) — POST " +
				"<prefix>/register is not mounted and answers the router's 404, the reference's deployment without an onRegister " +
				"hook (auth.router.ts:712-715): in both delivery modes, with no session, and no account comes of it",
			Needs: []Capability{CapRegistrationClosed},
			Run: func(t *testing.T, e *Env) {
				for _, mode := range []struct {
					name string
					opts []reqOpt
				}{{"cookie", nil}, {"bearer", []reqOpt{BearerStrategy()}}} {
					acct := randomAccount()
					r := e.NewClient().POST(t, "/register", body{"email": acct.Email, "password": acct.Password}, mode.opts...)
					if r.Status != 404 {
						t.Errorf("%s mode: want the router's 404\n  %s", mode.name, r.where())
					}
					for _, credential := range []string{cookieAccess, cookieRefresh} {
						if c := r.cookie(credential); c != nil {
							t.Errorf("%s mode: a refused registration set %s\n  %s", mode.name, c.Name, r.where())
						}
					}
					// Nothing was created: the address it named does not sign in.
					if login := e.NewClient().POST(t, "/login", body{"email": acct.Email, "password": acct.Password}); login.Status == 200 {
						t.Errorf("%s mode: the address a refused registration named signs in\n  %s", mode.name, login.where())
					}
				}
			},
		},

		Case{
			Name: "registration/closed-realm-hides-sign-up-from-the-ui",
			Doc: "ui.router.ts:115 — GET <prefix>/ui/config answers features.register false when no registration hook is " +
				"configured, which is what makes the built-in login page hide its sign-up link",
			Needs: []Capability{CapRegistrationClosed, CapUI},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/ui/config")
				r.mustStatus(t, 200)
				features, _ := r.obj(t)["features"].(map[string]any)
				if got, ok := features["register"]; !ok || got != false {
					t.Errorf("features.register = %v on a closed realm, want false\n  %s", got, r.where())
				}
			},
		},

		Case{
			Name:  "registration/closed-realm-documents-no-sign-up",
			Doc:   "core OpenAPIInfo.ClosedRegistration — the served OpenAPI document leaves out the route the realm does not mount",
			Needs: []Capability{CapRegistrationClosed, CapDocs},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/openapi.json")
				r.mustStatus(t, 200)
				paths, _ := r.obj(t)["paths"].(map[string]any)
				base := ""
				for p := range paths {
					if strings.HasSuffix(p, "/login") {
						base = strings.TrimSuffix(p, "/login")
					}
				}
				if base == "" && paths["/login"] == nil {
					t.Fatalf("the document has no /login path to find the base by\n  %s", r.where())
				}
				if _, ok := paths[base+"/register"]; ok {
					t.Errorf("the document describes %s/register on a closed realm\n  %s", base, r.where())
				}
			},
		},

		Case{
			Name: "2fa-required/password-alone-opens-no-session",
			Doc: "core config-require2fa-is-a-system-policy-term (twoFactor.required here) — under the policy a password alone " +
				"opens no session: an enrolled account gets the challenge (auth.router.ts:569-576) and completes it with its " +
				"factor; an account with none gets 403 {\"requires2FASetup\":true,\"tempToken\":…,\"code\":\"2FA_SETUP_REQUIRED\"} " +
				"(:562-568), whose token opens nothing",
			Needs: []Capability{Cap2FARequired},
			Run: func(t *testing.T, e *Env) {
				acct := e.Realm.account
				for _, mode := range []struct {
					name string
					opts []reqOpt
				}{{"cookie", nil}, {"bearer", []reqOpt{BearerStrategy()}}} {
					c := e.NewClient()
					login := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, mode.opts...)
					login.mustStatus(t, 200)
					m := login.obj(t)
					if m["requiresTwoFactor"] != true {
						t.Fatalf("%s mode: the realm account was not challenged\n  %s", mode.name, login.where())
					}
					for _, credential := range []string{"accessToken", "refreshToken"} {
						if _, leaked := m[credential]; leaked {
							t.Errorf("%s mode: the challenge carries %s\n  %s", mode.name, credential, login.where())
						}
						if ck := login.cookie(credential); ck != nil {
							t.Errorf("%s mode: the challenge set %s\n  %s", mode.name, ck.Name, login.where())
						}
					}
					if mode.opts == nil {
						// The cookie client holds no session until the factor.
						c.GET(t, "/me").mustCodelessError(t, 403, "No access token provided")
					}
				}
				// And the factor completes it.
				c := e.NewClient()
				e.signIn(t, c, acct).mustStatus(t, 200)
				me := c.GET(t, "/me")
				me.mustStatus(t, 200)
				if me.obj(t)["isTotpEnabled"] != true {
					t.Errorf("the realm account signed in with its factor and /me says isTotpEnabled is not true\n  %s", me.where())
				}

				if e.Realm.closed {
					t.Log("a closed realm has no account without a factor to show the setup-required answer on; it is covered on an open realm")
					return
				}
				// A fresh account has no TOTP. Told to enrol where no factor is
				// deliverable; challenged where a mailed or texted one is.
				fresh := e.registerFresh(t)
				gated := e.NewClient().POST(t, "/login", body{"email": fresh.Email, "password": fresh.Password})
				if ck := gated.cookie(cookieAccess); ck != nil {
					t.Errorf("a password alone set %s\n  %s", ck.Name, gated.where())
				}
				switch gated.Status {
				case 403:
					g := gated.obj(t)
					if g["requires2FASetup"] != true || g["code"] != "2FA_SETUP_REQUIRED" {
						t.Errorf("want {requires2FASetup:true, code:2FA_SETUP_REQUIRED}\n  %s", gated.where())
					}
					temp := gated.str(t, "tempToken")
					if me := e.NewClient().GET(t, "/me", Bearer(temp)); me.Status == 200 {
						t.Errorf("the setup-required tempToken opened GET /me\n  %s", me.where())
					}
				case 200:
					g := gated.obj(t)
					methods, _ := g["available2faMethods"].([]any)
					if g["requiresTwoFactor"] != true || len(methods) == 0 {
						t.Errorf("a fresh account's password alone was answered 200 without the challenge\n  %s", gated.where())
					}
					if _, leaked := g["accessToken"]; leaked {
						t.Errorf("the challenge carries an access token\n  %s", gated.where())
					}
				default:
					t.Errorf("want 403 2FA_SETUP_REQUIRED, or the challenge where a mailed or texted factor is deliverable\n  %s", gated.where())
				}
			},
		},

		Case{
			Name: "2fa-required/setup-token-enrols-and-opens-the-session",
			Doc: "core forced-enrolment-opens-a-session (twoFactor.enrolOnLogin here) — the setup-required tempToken, sent as " +
				"Authorization: Bearer as a reference client sends it, enrols through POST /2fa/setup and /2fa/verify-setup, and " +
				"the verify-setup it completes opens the session as /2fa/verify does, cookies or bearer tokens; the token dies " +
				"with the enrolment, and the next login is the challenge",
			Needs: []Capability{Cap2FARequired, Cap2FAEnrolOnLogin},
			Run: func(t *testing.T, e *Env) {
				for _, mode := range []struct {
					name string
					opts []reqOpt
				}{{"cookie", nil}, {"bearer", []reqOpt{BearerStrategy()}}} {
					fresh := e.registerFresh(t)
					c := e.NewClient()
					gated := c.POST(t, "/login", body{"email": fresh.Email, "password": fresh.Password}, mode.opts...)
					gated.mustStatus(t, 403)
					temp := gated.str(t, "tempToken")

					setup := c.POST(t, "/2fa/setup", body{}, append([]reqOpt{Bearer(temp)}, mode.opts...)...)
					setup.mustStatus(t, 200)
					secret := setup.str(t, "secret")

					done := c.POST(t, "/2fa/verify-setup", body{"secret": secret, "token": totpNow(t, secret)}, append([]reqOpt{Bearer(temp)}, mode.opts...)...)
					done.mustStatus(t, 200)
					var me *Resp
					if mode.opts == nil {
						if done.cookie(cookieAccess) == nil {
							t.Fatalf("cookie mode: the enrolment opened no session cookie\n  %s", done.where())
						}
						me = c.GET(t, "/me")
					} else {
						done.mustNoCookies(t)
						me = e.NewClient().GET(t, "/me", Bearer(done.str(t, "accessToken")))
					}
					me.mustStatus(t, 200)
					if me.obj(t)["isTotpEnabled"] != true {
						t.Errorf("%s mode: after the enrolment /me says isTotpEnabled is not true\n  %s", mode.name, me.where())
					}

					e.NewClient().POST(t, "/2fa/verify-setup", body{"tempToken": temp, "secret": secret, "token": totpNow(t, secret)}).
						mustError(t, 401, "INVALID_TEMP_TOKEN", "")
					again := e.NewClient().POST(t, "/login", body{"email": fresh.Email, "password": fresh.Password})
					again.mustStatus(t, 200)
					if again.obj(t)["requiresTwoFactor"] != true {
						t.Errorf("%s mode: the next login is not the challenge for the factor just enrolled\n  %s", mode.name, again.where())
					}
				}
			},
		},

		Case{
			Name: "2fa-required/disable-is-refused",
			Doc: "auth.router.ts:890-895, core config-require2fa-is-a-system-policy-term — under the policy POST /2fa/disable is " +
				"403 {\"error\":\"Cannot disable 2FA: required by system policy\",\"code\":\"2FA_REQUIRED\"}. Driven on a fresh " +
				"account enrolled at login, never on the declared realm account",
			Needs: []Capability{Cap2FARequired, Cap2FAEnrolOnLogin},
			Run: func(t *testing.T, e *Env) {
				fresh := e.registerFresh(t)
				c := e.NewClient()
				temp := c.POST(t, "/login", body{"email": fresh.Email, "password": fresh.Password}, BearerStrategy()).str(t, "tempToken")
				secret := c.POST(t, "/2fa/setup", body{}, Bearer(temp), BearerStrategy()).str(t, "secret")
				done := c.POST(t, "/2fa/verify-setup", body{"secret": secret, "token": totpNow(t, secret)}, Bearer(temp), BearerStrategy())
				done.mustStatus(t, 200)
				e.NewClient().POST(t, "/2fa/disable", body{}, Bearer(done.str(t, "accessToken"))).
					mustError(t, 403, "2FA_REQUIRED", "Cannot disable 2FA: required by system policy")
			},
		},
	)
}

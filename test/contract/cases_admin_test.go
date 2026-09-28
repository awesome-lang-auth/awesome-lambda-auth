package contract

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// The admin console, black-box: the reference's admin router
// (src/router/admin.router.ts), mounted by the host beside the auth router —
// `/admin` here, `AWESOME_AUTH_CONTRACT_ADMIN_PATH` to move it — and guarded
// by an access policy the operator chose.
//
// Two things make this surface unlike every other one in the suite.
//
// The suite cannot provision an administrator. It provisions ordinary accounts
// through POST /register and throws them away, but nothing a client can do
// turns one of those into an administrator: under is-admin-flag the flag is set
// by the console itself, under first-user the first account on a shared stack
// belongs to somebody else, and under rbac:<role> the role is assigned by an
// administrator. So the credential is the operator's to supply, exactly as the
// rate limiter's declaration is: AWESOME_AUTH_CONTRACT_ADMIN_EMAIL and
// AWESOME_AUTH_CONTRACT_ADMIN_PASSWORD name an account the console admits — the
// configured root user, or a user the operator promoted — and the cases that
// need one skip without them. The README says what to set and why.
//
// And it has no family client. The reference's admin.js is vendored by the
// core and served by the console itself, so the client this surface has to
// stay compatible with is that script — its login post, its ping, its user
// listing, its settings round trip — and those are what the cases below drive,
// with the same bodies it sends.
//
// Nothing here asserts a byte the reference does not send. The typed admin
// token, the unauthenticated-GET narrowing and the cookie's Secure derivation
// are upstream deviations, pinned in the core's own tests; what is pinned here
// is the wire the SPA sees.

const (
	// AdminPathEnv overrides the console's mount, the way PrefixEnv overrides
	// the auth router's. The reference mounts it at /admin (admin.router.ts:190,
	// the swagger default); so does this product (admin.basePath).
	AdminPathEnv = "AWESOME_AUTH_CONTRACT_ADMIN_PATH"

	// AdminEmailEnv and AdminPasswordEnv name an account the console admits.
	// Opt-in, and unset by default: the suite cannot mint one.
	AdminEmailEnv    = "AWESOME_AUTH_CONTRACT_ADMIN_EMAIL"
	AdminPasswordEnv = "AWESOME_AUTH_CONTRACT_ADMIN_PASSWORD"

	defaultAdminPath = "/admin"
)

// adminPath is the console's mount as an absolute path, for Env.URL's "!"
// form: the console is a sibling of the api prefix, not a child.
func adminPath() string {
	p := strings.TrimSpace(os.Getenv(AdminPathEnv))
	if p == "" {
		p = defaultAdminPath
	}
	return "!" + strings.TrimSuffix(p, "/")
}

// adminCredential is the operator's declared administrator, or nothing.
func adminCredential() (email, password string, ok bool) {
	email = strings.TrimSpace(os.Getenv(AdminEmailEnv))
	password = os.Getenv(AdminPasswordEnv)
	return email, password, email != "" && password != ""
}

// adminLogin logs the declared administrator in through the console's own
// route — as admin.js's doLogin does, a JSON post with credentials: 'include'
// and no CSRF header, because the admin router sits outside the auth router's
// CSRF chain — and returns a client holding the session cookie.
func adminLogin(t *testing.T, e *Env) *Client {
	t.Helper()
	email, password, ok := adminCredential()
	if !ok {
		t.Fatalf("adminLogin called without %s and %s; the case must need CapAdminCredential", AdminEmailEnv, AdminPasswordEnv)
	}
	c := e.NewClient()
	r := c.POST(t, adminPath()+"/login", body{"email": email, "password": password})
	if r.Status != 200 {
		t.Fatalf(`POST %s/login with the declared administrator answered %d %s

%s and %s are set, so the operator says this account is admitted. A 401 here is
"Invalid credentials": the root user's hash does not match, or the account is
not in the console's user store. The policy is not consulted at login — a user
it will refuse logs in and is answered 403 by the next request — so a 401 is
about the credential itself.`, adminPath()[1:], r.Status, r.snippet(), AdminEmailEnv, AdminPasswordEnv)
	}
	var m map[string]any
	if json.Unmarshal(r.Body, &m) != nil || m["success"] != true {
		t.Fatalf("the admin login answered 200 without {\"success\":true}: %s", r.where())
	}
	if len(r.SetCookie) == 0 {
		t.Fatalf("the admin login set no cookie; the SPA relies on the session cookie, not on the body\n  %s", r.where())
	}
	return c
}

func init() {
	register(
		Case{
			Name: "admin/ping-refuses-an-anonymous-caller",
			Doc: "reference src/router/admin.router.ts:274-332 — under a session policy, GET <admin>/api/ping with no credential and no " +
				"text/html Accept is 401 {\"error\":\"Unauthorized\"}: the admin envelope, not the auth router's {error,code} shape",
			Needs: []Capability{CapAdmin},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, adminPath()+"/api/ping")
				r.mustStatus(t, 401)
				m := r.obj(t)
				if m["error"] != "Unauthorized" {
					t.Errorf("body = %v, want {\"error\":\"Unauthorized\"}\n  %s", m, r.where())
				}
				if _, coded := m["code"]; coded {
					t.Errorf("the admin envelope carries a `code`; the admin router writes {error} and nothing else (admin.router.ts:329)\n  %s", r.where())
				}
				// A bogus bearer token is the same refusal, not a 403: the guard
				// reads no principal from a token it cannot verify.
				e.NewClient().GET(t, adminPath()+"/api/ping", Bearer("not.a.token")).mustStatus(t, 401)
			},
		},

		Case{
			Name: "admin/shell-serves-the-login-form-anonymously",
			Doc: "reference src/router/admin.router.ts:311-325, :406-496 — an unauthenticated GET <admin>/ that accepts text/html is 200 " +
				"with the HTML shell, window.__ADMIN_CONFIG__ injected and sessionBased true under a session policy, or 302 to " +
				"<loginPath>?redirect=… when the host configured one; the two static assets are public either way",
			Needs: []Capability{CapAdmin, CapAdminSession},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, adminPath()+"/", Header("Accept", "text/html"))
				r.mustStatusIn(t, 200, 302)
				if r.Status == 302 {
					// admin.loginPath: the console sends a browser to the
					// operator's login page with its own mount as the redirect
					// parameter (admin.router.ts:311-315). The suite cannot know
					// the configured path; it can know the shape.
					loc, err := url.Parse(r.Header.Get("Location"))
					if err != nil || !strings.HasPrefix(loc.Query().Get("redirect"), adminPath()[1:]) {
						t.Errorf("Location = %q, want <loginPath>?redirect=<the admin mount, URL-encoded>\n  %s", r.Header.Get("Location"), r.where())
					}
				} else {
					if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
						t.Errorf("Content-Type = %q, want text/html\n  %s", ct, r.where())
					}
					cfg, ok := adminShellConfig(string(r.Body))
					if !ok {
						t.Fatalf("the shell carries no window.__ADMIN_CONFIG__ block, or it is not JSON, so admin.js cannot find its mount or its features\n  %s", r.where())
					}
					if cfg.Base != adminPath()[1:] {
						t.Errorf("injected base = %q, want the mount %q — the SPA would call routes under the wrong path\n  %s", cfg.Base, adminPath()[1:], r.where())
					}
					if !cfg.SessionBased {
						t.Errorf("injected sessionBased = false under a session policy; the SPA would render the bearer-secret form\n  %s", r.where())
					}
					// The reference emits the host-supplied apiPrefix option
					// (`features.authApiPrefix || '/auth'`, admin.router.ts:445),
					// not the mount it observes, so a host that mounted the auth
					// router elsewhere and did not say so is a conforming
					// deployment whose value differs from e.Prefix. What is the
					// contract is that the SPA is told an absolute path.
					if !strings.HasPrefix(cfg.AuthAPIPrefix, "/") {
						t.Errorf("injected authApiPrefix = %q, want an absolute path — the console tells the SPA where the auth router lives\n  %s", cfg.AuthAPIPrefix, r.where())
					}
					if cfg.AuthAPIPrefix != e.Prefix {
						t.Logf("note: injected authApiPrefix = %q while the suite drives the auth router at %q; the reference emits the host's option, not the mount", cfg.AuthAPIPrefix, e.Prefix)
					}
				}
				// The two static assets the shell loads are public, as the
				// reference registers them (admin.router.ts:688-701).
				for _, asset := range []string{"/assets/admin.js", "/assets/admin.css"} {
					e.NewClient().GET(t, adminPath()+asset).mustStatus(t, 200)
				}
			},
		},

		Case{
			Name: "admin/login-sets-the-session-and-ping-reads-it",
			Doc: "reference src/router/admin.router.ts:543-611, :741-743 — POST <admin>/login {email,password} is 200 {\"success\":true} " +
				"with the session cookie, and GET <admin>/api/ping with that cookie is 200 {ok:true, features:{…}}",
			Needs: []Capability{CapAdmin, CapAdminSession, CapAdminCredential},
			Run: func(t *testing.T, e *Env) {
				c := adminLogin(t, e)
				r := c.GET(t, adminPath()+"/api/ping")
				r.mustStatus(t, 200)
				m := r.obj(t)
				if m["ok"] != true {
					t.Errorf("ping body = %v, want ok:true\n  %s", m, r.where())
				}
				features, ok := m["features"].(map[string]any)
				if !ok {
					t.Fatalf("ping carries no features object; the SPA reads it to decide which tabs to draw\n  %s", r.where())
				}
				// The eleven flags admin.js reads (admin.router.ts:645-656).
				// Their values are the deployment's; their presence is the
				// contract.
				for _, flag := range []string{"sessions", "roles", "tenants", "metadata", "twoFAPolicy", "control", "linkedAccounts", "apiKeys", "webhooks", "templates", "upload"} {
					if _, present := features[flag]; !present {
						t.Errorf("features lacks %q; admin.js reads it\n  %s", flag, r.where())
					}
				}
				// The wrong password is the same shape of refusal the SPA
				// shows: 401 {error}.
				email, _, _ := adminCredential()
				bad := e.NewClient().POST(t, adminPath()+"/login", body{"email": email, "password": "not-the-password"})
				bad.mustStatus(t, 401)
				if bad.obj(t)["error"] != "Invalid credentials" {
					t.Errorf("wrong-password body = %v, want {\"error\":\"Invalid credentials\"}\n  %s", bad.obj(t), bad.where())
				}
				// And logout clears it: the next ping is anonymous again.
				c.POST(t, adminPath()+"/logout", nil).mustStatus(t, 200)
				c.GET(t, adminPath()+"/api/ping").mustStatus(t, 401)
			},
		},

		Case{
			Name: "admin/users-listing-has-the-reference-shape",
			Doc: "reference src/router/admin.router.ts:748-790 — GET <admin>/api/users is 200 {users:[…], total:n} with the lister, " +
				"or 501 {error:'IUserStore.listUsers is not implemented', users:[], total:0} without one; never a bare array",
			Needs: []Capability{CapAdmin, CapAdminSession, CapAdminCredential},
			Run: func(t *testing.T, e *Env) {
				// A fresh account, so the listing has at least one row this run
				// can vouch for on the stack.
				acct := e.NewAccount(t)
				c := adminLogin(t, e)
				r := c.GET(t, adminPath()+"/api/users")
				r.mustStatusIn(t, 200, 501)
				m := r.obj(t)
				users, ok := m["users"].([]any)
				if !ok {
					t.Fatalf("users is %T, want an array in both branches\n  %s", m["users"], r.where())
				}
				total, ok := m["total"].(float64)
				if !ok {
					t.Fatalf("total is %T, want a number in both branches\n  %s", m["total"], r.where())
				}
				if r.Status == 501 {
					if len(users) != 0 || total != 0 || m["error"] != "IUserStore.listUsers is not implemented" {
						t.Errorf("the 501 branch must carry the reference's message, an empty users array and total 0: %v\n  %s", m, r.where())
					}
					return
				}
				if total < 1 {
					t.Errorf("total = %v after registering %s; an unswept table under-reports (run migrate backfill-users)\n  %s", total, acct.Email, r.where())
				}
				for _, u := range users {
					row, _ := u.(map[string]any)
					for _, key := range []string{"id", "email"} {
						if _, present := row[key]; !present {
							t.Errorf("a users row lacks %q: %v\n  %s", key, row, r.where())
						}
					}
					if _, leaked := row["passwordHash"]; leaked {
						t.Fatalf("a users row carries passwordHash\n  %s", r.where())
					}
				}
			},
		},

		Case{
			Name: "admin/settings-round-trip",
			Doc: "reference src/router/admin.router.ts:951-987 — GET <admin>/api/settings is the settings object unwrapped; PUT merges " +
				"a partial object and PATCH /api/settings/ui merges into the ui block, each answering 200 {\"success\":true}, and the " +
				"next GET reflects the change; 404 {error:'Settings store not configured'} on every settings route without a store",
			Needs: []Capability{CapAdmin, CapAdminSession, CapAdminCredential},
			Run: func(t *testing.T, e *Env) {
				c := adminLogin(t, e)
				r := c.GET(t, adminPath()+"/api/settings")
				r.mustStatusIn(t, 200, 404)
				if r.Status == 404 {
					if r.obj(t)["error"] != "Settings store not configured" {
						t.Errorf("404 body = %v, want the reference's 'Settings store not configured'\n  %s", r.obj(t), r.where())
					}
					t.Skip("this deployment wires no settings store (stores.enable.settings), which is a configuration and not a fault")
				}
				before := r.obj(t)

				// The write half has two rules and they pull in opposite
				// directions. It must be non-vacuous: a PUT that persisted
				// nothing and answered {"success":true} must fail here, which
				// means the value written has to differ from the value read.
				// And it must leave the stack exactly as it found it — not
				// only the same values but the same KEYS, because on this
				// product a key's presence carries meaning: the cold-start
				// seed fills only absent keys (runtime-settings-seed-only-
				// fills-absent-keys), so materialising require2FA: false where
				// the store held no such key would permanently disarm a later
				// `runtimeSettings.require2fa: true` in the document. So the
				// case round-trips a key the store already holds and restores
				// it, and when the store holds nothing restorable it skips the
				// write half rather than invent a key.
				settings := adminPath() + "/api/settings"
				switch {
				case before["require2FA"] != nil:
					// Present: flip it, see it, put it back. The key stays
					// present throughout, with its original value at the end.
					current, _ := before["require2FA"].(bool)
					t.Cleanup(func() {
						c.PUT(t, settings, body{"require2FA": current}).mustStatus(t, 200)
					})
					put := c.PUT(t, settings, body{"require2FA": !current})
					put.mustStatus(t, 200)
					if put.obj(t)["success"] != true {
						t.Errorf("PUT body = %v, want {\"success\":true}\n  %s", put.obj(t), put.where())
					}
					after := c.GET(t, settings).mustStatus(t, 200).obj(t)
					if got, _ := after["require2FA"].(bool); got != !current {
						t.Errorf("require2FA after PUT %v = %v; the merge persisted nothing\n  %s", !current, got, put.where())
					}
				case before["ui"] != nil:
					// A ui block is present: PATCH one member and restore the
					// whole block with a PUT, which replaces `ui` as a unit
					// (the store's merge is shallow, admin.router.ts:979-981)
					// — so a member the block did not hold is gone again at
					// the end, not left behind as an empty string.
					original, _ := before["ui"].(map[string]any)
					if original == nil {
						original = map[string]any{}
					}
					t.Cleanup(func() {
						c.PUT(t, settings, body{"ui": original}).mustStatus(t, 200)
					})
					probe := fmt.Sprintf("contract-probe-%d", time.Now().UnixNano())
					patch := c.PATCH(t, settings+"/ui", body{"siteName": probe})
					patch.mustStatus(t, 200)
					if patch.obj(t)["success"] != true {
						t.Errorf("PATCH body = %v, want {\"success\":true}\n  %s", patch.obj(t), patch.where())
					}
					after := c.GET(t, settings).mustStatus(t, 200).obj(t)
					ui, _ := after["ui"].(map[string]any)
					if ui["siteName"] != probe {
						t.Errorf("ui.siteName after the PATCH = %v, want %q; the merge persisted nothing\n  %s", ui["siteName"], probe, patch.where())
					}
					for k, v := range original {
						if k != "siteName" && fmt.Sprint(ui[k]) != fmt.Sprint(v) {
							t.Errorf("ui.%s after the PATCH = %v, want the untouched %v; the sub-object merge dropped a sibling\n  %s", k, ui[k], v, patch.where())
						}
					}
				default:
					t.Skipf("the settings store holds neither require2FA nor a ui block (%v); every write would create a key the seed reads as administrator-set, and the suite leaves the stack as it found it", before)
				}
			},
		},
	)
}

// PUT and PATCH are the two methods this file adds to the client: the settings
// routes are the only PUT and PATCH on any surface the suite covers.
func (c *Client) PUT(t *testing.T, path string, b body, opts ...reqOpt) *Resp {
	t.Helper()
	return c.do(t, http.MethodPut, path, b, opts)
}

func (c *Client) PATCH(t *testing.T, path string, b body, opts ...reqOpt) *Resp {
	t.Helper()
	return c.do(t, http.MethodPatch, path, b, opts)
}

// adminProbeWhy renders the probe's observation for the report.
func adminProbeWhy(r *Resp, verdict string) string {
	return fmt.Sprintf("%s answered %d — %s", r.Target, r.Status, verdict)
}

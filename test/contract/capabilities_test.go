package contract

// The capability registry: one contiguous region per capability, each holding
// the name cases gate on, the stage its probe belongs to, and the probe itself.
// harness_test.go enumerates none of them — the probe order, the names
// AWESOME_AUTH_CONTRACT_REQUIRE accepts and the report are all derived from what
// is registered here.
//
// Adding a capability is adding one region, here or in a file of its own, and
// touching nothing else. That is the point: every block after this one adds one,
// and before the registry existed each of them would have edited the same two
// hand-maintained lists and the same probe body.
//
// Two rules a new region has to respect, both of them properties the probes had
// when they were a single block and neither of them expressible in the type:
//
//   - Pick the stage, not the neighbours. Order within a stage is registration
//     order, which across files is file-name order, so a probe that depends on
//     another probe having run is a probe in the wrong stage.
//   - Say which client, and why. p.Anon and p.LoggedIn(t) are different
//     identities and the difference is observable: a route probed with the wrong
//     one can report a capability that is really an authorisation result. Every
//     probe below argues its choice, and a new one is expected to.

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

// TestCapabilityRegistryIsWellFormed is the one test in this package that runs
// without a deployment, and it checks the registry rather than the wire.
//
// It deliberately pins no list. Pinning the set of capabilities would put the
// conflict back that the registry exists to remove — every later block would
// edit it — so what is asserted here are the structural properties a
// declaration has to have for the pass to be sound, each of which is silent
// when broken:
//
//   - A name declared twice: the second probe's answer overwrites the first's,
//     so whichever is registered later decides, and which that is depends on
//     file names.
//   - More or less than one stageProvision declaration: the account the rest of
//     the pass runs on is provisioned exactly once, by the probe that is also
//     allowed to stand the suite down.
//   - A case needing a name nobody registered: an unprobed capability is the
//     zero capState, which is capOn, so the case runs against a deployment
//     nothing looked at — the exact failure the three-way capState exists to
//     prevent, reintroduced by a typo.
func TestCapabilityRegistryIsWellFormed(t *testing.T) {
	t.Parallel()

	known := map[Capability]Capability{} // name -> the declaration that owns it
	provisioners := []Capability{}
	for _, decl := range capabilityRegistry {
		if decl.Probe == nil {
			t.Errorf("capability %q declares no probe", decl.Name)
		}
		if decl.Stage == stageProvision {
			provisioners = append(provisioners, decl.Name)
		}
		for _, name := range decl.names() {
			if owner, dup := known[name]; dup {
				t.Errorf("capability %q is declared twice, by %q and by %q; the later registration would silently decide it",
					name, owner, decl.Name)
			}
			known[name] = decl.Name
		}
	}
	if len(provisioners) != 1 || provisioners[0] != CapRegister {
		t.Errorf("stageProvision holds %v, want exactly [%q]: it is the account the whole pass runs on", provisioners, CapRegister)
	}

	// Stage order, and nothing else, is what orderedCapabilities promises.
	ordered := orderedCapabilities()
	if len(ordered) != len(capabilityRegistry) {
		t.Fatalf("orderedCapabilities returned %d declarations, want all %d", len(ordered), len(capabilityRegistry))
	}
	for i := 1; i < len(ordered); i++ {
		if ordered[i-1].Stage > ordered[i].Stage {
			t.Fatalf("orderedCapabilities is not stage-sorted: %q (stage %d) precedes %q (stage %d)",
				ordered[i-1].Name, ordered[i-1].Stage, ordered[i].Name, ordered[i].Stage)
		}
	}
	if got := len(knownCapabilities()); got != len(known) {
		t.Errorf("knownCapabilities returned %d names for %d declared", got, len(known))
	}

	for _, c := range registry {
		for _, need := range c.Needs {
			if _, ok := known[need]; !ok {
				t.Errorf("case %q needs capability %q, which no declaration registers; an unprobed capability reads as \"on\"",
					c.Name, need)
			}
		}
	}
}

// ── csrf, and the Secure flag that rides on it ───────────────────────────────

// CapCSRF is the double-submit CSRF cookie the router auto-initialises.
const CapCSRF Capability = "csrf"

// CapCookieSecure is whether this deployment marks its cookies Secure. It is not
// probed on its own: it is read off the same cookie CapCSRF observes, because
// that is the only cookie a client can obtain without holding a session.
const CapCookieSecure Capability = "secure-cookies"

func init() {
	registerCapability(capabilityDecl{
		Name:    CapCSRF,
		Settles: []Capability{CapCookieSecure},
		// The cookie is distributed solely by the router's auto-init middleware
		// (§0.6), so any request through the router reveals whether the feature
		// is on — but only a request made before anything else has happened
		// proves that the *middleware* set it rather than some token-issuing
		// response, which is why this is stageAnonymous and uses p.Anon while
		// that client is still credential-free.
		Stage: stageAnonymous,
		Probe: func(t *testing.T, p *probeRun) {
			// An unauthenticated GET /me is the cheapest request through the
			// router.
			//
			// This is the one capability with no status to classify — a router
			// with csrf.enabled off and a router that stopped setting the cookie
			// look the same from outside — so absence here is exactly what
			// RequireEnv is for.
			r := p.Anon.GET(t, "/me")
			c := r.cookie("csrf-token")
			if c == nil {
				p.Set(CapCSRF, capability{state: capAbsent, why: "no csrf-token cookie is auto-initialised, so config.csrf.enabled is off"})
				p.Set(CapCookieSecure, capability{state: capAbsent, why: "no cookie observed during the probe"})
				return
			}
			p.Set(CapCSRF, capability{state: capOn, why: fmt.Sprintf("auto-init cookie %q observed", c.Name)})
			secure := capAbsent
			if c.Secure {
				secure = capOn
			}
			p.Set(CapCookieSecure, capability{state: secure, why: fmt.Sprintf("csrf cookie Secure=%v", c.Secure)})
		},
	})
}

// ── register, which gates the whole suite ────────────────────────────────────

// CapRegister is POST <prefix>/register. It is not a capability like the others:
// the suite provisions itself through it, so its absence stands every case down
// rather than skipping the ones that name it.
const CapRegister Capability = "register"

func init() {
	registerCapability(capabilityDecl{
		Name: CapRegister,
		// The whole of stageProvision, and the reason the stage exists: p.Anon
		// carries this registration's cookies from here on, and p.LoggedIn is
		// built from the account it stores.
		Stage: stageProvision,
		Probe: func(t *testing.T, p *probeRun) {
			// Registration, without which the suite cannot provision anything:
			// it cannot seed a store it is not allowed to reach.
			//
			// Only the reference's documented absence — Express's 404
			// fall-through for a route mounted only when the host app passes
			// onRegister (§3.7, auth.router.ts:713) — is a reason to stand down.
			// A 500 here used to skip the entire suite and exit 0, which meant a
			// deployment answering 500 to every request produced the same green
			// `ok` as a healthy one.
			e := p.Env
			p.account = randomAccount()
			reg := p.Anon.POST(t, "/register", body{"email": p.account.Email, "password": p.account.Password})
			switch {
			case reg.Status == 200 || reg.Status == 201:
				p.Set(CapRegister, capability{state: capOn, why: fmt.Sprintf("POST %s/register answered %d", e.Prefix, reg.Status)})
			case reg.Status == 404 && !p.Req.wants(CapRegister):
				p.Set(CapRegister, capability{state: capAbsent, why: fmt.Sprintf("POST %s/register answered 404 — the route is not mounted", e.Prefix)})
				announce("SKIPPED: %s does not mount POST %s/register, so the suite could not provision an account.\n"+
					"None of the %d contract cases ran. Set %s=register to make this a failure.",
					e.BaseURL, e.Prefix, len(registry), RequireEnv)
				t.Skipf(`this deployment does not mount registration: POST %s/register answered 404.

The suite is black-box and self-provisioning — it registers the accounts it
needs because it cannot seed a store it cannot reach — so it cannot run against
a stack with the route unmounted (the reference mounts it only when the host app
passes onRegister; wire-contract.md §3.7).`, e.Prefix)
			default:
				t.Fatalf(`probe: POST %s/register answered %d %s

That is a broken deployment, not an unconfigured one: the documented absence of
this route is Express's 404 fall-through (§3.7), and nothing else. The suite
refuses to treat a fault as a reason to stand down — this used to be a skip, and
a stack answering 500 to every route exited 0.`, e.Prefix, reg.Status, reg.snippet())
			}
		},
	})
}

// ── the store-gated probes, read with the account's own session ──────────────

// CapSessions is the session store behind GET <prefix>/sessions.
const CapSessions Capability = "sessions"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapSessions,
		Stage: stageProbed,
		// The logged-in client: the route is session-gated, so an anonymous
		// probe would read 401 and classify a configured store as broken.
		Probe: func(t *testing.T, p *probeRun) {
			p.Set(CapSessions, classify(p.LoggedIn(t).GET(t, "/sessions")))
		},
	})
}

// CapLinkedAccounts is the linked-account store behind GET
// <prefix>/linked-accounts.
const CapLinkedAccounts Capability = "linked-accounts"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapLinkedAccounts,
		Stage: stageProbed,
		// Session-gated, like CapSessions. It gates no case today, which is
		// exactly why the pass reports a fault on it: see the loop in probe.
		Probe: func(t *testing.T, p *probeRun) {
			p.Set(CapLinkedAccounts, classify(p.LoggedIn(t).GET(t, "/linked-accounts")))
		},
	})
}

// CapTOTP is the TOTP store behind POST <prefix>/2fa/setup.
const CapTOTP Capability = "totp"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapTOTP,
		Stage: stageProbed,
		// Session-gated and unsafe, so it carries the CSRF header the
		// double-submit middleware wants; without CSRF() a deployment with the
		// feature on would answer 403 and read as broken.
		Probe: func(t *testing.T, p *probeRun) {
			p.Set(CapTOTP, classify(p.LoggedIn(t).POST(t, "/2fa/setup", nil, CSRF())))
		},
	})
}

// ── the two probed without a session, on purpose ─────────────────────────────

// CapOAuthGoogle is a configured Google provider behind GET
// <prefix>/oauth/google.
const CapOAuthGoogle Capability = "oauth-google"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapOAuthGoogle,
		Stage: stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			// The OAuth entry point reads no credential (§4: "Auth gate:
			// none"), so the anonymous client is the honest probe for it.
			p.Set(CapOAuthGoogle, classifyOAuth(p.Anon.GET(t, "/oauth/google")))
		},
	})
}

// classifyOAuth reads the probe answer for GET <prefix>/oauth/google, whose two
// documented shapes are not the two classify knows about.
//
// "On" is a 302 to the provider carrying a state — the route answers a redirect,
// never a 200 — and the documented absence is the reference's own stub for a
// strategy the host app never passed: 404 {"error":"Google OAuth not
// configured"} (auth.router.ts:1361), which is a JSON body rather than an
// unmounted route's fall-through. Anything else is a fault: a 500 from a
// half-wired provider must not read as "nobody configured Google".
func classifyOAuth(r *Resp) capability {
	switch r.Status {
	case 302:
		loc := r.Header.Get("Location")
		if loc == "" {
			return capability{state: capBroken, why: fmt.Sprintf("%s answered 302 with no Location", r.Target)}
		}
		u, err := url.Parse(loc)
		if err != nil || u.Query().Get("state") == "" {
			return capability{state: capBroken, why: fmt.Sprintf("%s answered 302 to %q, which carries no state parameter", r.Target, loc)}
		}
		return capability{state: capOn, why: fmt.Sprintf("%s answered 302 to %s with a state", r.Target, u.Host)}
	case 404:
		var m map[string]any
		if json.Unmarshal(r.Body, &m) == nil && m["error"] == "Google OAuth not configured" {
			return capability{state: capAbsent, why: fmt.Sprintf("%s answered the reference's 404 stub — no Google provider is configured", r.Target)}
		}
	}
	return capability{state: capBroken, why: fmt.Sprintf("%s answered %d %s, which is neither a provider redirect nor the documented 404 stub", r.Target, r.Status, r.snippet())}
}

// CapIDP is identity-provider mode: the deployment publishes a JWKS document
// and mounts the OIDC endpoints. Probed on the JWKS route, which is the one
// endpoint of the set that is public by construction and answers without any
// client being registered — so the probe cannot be confused by an IdP that is
// on but has no clients.
const CapIDP Capability = "idp"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapIDP,
		Stage: stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			// Probed without the account's session on purpose: the JWKS
			// document is public by construction — a relying party fetches it
			// with no credential of any kind — so probing it with the logged-in
			// client would hide a deployment that had put it behind a session.
			p.Set(CapIDP, classify(p.Anon.GET(t, "/.well-known/jwks.json")))
		},
	})
}

// ── the documentation surface, probed without a session for the same reason ──

// CapDocs is the pair of documentation routes: GET <prefix>/openapi.json, the
// generated OpenAPI document, and GET <prefix>/docs, the Swagger UI page that
// reads it. A deployment either mounts both or mounts neither
// (auth.router.ts:1651-1677, registered under one option; docs.swagger here).
const CapDocs Capability = "docs"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapDocs,
		Stage: stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			// Anonymous, and on the document rather than the page.
			//
			// Anonymous because neither route carries a guard of its own where
			// the reference registers them — no auth middleware, no session,
			// nothing to present a credential to — so both answer with no
			// credential of any kind. Probing with p.LoggedIn would hide a
			// deployment that had put them behind a session, which is exactly
			// the difference this pass exists to see.
			//
			// On the document because that is the machine-readable half, the
			// one a client generator or a gateway actually reads, and because
			// one option mounts both: a deployment answering one and not the
			// other is a fault and not a configuration, so the page's own case
			// fails on it rather than skipping. If upstream ever splits the
			// switch, this becomes two declarations.
			p.Set(CapDocs, classify(p.Anon.GET(t, "/openapi.json")))
		},
	})
}

// ── the hosted UI, probed on the document its pages boot from ────────────────

// CapUI is the built-in UI: the whole of the reference's ui router, mounted at
// <prefix>/ui — the config document, the server-rendered pages, the vendored
// assets. A deployment either mounts all of it or none of it, because one flag
// registers one handler for the subtree (ui.enabled here, config.ui.enabled and
// auth.router.ts:1639-1648 there).
const CapUI Capability = "ui"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapUI,
		Stage: stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			// Anonymous, and on the config document rather than on a page.
			//
			// Anonymous because this is the first request a login page makes,
			// before any session exists — the route asks for no credential and a
			// probe holding one would hide a deployment that had put the UI
			// behind a session.
			//
			// On the document because it is the one response under this mount
			// whose *shape* says the UI is really there. Every page path falls
			// through to the SSR catch-all, so a deployment serving a stray
			// index.html would answer 200 to a page probe while being no UI at
			// all; and the document is the only part of the surface a headless
			// deployment still serves, so probing a page would report a
			// legitimate SPA posture as an absent feature.
			p.Set(CapUI, classifyUI(p.Anon.GET(t, "/ui/config")))
		},
	})
}

// ── the admin console, probed on its health route without a session ─────────

// CapAdmin is the admin console: the reference's admin router, mounted beside
// the api prefix — at /admin by default, AWESOME_AUTH_CONTRACT_ADMIN_PATH to
// move it — and guarded by an access policy. It is "on" only when it is both
// mounted and guarded: a console that admits an anonymous caller is reported
// as a fault, not as a capability.
const CapAdmin Capability = "admin"

// CapAdminCredential is whether the operator declared an account the console
// admits, through AWESOME_AUTH_CONTRACT_ADMIN_EMAIL and _PASSWORD. It is
// declared rather than probed, like the rate limiter's budget, because the
// suite cannot mint an administrator: the console's own routes are what
// promote one, and the first account on a shared stack is somebody else's.
const CapAdminCredential Capability = "admin-credential"

// CapAdminSession is whether the console authenticates through a session — an
// access policy, with POST <admin>/login and /logout mounted and the shell
// rendering the email-and-password form — rather than through the legacy
// bearer secret, under which the shell is served with sessionBased false, no
// login route exists and the SPA holds the secret in sessionStorage. Both are
// conforming deployments (admin.router.ts:516-537) and both answer 401 to the
// anonymous ping, so the ping cannot tell them apart; the shell can, and this
// is read off the anonymous shell's injected config. Every case that logs in,
// or asserts the login form, needs it.
const CapAdminSession Capability = "admin-session"

// adminShellConfig parses the window.__ADMIN_CONFIG__ block out of the shell
// the console serves an anonymous browser (admin.router.ts:406-496). The
// three members are the ones the suite reads; ok is false when the block is
// missing or is not JSON.
func adminShellConfig(page string) (cfg struct {
	Base          string `json:"base"`
	SessionBased  bool   `json:"sessionBased"`
	AuthAPIPrefix string `json:"authApiPrefix"`
}, ok bool) {
	const marker = "window.__ADMIN_CONFIG__ = "
	i := strings.Index(page, marker)
	if i < 0 {
		return cfg, false
	}
	dec := json.NewDecoder(strings.NewReader(page[i+len(marker):]))
	if err := dec.Decode(&cfg); err != nil {
		return cfg, false
	}
	return cfg, true
}

func init() {
	registerCapability(capabilityDecl{
		Name:    CapAdmin,
		Settles: []Capability{CapAdminCredential, CapAdminSession},
		Stage:   stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			// Anonymous, on GET <admin>/api/ping, on purpose. The route is
			// the SPA's own health and auth check (admin.router.ts:741) and it
			// sits behind the guard, so the three answers it can give are the
			// three states this pass distinguishes: 401 is a mounted, guarded
			// console; 404 is no console — admin.enabled off, or the core
			// refusing to mount one with no access decision; and a 200 to a
			// caller holding nothing is the `open` policy, the reference's
			// default and the one configuration an auth product must not
			// report as healthy. A session would hide the third.
			r := p.Anon.GET(t, adminPath()+"/api/ping")
			switch r.Status {
			case 401:
				p.Set(CapAdmin, capability{state: capOn, why: adminProbeWhy(r, "the console is mounted and guarded")})
			case 404:
				p.Set(CapAdmin, capability{state: capAbsent, why: adminProbeWhy(r, "no console is mounted (admin.enabled is off)")})
			case 200:
				// Loud, and a fault: the suite will not call an unguarded
				// console a capability, because every case below would then
				// pass against a deployment that admits the world.
				p.Set(CapAdmin, capability{state: capBroken, why: adminProbeWhy(r,
					"THE CONSOLE IS OPEN: an anonymous caller was admitted, so admin.accessPolicy is `open`. "+
						"That is the reference's default and is only for a stack behind a network boundary; this suite refuses to treat it as healthy")})
			default:
				p.Set(CapAdmin, capability{state: capBroken, why: adminProbeWhy(r, "neither the guard's 401, the unmounted 404 nor the open console's 200")})
			}

			// Session or legacy secret, read off the anonymous shell. Only a
			// mounted, guarded console has a shell worth reading; the other
			// three states settle this one by implication.
			switch p.Env.Caps[CapAdmin].state {
			case capOn:
				shell := p.Anon.GET(t, adminPath()+"/", Header("Accept", "text/html"))
				switch {
				case shell.Status == 200:
					cfg, ok := adminShellConfig(string(shell.Body))
					switch {
					case !ok:
						p.Set(CapAdminSession, capability{state: capBroken, why: adminProbeWhy(shell, "the shell carries no window.__ADMIN_CONFIG__ block, so admin.js could not find its mount")})
					case cfg.SessionBased:
						p.Set(CapAdminSession, capability{state: capOn, why: adminProbeWhy(shell, "the shell injects sessionBased true: an access policy guards the console and POST <admin>/login is mounted")})
					default:
						p.Set(CapAdminSession, capability{state: capAbsent, why: adminProbeWhy(shell,
							"the shell injects sessionBased false: the legacy bootstrap secret is the guard, no login route exists, and the SPA holds the secret in sessionStorage")})
					}
				case shell.Status == 302 && strings.Contains(shell.Header.Get("Location"), "redirect="):
					// admin.loginPath: the session guard sends an anonymous
					// browser to a login page of the operator's choosing
					// (admin.router.ts:311-315) instead of rendering the form.
					// The redirect exists only under a session policy, so it
					// settles this on.
					p.Set(CapAdminSession, capability{state: capOn, why: adminProbeWhy(shell,
						"an anonymous browser is redirected to the configured loginPath ("+shell.Header.Get("Location")+"), which only the session guard does")})
				default:
					p.Set(CapAdminSession, capability{state: capBroken, why: adminProbeWhy(shell, "neither the shell (200 text/html) nor a loginPath redirect (302 with ?redirect=)")})
				}
			case capAbsent:
				p.Set(CapAdminSession, capability{state: capAbsent, why: "no console is mounted"})
			default:
				p.Set(CapAdminSession, capability{state: capBroken, why: "the console itself is broken; see admin"})
			}

			// The half-declared shape has to be tested first: `declared` is
			// already false for it, so an `!declared` arm above it would report
			// a misconfigured run as a deployment without an administrator and
			// silently skip every credentialed case.
			email, password, declared := adminCredential()
			switch {
			case (email == "") != (password == ""):
				p.Set(CapAdminCredential, capability{state: capBroken, why: fmt.Sprintf(
					"only one of %s and %s is set; a half-declared credential is a misconfigured run, not a deployment without one", AdminEmailEnv, AdminPasswordEnv)})
			case !declared:
				p.Set(CapAdminCredential, capability{state: capAbsent, why: fmt.Sprintf(
					"%s and %s are unset, so no administrator is declared; the suite cannot mint one", AdminEmailEnv, AdminPasswordEnv)})
			default:
				p.Set(CapAdminCredential, capability{state: capOn, why: fmt.Sprintf("%s declares %s", AdminEmailEnv, email)})
			}
		},
	})
}

// classifyUI reads the probe answer for GET <prefix>/ui/config.
//
// It is classify with two changes, both of which exist because this route is
// not gated on a store.
//
// A 404 is the UI being switched off, not a store being unwired: with
// ui.enabled false the adapter registers nothing under the mount, and the
// router answers whatever it answers for an unknown path. classify's own
// message would tell an operator to go looking for a store.
//
// And a 200 has to be JSON. The config route lives *inside* the UI handler
// rather than beside it (ui.router.ts:165), and the layer behind it is an SSR
// catch-all that renders the login page for anything it does not recognise — so
// a deployment whose config route had stopped answering would serve HTML here
// with a perfectly good 200, and every case below would then fail on the
// document's contents instead of the probe reporting one fault once.
func classifyUI(r *Resp) capability {
	switch {
	case r.Status == 404:
		return capability{state: capAbsent, why: fmt.Sprintf("%s answered 404 — ui.enabled is off, so no UI is mounted at all", r.Target)}
	case r.Status == 200 && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json"):
		return capability{state: capBroken, why: fmt.Sprintf(
			"%s answered 200 %s, which is not the config document — the SSR catch-all is answering in its place",
			r.Target, r.Header.Get("Content-Type"))}
	}
	return classify(r)
}

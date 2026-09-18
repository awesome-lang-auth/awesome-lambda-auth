// Package contract is the black-box wire-contract suite for awesome-lambda-auth.
//
// It talks HTTP to a running stack and nothing else: no import of the auth core,
// no import of this repository's internals, no database handle, no AWS call. The
// correctness claim it exists to check is "the family's shipped clients work
// against this deployment with only a base-URL change", and a claim about a
// deployment can only be checked against a deployment.
//
// Everything lives in _test.go files on purpose. Nothing here is compiled into
// the deployable, and nothing here can be imported by it.
//
// Point it at a stack with AWESOME_AUTH_CONTRACT_BASE_URL; see README.md.
package contract

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
)

const (
	// BaseURLEnv names the stack under test, scheme and host, no trailing
	// slash: https://example.execute-api.eu-west-1.amazonaws.com, or
	// http://localhost:3000 for the reference Express app. Unset means "no
	// deployment to talk to", which is a skip and not a failure — a plain
	// checkout must stay green under `go test ./...`.
	BaseURLEnv = "AWESOME_AUTH_CONTRACT_BASE_URL"

	// PrefixEnv overrides the router mount point. The reference calls it
	// apiPrefix and defaults it to /auth (wire-contract.md §1, auth.router.ts
	// :253-255); so does this suite.
	PrefixEnv = "AWESOME_AUTH_CONTRACT_API_PREFIX"

	// RequireEnv lists the capabilities this deployment claims to offer, comma
	// separated, or the word "all". A listed capability that is missing is a
	// failure instead of a skip.
	//
	// It exists because "absent" is unfalsifiable from outside: a store the
	// operator never wired and a store that regressed into answering
	// NOT_IMPLEMENTED look identical on the wire, and the skip that is correct
	// for the first is a silent green run for the second. Nobody but the
	// operator knows which deployment they pointed the suite at, so the
	// operator says. Set it for a stack that is supposed to be complete; leave
	// it unset for the reference demo, which really does run without CSRF.
	RequireEnv = "AWESOME_AUTH_CONTRACT_REQUIRE"

	// ToolsPathEnv overrides the tools router's mount point, which is a
	// sibling of the api prefix and not a path under it: the reference's
	// createToolsRouter is a second router the host mounts wherever it likes
	// (tools.router.ts:114) and its own swaggerBasePath defaults to '/tools'
	// (:127), which is where this port mounts it too (tools.basePath here).
	// The Angular demo mounts it at <apiPrefix>/tools, so a deployment that
	// followed it sets this to that.
	ToolsPathEnv = "AWESOME_AUTH_CONTRACT_TOOLS_PATH"

	defaultPrefix    = "/auth"
	defaultToolsPath = "/tools"
)

// Capability is one thing a deployment either offers or does not. It is probed,
// never assumed: a route gated on a store the operator did not configure is a
// deployment difference, not a contract break, and a suite that fails on it is
// a broken suite.
//
// The capabilities themselves are not listed here. Each one declares its own
// name, its stage and its probe in a single contiguous region of
// capabilities_test.go — see capabilityDecl — and everything this file needs
// about the set (the probe order, the names AWESOME_AUTH_CONTRACT_REQUIRE
// accepts, the report) is derived from that registry rather than repeated.
type Capability string

// capState is the three-way answer a probe can get, and the distinction the
// suite turns on. "Off" is not one state but two, and collapsing them is how a
// contract suite goes green against a broken deployment: a store the operator
// did not wire is a deployment difference and a legitimate skip, while a route
// that answers 500 — or 403, or a 501 without the documented code — is a
// deployment that is broken, and a broken deployment must never be able to
// switch a case off.
type capState int

const (
	capOn     capState = iota // the feature answered
	capAbsent                 // the deployment declared, in the documented way, that it has no such store
	capBroken                 // neither: this is a fault, not a configuration
)

func (s capState) String() string {
	switch s {
	case capOn:
		return "on"
	case capAbsent:
		return "absent"
	default:
		return "BROKEN"
	}
}

type capability struct {
	state capState
	why   string // what was observed
}

// classify reads one probe answer. 200 is the feature. The two documented ways
// for a deployment to say "no store is wired" are the reference's Express 404
// fall-through for an unmounted route (§4, auth.router.ts:1456 — the route is
// simply not registered) and this port's 5xx with code NOT_IMPLEMENTED. There
// is no third way, so everything else is capBroken.
func classify(r *Resp) capability {
	switch {
	case r.Status == 200:
		return capability{state: capOn, why: fmt.Sprintf("%s answered 200", r.Target)}
	case r.Status == 404:
		return capability{state: capAbsent, why: fmt.Sprintf("%s answered 404 — the route is not mounted, so no store is wired", r.Target)}
	case r.Status >= 500:
		var m map[string]any
		if json.Unmarshal(r.Body, &m) == nil && m["code"] == "NOT_IMPLEMENTED" {
			return capability{state: capAbsent, why: fmt.Sprintf("%s answered %d NOT_IMPLEMENTED — the store is switched off", r.Target, r.Status)}
		}
	}
	return capability{state: capBroken, why: fmt.Sprintf("%s answered %d %s, which is neither the feature nor a declared absence", r.Target, r.Status, r.snippet())}
}

// probeStage orders the registry. A probe cannot choose its neighbours, only the
// point in the pass it belongs to, and there are exactly three such points
// because there are exactly two things a probe can need that do not exist yet
// when the pass starts: a provisioned account, and a session on it.
//
// Within one stage the order is the registration order, and it is deliberately
// not meaningful: two probes in the same stage must not depend on each other,
// because a later block adds its declaration in its own file and Go runs the
// init functions of a package in file-name order. Anything that does care —
// the account everything else is provisioned from, the login that follows it —
// is a stage boundary or a lazily-resolved accessor on probeRun, not a
// neighbour.
type probeStage int

const (
	// stageAnonymous runs before anything has been registered. It is the only
	// point at which the shared client is genuinely unauthenticated, which is
	// what the CSRF auto-init probe reads.
	stageAnonymous probeStage = iota

	// stageProvision is the account the rest of the pass is run on. Exactly one
	// declaration belongs here — CapRegister — and it is the one that may stand
	// the whole suite down.
	stageProvision

	// stageProbed is everything that needs the account: directly, through
	// probeRun.LoggedIn, or indirectly by being a route whose answer is only
	// worth reading once the deployment has been shown to work at all.
	stageProbed
)

// capabilityDecl is one capability's whole declaration: the name cases gate on,
// the point in the pass its probe belongs to, and the probe itself. Adding a
// capability is adding one of these, in its own contiguous region or its own
// file; nothing in this file enumerates them.
//
// Settles exists for the one probe that answers about more than one capability:
// a single response can be evidence about two things — the CSRF cookie is also
// the only place the Secure flag can be observed — and splitting that into two
// probes would mean two requests and two chances for them to disagree.
type capabilityDecl struct {
	// Name is the capability this declaration owns, and the name
	// AWESOME_AUTH_CONTRACT_REQUIRE accepts for it.
	Name Capability

	// Settles names the further capabilities this declaration's probe decides
	// out of the same observation. They are registered names like Name: a case
	// may need one, and RequireEnv may name one.
	Settles []Capability

	// Stage is where in the pass the probe runs. See probeStage.
	Stage probeStage

	// Probe records its answers with probeRun.Set, one per name this
	// declaration claims, and is checked afterwards for having recorded exactly
	// those. It runs on the suite's own *testing.T, never a subtest, so a probe
	// that decides the whole suite cannot run — CapRegister's — can still
	// t.Skipf or t.Fatalf out of the pass.
	Probe func(t *testing.T, p *probeRun)
}

// names is everything this declaration is responsible for recording.
func (d capabilityDecl) names() []Capability {
	return append([]Capability{d.Name}, d.Settles...)
}

var capabilityRegistry []capabilityDecl

// registerCapability is what a capability's declaration calls from its init.
func registerCapability(decls ...capabilityDecl) {
	capabilityRegistry = append(capabilityRegistry, decls...)
}

// orderedCapabilities is the registry in probe order: by stage, and within a
// stage in registration order (sort.SliceStable, so the registration order is
// kept rather than replaced by an arbitrary one).
func orderedCapabilities() []capabilityDecl {
	out := append([]capabilityDecl(nil), capabilityRegistry...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Stage < out[j].Stage })
	return out
}

// knownCapabilities is every registered name, in probe order. It is what
// RequireEnv is validated against and what its error message lists, so a
// capability cannot be probed without being nameable, or nameable without being
// probed — which is exactly the drift two hand-maintained lists used to allow.
func knownCapabilities() []Capability {
	var out []Capability
	for _, decl := range orderedCapabilities() {
		out = append(out, decl.names()...)
	}
	return out
}

// probeRun is the state one probe pass shares. Everything a probe may need is
// here rather than in a closure, so that a declaration is a value in a slice and
// not a line in a function.
type probeRun struct {
	// Env is the deployment under test. Probes read Prefix and BaseURL from it
	// for their diagnostics; they record through Set, never into Env.Caps.
	Env *Env

	// Req is what the operator claimed. Only CapRegister's probe reads it: it is
	// the one probe whose absence branch is a skip rather than a recorded state,
	// so it has to know whether the operator forbade that skip.
	Req required

	// Anon is the client every probe outside stageProbed uses, and the one the
	// two deliberately-credential-free probes keep using afterwards. It is NOT
	// re-created between stages: it registers the account in stageProvision and
	// therefore carries that registration's cookies from then on (the core's
	// register-issues-a-session deviation). Probes that want the account's
	// session use LoggedIn, which is a separate identity with its own jar.
	Anon *Client

	// account is what CapRegister's probe provisioned, and LoggedIn's
	// credentials.
	account Account

	user *Client

	// settled records what the running declaration claimed, so the pass can hold
	// each one to the names it declared.
	settled []Capability
}

// Set records one probe's answer. It is the only way into Env.Caps, which is
// what lets the pass check a declaration against what it said it would settle.
func (p *probeRun) Set(c Capability, answer capability) {
	p.Env.Caps[c] = answer
	p.settled = append(p.settled, c)
}

// LoggedIn is a client holding a session on the provisioned account, created on
// the first probe that asks for one and shared by the rest.
//
// It is lazy rather than a stage of its own because the login is not an
// observation: nothing about it is recorded, and a deployment that cannot log a
// freshly registered account in is broken in a way no capability can express, so
// it is a t.Fatalf here exactly as it was when this ran inline.
func (p *probeRun) LoggedIn(t *testing.T) *Client {
	t.Helper()
	if p.user != nil {
		return p.user
	}
	cli := p.Env.NewClient()
	login := cli.POST(t, "/login", body{"email": p.account.Email, "password": p.account.Password})
	if login.Status != 200 {
		t.Fatalf("probe: cannot log the freshly registered account in: POST %s/login -> %d %s",
			p.Env.Prefix, login.Status, login.snippet())
	}
	p.user = cli
	return cli
}

// Case is one assertion about the wire. Adding a route to the covered surface is
// adding a Case in a cases_*.go file; the harness never has to change.
type Case struct {
	// Name is the subtest name. Slash-separated, area first, so `go test -run`
	// can select a whole area.
	Name string

	// Doc cites the clause of docs/spec/wire-contract.md this case pins. It is
	// logged before the case runs, so a failure report says which clause broke
	// without anyone opening the spec.
	Doc string

	// Needs lists the deployment capabilities the case requires. A case whose
	// needs are not met is skipped with the reason the probe recorded.
	Needs []Capability

	Run func(t *testing.T, e *Env)
}

var registry []Case

// register is what a cases_*.go file calls from its init.
func register(cs ...Case) { registry = append(registry, cs...) }

// Env is the probed deployment: where it is, and what it turned out to offer.
type Env struct {
	BaseURL string
	Prefix  string
	// ToolsPath is where the tools router is mounted, beside Prefix rather
	// than under it. See ToolsPathEnv.
	ToolsPath string
	Caps      map[Capability]capability
}

// URL builds an absolute URL for a path relative to the router mount point.
// A path starting with "!" is taken as absolute (outside the prefix).
func (e *Env) URL(path string) string {
	if strings.HasPrefix(path, "!") {
		return e.BaseURL + path[1:]
	}
	return e.BaseURL + e.Prefix + path
}

// tools spells a path under the tools mount in the form the client takes: an
// absolute path, because the mount is a sibling of the prefix and URL would
// otherwise put it underneath.
func (e *Env) tools(path string) string {
	return "!" + e.ToolsPath + path
}

func (e *Env) can(c Capability) bool { return e.Caps[c].state == capOn }

// required is the set named by RequireEnv. `all` means every capability the
// probe knows about.
type required struct {
	all  bool
	set  map[Capability]bool
	spec string
}

func readRequired(t *testing.T) required {
	raw := strings.TrimSpace(os.Getenv(RequireEnv))
	req := required{set: map[Capability]bool{}, spec: raw}
	if raw == "" {
		return req
	}
	// Both the accepted set and the message that lists it come from the
	// registry. They used to be two hand-written lists beside a third one in the
	// probe, and a capability added to one of the three was accepted, probed and
	// unnameable in whichever combination the author happened to miss.
	names := knownCapabilities()
	known := make(map[Capability]bool, len(names))
	spelled := make([]string, 0, len(names)+1)
	for _, c := range names {
		known[c] = true
		spelled = append(spelled, string(c))
	}
	spelled = append(spelled, "all")

	for _, f := range strings.Split(raw, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if f == "all" {
			req.all = true
			continue
		}
		if !known[Capability(f)] {
			t.Fatalf("%s names an unknown capability %q; known: %s",
				RequireEnv, f, strings.Join(spelled, ", "))
		}
		req.set[Capability(f)] = true
	}
	return req
}

func (r required) wants(c Capability) bool { return r.all || r.set[c] }

// TestContract is the whole suite: one subtest per registered case.
func TestContract(t *testing.T) {
	base := strings.TrimSpace(os.Getenv(BaseURLEnv))
	if base == "" {
		// A caller who named the capabilities to verify has told us they meant
		// to run this against something. Skipping that quietly is the one shape
		// of "green forever" the exit code can still catch: a CI job whose
		// base URL arrived empty keeps its %s and goes red.
		if spec := strings.TrimSpace(os.Getenv(RequireEnv)); spec != "" {
			t.Fatalf(`%s=%q asks this suite to verify a deployment offers those capabilities, and %s is empty.

There is nothing to verify them against. This is a misconfigured run, not an
offline one — skipping it would report success for checks that never happened.`,
				RequireEnv, spec, BaseURLEnv)
		}
		announce("SKIPPED: %s is not set, so the wire contract was checked against nothing.\n"+
			"Nothing below this line was executed. See test/contract/README.md.", BaseURLEnv)
		t.Skipf(`%s is not set, so there is no deployment to check the wire contract against.

Set it to the origin of a running stack and re-run, for example:

    %s=https://<api-id>.execute-api.<region>.amazonaws.com ./scripts/toolchain.sh go test ./test/contract/...
    %s=http://localhost:3000 go test ./test/contract/...        # the reference Express app

Override the router mount point with %s (default %q). See test/contract/README.md.`,
			BaseURLEnv, BaseURLEnv, BaseURLEnv, PrefixEnv, defaultPrefix)
	}

	prefix := strings.TrimSpace(os.Getenv(PrefixEnv))
	if prefix == "" {
		prefix = defaultPrefix
	}
	toolsPath := strings.TrimSpace(os.Getenv(ToolsPathEnv))
	if toolsPath == "" {
		toolsPath = defaultToolsPath
	}
	env := &Env{
		BaseURL:   strings.TrimSuffix(base, "/"),
		Prefix:    strings.TrimSuffix(prefix, "/"),
		ToolsPath: "/" + strings.Trim(toolsPath, "/"),
	}
	req := readRequired(t)
	probe(t, env, req)

	cases := append([]Case(nil), registry...)
	sort.Slice(cases, func(i, j int) bool { return cases[i].Name < cases[j].Name })

	var skipped []string
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			for _, need := range c.Needs {
				st := env.Caps[need]
				switch {
				case st.state == capOn:
					// nothing to gate on
				case st.state == capBroken:
					t.Fatalf(`this case needs %q, and this deployment neither offers it nor declares it absent — it is broken.
A fault is not a configuration, and the suite will not let one switch a case off.
  %s`, need, st.why)
				case req.wants(need):
					t.Fatalf(`%s=%q names %q as a capability this deployment offers, and it does not.
  %s`, RequireEnv, req.spec, need, st.why)
				default:
					skipped = append(skipped, fmt.Sprintf("%-58s needs %q: %s", c.Name, need, st.why))
					t.Skipf(`deployment does not offer %q: %s

If this deployment is supposed to offer it, say so with %s and the skip becomes a failure.`,
						need, st.why, RequireEnv)
				}
			}
			if c.Doc != "" {
				t.Logf("contract: %s", c.Doc)
			}
			c.Run(t, env)
		})
	}

	// A skip is invisible without -v and costs nothing in the exit code, so a
	// suite that quietly stopped checking half the contract reads exactly like
	// one that checked all of it. Say it on stdout, where a non-verbose CI log
	// still shows it.
	if len(skipped) > 0 {
		var b strings.Builder
		fmt.Fprintf(&b, "%d of %d contract cases did NOT run against %s:\n", len(skipped), len(cases), env.BaseURL)
		for _, s := range skipped {
			fmt.Fprintf(&b, "  - %s\n", s)
		}
		fmt.Fprintf(&b, "Set %s (comma-separated, or \"all\") to turn these skips into failures.", RequireEnv)
		announce("%s", b.String())
	}
}

// announce puts a skip where a reader will trip over it under `go test -v`,
// which is how every invocation in the README runs.
//
// It cannot do better than that: cmd/go buffers a passing package's stdout and
// stderr alike and prints neither, so nothing a green test binary writes
// survives a non-verbose run. The exit code is the only channel that does, and
// the two things that use it are RequireEnv (an absent capability the operator
// said would be there) and the BaseURLEnv-empty-but-RequireEnv-set check above.
func announce(format string, args ...any) {
	fmt.Fprintf(os.Stdout, "\n[contract] "+format+"\n\n", args...)
}

// probe reads the deployment. Every answer here is an observation about this
// stack, never a decision about the contract: the contract is the same
// everywhere, and what changes between deployments is which parts of it are
// reachable.
//
// What each capability observes, and with which client, is the capability's own
// business and lives with its declaration (capabilities_test.go). This function
// owns only what is true of the pass as a whole: that it runs on the suite's own
// *testing.T so a probe can stand the suite down, that every declaration records
// exactly what it declared, and that what came back is reported once and loudly.
func probe(t *testing.T, e *Env, req required) {
	t.Helper()
	e.Caps = map[Capability]capability{}
	run := &probeRun{Env: e, Req: req, Anon: e.NewClient()}

	for _, decl := range orderedCapabilities() {
		run.settled = nil
		decl.Probe(t, run)
		assertSettled(t, decl, run.settled)
	}

	names := make([]string, 0, len(e.Caps))
	for k := range e.Caps {
		names = append(names, string(k))
	}
	sort.Strings(names)
	var b strings.Builder
	fmt.Fprintf(&b, "deployment under test: %s (router mounted at %s)\n", e.BaseURL, e.Prefix)
	if req.spec != "" {
		fmt.Fprintf(&b, "  %s=%s\n", RequireEnv, req.spec)
	}
	for _, n := range names {
		st := e.Caps[Capability(n)]
		fmt.Fprintf(&b, "  %-16s %-7s %s\n", n, st.state, st.why)
	}
	t.Log(b.String())

	// Report every fault once, loudly, even for a capability no case happens to
	// need: linked-accounts gates nothing, so a linked-accounts route that
	// started answering 500 would otherwise be recorded and never mentioned.
	for _, n := range names {
		c := Capability(n)
		st := e.Caps[c]
		if st.state == capBroken {
			t.Errorf(`capability %q is broken, not absent — this deployment is faulty.
  %s`, c, st.why)
		}
		if st.state == capAbsent && req.wants(c) {
			t.Errorf(`%s=%q names %q as a capability this deployment offers, and the probe could not find it.
  %s`, RequireEnv, req.spec, c, st.why)
		}
	}
}

// assertSettled holds one declaration to what it declared: every name in it
// recorded, and nothing recorded that it did not name.
//
// It is a check on the registry rather than on the deployment, and it is here
// because the registry is what later blocks extend. A declaration that names a
// capability its probe never records would leave that capability at the zero
// capState — capOn — so every case needing it would run against a deployment
// nobody looked at; one that records a name it did not declare would be
// invisible to RequireEnv, which is built from the declarations. Both are silent
// without this, and both are the exact mistake a copied declaration makes.
func assertSettled(t *testing.T, decl capabilityDecl, settled []Capability) {
	t.Helper()
	got := make(map[Capability]bool, len(settled))
	for _, c := range settled {
		got[c] = true
	}
	for _, want := range decl.names() {
		if !got[want] {
			t.Fatalf("capability %q declares that it settles %q, and its probe recorded no answer for it;"+
				" an unrecorded capability reads as \"on\" and would switch no case off",
				decl.Name, want)
		}
		delete(got, want)
	}
	for c := range got {
		t.Fatalf("capability %q recorded an answer for %q, which it does not declare;"+
			" add it to that declaration's Settles or %s could never name it",
			decl.Name, c, RequireEnv)
	}
}

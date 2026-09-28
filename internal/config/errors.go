package config

import (
	"fmt"
	"sort"
	"strings"
)

// Severity distinguishes a problem that refuses the deployment from one that is
// merely worth reading in the deployment log.
type Severity string

// Severity values.
const (
	SeverityError   Severity = "error"
	SeverityWarning Severity = "warning"
)

// Where a value came from. Anything else in Diagnostic.Source is the name of the
// AWESOME_AUTH_* variable that supplied it.
const (
	SourceDefault  = "default"
	SourceDocument = "config document"
)

// Refuse-to-start rule identifiers, matching the table in spec §2. They are
// part of the operator-visible contract: an error line carries the rule ID so a
// search for "RS-5" lands on the documentation that explains it.
const (
	RuleSecrets            = "RS-1"
	RuleInsecureCookieMode = "RS-2"
	RuleCSRFDisabled       = "RS-3"
	RuleIDProviderKeys     = "RS-4"
	RuleSameSiteNone       = "RS-5"
	RuleAdminUnguarded     = "RS-6"
	RuleResourceServerJWKS = "RS-8"
	RuleTTLSyntax          = "RS-9"
	RuleFirstUserListUsers = "RS-10"
	RuleOAuthIncomplete    = "RS-11"
	RuleMemoryStore        = "RS-12"

	// RuleMigrationIncomplete is not in the §2 table: the spec was extracted
	// from a reference that has no migration block, so there was nothing to
	// number. It takes the next free identifier rather than a name of its own
	// because it is the same kind of rule as the twelve above — a combination of
	// individually valid values that would deploy and then be wrong — and an
	// operator who searches for "RS-13" should land on it exactly as they land
	// on RS-5.
	RuleMigrationIncomplete = "RS-13"

	// RS-14 to RS-16 belong to the tools block (D9a), which numbered them first
	// and lands beside this one; the admin surface takes the two after them.
	//
	// RuleFirstUserRandomIDs refuses admin.accessPolicy: first-user on every
	// driver, because the policy's premise does not hold here. The reference
	// grants "the first registered user", meaning whoever listUsers(1, 0)
	// returns first, and that is the first registered user only under
	// monotonic ids. The core's ids are 128 random bits (newID, security.go),
	// the listers order by id, and so the console goes to whoever holds the
	// LOWEST RANDOM id -- which changes hands every time a later registrant
	// draws a lower one, through a route anybody can call. RS-10 already refuses
	// the policy on a driver that cannot list at all; this one refuses it on the
	// drivers that can, for the reason that what they list is not what the
	// policy assumes. cmd/auth/deviations.go admin-first-user-policy-is-refused
	// carries the argument and names the day it retires.
	RuleFirstUserRandomIDs = "RS-17"

	// RuleAdminCrossSiteCookie refuses the admin console under a session policy
	// beside cookies.sameSite: none. The console sits outside the CSRF chain by
	// design -- the vendored SPA posts to <admin>/login as JSON with no CSRF
	// header, so a double-submit check would refuse every login it makes -- and
	// the guard accepts the ordinary access-token cookie, so the cookie's
	// SameSite attribute is the only thing between a cross-site form post and
	// every admin write, POST <admin>/users/{id}/promote included. RS-5 makes
	// `none` need Secure; this one makes it and the console exclusive.
	RuleAdminCrossSiteCookie = "RS-18"

	// RuleSchemaVersion is not in the §2 table because §4 states it separately:
	// a document whose major version this build does not know refuses to start
	// with the same posture as any §2 rule.
	RuleSchemaVersion = "SCHEMA"

	// RuleUnimplemented marks a knob that is validated but not yet wired in this
	// phase. Reported as an error, not swallowed: an operator who configures
	// something that does nothing has to be told.
	RuleUnimplemented = "PHASE"

	// RuleStoreRequired marks the cross-store requirements of spec §1.17 — a
	// feature switched on whose backing store is disabled.
	RuleStoreRequired = "STORE"

	// RulePlaintextSecret marks a secret written literally into the
	// configuration document, which the secrets rule of spec §1 forbids.
	RulePlaintextSecret = "SECRET"

	// RuleIdentityModeConflict marks the one pair of domains that cannot both
	// describe one deployment: identity-provider mode, which mounts an
	// endpoint that takes a password and mints tokens, and resource-server
	// mode, whose whole purpose is that no such endpoint exists here.
	RuleIdentityModeConflict = "IDENTITY"
)

// Diagnostic is one configuration problem, aimed at an operator reading a single
// CloudWatch line at 3am with no source checkout: it names the knob by its
// dotted path, says where the offending value came from, what is wrong and what
// to do instead.
type Diagnostic struct {
	// Severity is SeverityError (refuse to start) or SeverityWarning.
	Severity Severity

	// Path is the dotted path of the offending knob, e.g.
	// "security.jwt.refreshTokenSecret". Empty only for a problem that is not
	// attributable to a single knob.
	Path string

	// Rule is the refuse-to-start rule identifier when one fired, e.g. "RS-5".
	Rule string

	// Source is SourceDefault, SourceDocument or the name of the environment
	// variable that supplied the value.
	Source string

	// Problem states what is wrong, in the present tense.
	Problem string

	// Remedy states what to do about it, imperatively.
	Remedy string
}

// Error renders the diagnostic as one self-contained line.
func (d Diagnostic) Error() string {
	var b strings.Builder
	b.WriteString("config: ")
	if d.Path != "" {
		b.WriteString(d.Path)
		b.WriteString(": ")
	}
	b.WriteString(d.Problem)
	if d.Source != "" && d.Source != SourceDefault {
		fmt.Fprintf(&b, " (value from %s)", d.Source)
	}
	if d.Remedy != "" {
		b.WriteString(" -- ")
		b.WriteString(d.Remedy)
	}
	if d.Rule != "" {
		fmt.Fprintf(&b, " [%s]", d.Rule)
	}
	return b.String()
}

// ValidationError aggregates every problem found in one pass. Load reports all
// of them at once on purpose: a deploy cycle per typo is not an acceptable way
// to configure a product.
type ValidationError struct {
	Diagnostics []Diagnostic
}

// Error lists every diagnostic, one self-contained line each, so that whichever
// line an operator happens to see is actionable on its own.
func (e *ValidationError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "config: refusing to start: %d problem(s) in the configuration", len(e.Diagnostics))
	for _, d := range e.Diagnostics {
		b.WriteString("\n")
		b.WriteString(d.Error())
	}
	return b.String()
}

// Unwrap exposes the individual diagnostics to errors.Is and errors.As.
func (e *ValidationError) Unwrap() []error {
	out := make([]error, len(e.Diagnostics))
	for i, d := range e.Diagnostics {
		out[i] = d
	}
	return out
}

// Rule returns the first diagnostic raised by the named rule, or nil. Tests and
// deployment tooling use it to assert on a specific rule rather than on the mere
// existence of an error.
func (e *ValidationError) Rule(rule string) *Diagnostic {
	for i := range e.Diagnostics {
		if e.Diagnostics[i].Rule == rule {
			return &e.Diagnostics[i]
		}
	}
	return nil
}

// HasRule reports whether the named rule fired.
func (e *ValidationError) HasRule(rule string) bool {
	return e.Rule(rule) != nil
}

// Paths returns the dotted paths of every diagnostic, deduplicated and sorted.
func (e *ValidationError) Paths() []string {
	seen := make(map[string]struct{}, len(e.Diagnostics))
	out := make([]string, 0, len(e.Diagnostics))
	for _, d := range e.Diagnostics {
		if _, dup := seen[d.Path]; dup {
			continue
		}
		seen[d.Path] = struct{}{}
		out = append(out, d.Path)
	}
	sort.Strings(out)
	return out
}

// diagnostics accumulates problems during a Load pass.
type diagnostics struct {
	cfg  *Config
	list []Diagnostic
}

// errf records a refuse-to-start problem at path. rule may be empty for plain
// type or range validation, which has no §2 rule ID.
func (d *diagnostics) errf(rule, path, problem, remedy string) {
	source := SourceDefault
	if d.cfg != nil {
		source = d.cfg.Source(path)
	}
	d.list = append(d.list, Diagnostic{
		Severity: SeverityError,
		Path:     path,
		Rule:     rule,
		Source:   source,
		Problem:  problem,
		Remedy:   remedy,
	})
}

func (d *diagnostics) err() error {
	if len(d.list) == 0 {
		return nil
	}
	// Stable, path-ordered output so the same broken document always produces
	// the same log, which is what makes a deployment diff readable.
	list := make([]Diagnostic, len(d.list))
	copy(list, d.list)
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].Path != list[j].Path {
			return list[i].Path < list[j].Path
		}
		return list[i].Rule < list[j].Rule
	})
	return &ValidationError{Diagnostics: list}
}

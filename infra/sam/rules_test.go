package sam

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// ── the Rules, evaluated ────────────────────────────────────────────────────
//
// A Rule is the template's own refusal: CloudFormation evaluates it against the
// parameters when a change set is created, before anything is touched. The
// ...IsARule tests pin each one's text. What text cannot show is whether the
// Rules refuse exactly what the function refuses at cold start — a refusal with
// no Rule deploys a function that fails every cold start, and a Rule stricter
// than the loader blocks a stack that would have run. The reader below
// evaluates them, so a test can hand the Rules and config.Load the same
// parameters and compare.
//
// It reads the small language the Rules section is written in and nothing
// more: !Equals, !Not, !And, !Or and !Ref, in flow form
// (`!Not [!Equals [!Ref X, '']]`) or as a block list under a bare tag. The
// Rule-specific functions over lists (!Contains, !EachMemberIn, ...) are not
// used here and are refused, and so are !Condition and !If, which
// CloudFormation does not allow in a Rule. Like the reader in template_test.go
// it adds no YAML dependency and refuses to guess: a shape it does not know
// fails the test that asked, rather than reading as a Rule that holds.
//
// cfn-lint is no substitute: it checks a Rule's structure, but given
// --parameters or --parameter-files it evaluates no Rule (1.60.1 passes a set
// that two Rules refuse, and a value outside AllowedValues).

// expr is one intrinsic-function expression. fn is the function's tag without
// the "!" ("Equals", "Ref", ...), or "" for a plain scalar, whose value is
// text; a !Ref or !Condition names its target in text.
type expr struct {
	fn   string
	args []expr
	text string
}

// parseFlow reads one expression written in flow form.
func parseFlow(s string) (expr, error) {
	p := flowReader{s: s}
	e, err := p.expr()
	if err != nil {
		return expr{}, fmt.Errorf("%w, in %q", err, s)
	}
	if p.skipSpace(); p.pos != len(p.s) {
		return expr{}, fmt.Errorf("%q follows the expression, in %q", p.s[p.pos:], s)
	}
	return e, nil
}

type flowReader struct {
	s   string
	pos int
}

func (p *flowReader) skipSpace() {
	for p.pos < len(p.s) && p.s[p.pos] == ' ' {
		p.pos++
	}
}

func isLetter(c byte) bool { return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' }

func (p *flowReader) expr() (expr, error) {
	p.skipSpace()
	if p.pos == len(p.s) {
		return expr{}, errors.New("an expression is missing")
	}
	if p.s[p.pos] != '!' {
		v, err := p.scalar()
		return expr{text: v}, err
	}
	p.pos++
	start := p.pos
	for p.pos < len(p.s) && isLetter(p.s[p.pos]) {
		p.pos++
	}
	fn := p.s[start:p.pos]
	if fn == "" {
		return expr{}, errors.New("a ! with no function name")
	}
	if p.skipSpace(); p.pos < len(p.s) && p.s[p.pos] == '[' {
		args, err := p.list()
		return expr{fn: fn, args: args}, err
	}
	v, err := p.scalar()
	return expr{fn: fn, text: v}, err
}

func (p *flowReader) list() ([]expr, error) {
	p.pos++ // the [
	var out []expr
	for {
		e, err := p.expr()
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		if p.skipSpace(); p.pos == len(p.s) {
			return nil, errors.New("a [ is never closed")
		}
		switch p.s[p.pos] {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return out, nil
		default:
			return nil, fmt.Errorf("%q inside a list", p.s[p.pos])
		}
	}
}

// scalar reads a single-quoted scalar, where two quotes in a row stand for
// one, or a plain one, which ends at the next comma or bracket. A plain
// scalar carrying anything YAML could read otherwise is refused instead of
// being read one way here and another there.
func (p *flowReader) scalar() (string, error) {
	p.skipSpace()
	if p.pos < len(p.s) && p.s[p.pos] == '\'' {
		var b strings.Builder
		for p.pos++; p.pos < len(p.s); p.pos++ {
			if p.s[p.pos] != '\'' {
				b.WriteByte(p.s[p.pos])
				continue
			}
			if p.pos+1 < len(p.s) && p.s[p.pos+1] == '\'' {
				b.WriteByte('\'')
				p.pos++
				continue
			}
			p.pos++
			return b.String(), nil
		}
		return "", errors.New("a quote is never closed")
	}
	start := p.pos
	for p.pos < len(p.s) && !strings.ContainsRune(",[]", rune(p.s[p.pos])) {
		p.pos++
	}
	v := strings.TrimSpace(p.s[start:p.pos])
	if v == "" || strings.ContainsAny(v, "\"'{}!&*#|>:%@`") {
		return "", fmt.Errorf("the scalar %q is not one this reader reads", v)
	}
	return v, nil
}

// ruleLine is one significant line of the Rules section: comments and blank
// lines are dropped, and the indentation is kept apart from the text.
type ruleLine struct {
	indent int
	text   string
	n      int // 1-based, in the template, for messages
}

// cfnRule is one Rule as CloudFormation evaluates it: with no condition, or a
// condition that holds, every assertion must hold.
type cfnRule struct {
	name      string
	condition *expr
	asserts   []expr
}

var (
	ruleNameLine = regexp.MustCompile(`^([A-Za-z0-9]+):$`)
	bareTag      = regexp.MustCompile(`^!([A-Za-z]+)$`)
)

// readRules returns every Rule of the template, in order. It fails the test if
// any line of the section is not one it understands, and if it finds a name it
// did not read a Rule for, so a Rule cannot drop out of an evaluation unseen.
func readRules(t *testing.T) []cfnRule {
	t.Helper()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	var lines []ruleLine
	names := 0
	section := ""
	for i, l := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if m := topLevelKey.FindStringSubmatch(l); m != nil {
			section = m[1]
			continue
		}
		if section != "Rules" || skip(l) {
			continue
		}
		text := strings.TrimLeft(l, " ")
		indent := len(l) - len(text)
		if indent == 2 && ruleNameLine.MatchString(strings.TrimSpace(text)) {
			names++
		}
		lines = append(lines, ruleLine{indent: indent, text: strings.TrimSpace(text), n: i + 1})
	}
	r := rulesReader{lines: lines}
	rules, err := r.rules()
	if err != nil {
		t.Fatalf("%s, Rules: %v", templateFile, err)
	}
	if len(rules) == 0 || len(rules) != names {
		t.Fatalf("read %d Rules out of %d names in %s: the reader in rules_test.go no longer understands the section, "+
			"and every evaluation would pass vacuously", len(rules), names, templateFile)
	}
	return rules
}

type rulesReader struct {
	lines []ruleLine
	pos   int
}

func (r *rulesReader) rules() ([]cfnRule, error) {
	var out []cfnRule
	for r.pos < len(r.lines) {
		l := r.lines[r.pos]
		m := ruleNameLine.FindStringSubmatch(l.text)
		if l.indent != 2 || m == nil {
			return nil, fmt.Errorf("line %d: %q is not the name of a Rule", l.n, l.text)
		}
		r.pos++
		rule := cfnRule{name: m[1]}
		for r.pos < len(r.lines) && r.lines[r.pos].indent > l.indent {
			k := r.lines[r.pos]
			key, rest, _ := strings.Cut(k.text, ":")
			rest = strings.TrimSpace(rest)
			switch {
			case k.indent == 4 && key == "RuleCondition" && rule.condition == nil:
				e, err := r.value(rest)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", rule.name, err)
				}
				rule.condition = &e
			case k.indent == 4 && key == "Assertions" && rest == "" && rule.asserts == nil:
				r.pos++
				asserts, err := r.assertions(k.indent)
				if err != nil {
					return nil, fmt.Errorf("%s: %w", rule.name, err)
				}
				rule.asserts = asserts
			default:
				return nil, fmt.Errorf("line %d: %q is not a key this reader reads in %s", k.n, k.text, rule.name)
			}
		}
		if len(rule.asserts) == 0 {
			return nil, fmt.Errorf("%s has no assertion", rule.name)
		}
		out = append(out, rule)
	}
	return out, nil
}

// value reads the expression after a key, or after the dash of a list item,
// on the current line: a flow expression on that line, or a bare tag whose
// arguments are the block list below it.
func (r *rulesReader) value(rest string) (expr, error) {
	l := r.lines[r.pos]
	r.pos++
	if m := bareTag.FindStringSubmatch(rest); m != nil {
		args, err := r.items(l)
		return expr{fn: m[1], args: args}, err
	}
	e, err := parseFlow(rest)
	if err != nil {
		return expr{}, fmt.Errorf("line %d: %w", l.n, err)
	}
	return e, nil
}

// items reads the block list under the bare tag on parent: items indented
// alike, deeper than parent, each a flow expression or a bare tag over a list
// of its own.
func (r *rulesReader) items(parent ruleLine) ([]expr, error) {
	if r.pos == len(r.lines) || r.lines[r.pos].indent <= parent.indent || !strings.HasPrefix(r.lines[r.pos].text, "- ") {
		return nil, fmt.Errorf("line %d: %q has no list under it", parent.n, parent.text)
	}
	indent := r.lines[r.pos].indent
	var out []expr
	for r.pos < len(r.lines) && r.lines[r.pos].indent >= indent {
		l := r.lines[r.pos]
		if l.indent != indent || !strings.HasPrefix(l.text, "- ") {
			return nil, fmt.Errorf("line %d: %q is not an item of the list under line %d", l.n, l.text, parent.n)
		}
		e, err := r.value(strings.TrimPrefix(l.text, "- "))
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

// assertions reads the list under Assertions: each item an Assert, and the
// AssertDescription beside it, which is text and is read past.
func (r *rulesReader) assertions(parent int) ([]expr, error) {
	var out []expr
	for r.pos < len(r.lines) && r.lines[r.pos].indent > parent {
		l := r.lines[r.pos]
		key, rest, _ := strings.Cut(strings.TrimPrefix(l.text, "- "), ":")
		if !strings.HasPrefix(l.text, "- ") || key != "Assert" {
			return nil, fmt.Errorf("line %d: %q is not an assertion (- Assert: ...)", l.n, l.text)
		}
		e, err := r.value(strings.TrimSpace(rest))
		if err != nil {
			return nil, err
		}
		out = append(out, e)
		if r.pos < len(r.lines) && r.lines[r.pos].indent == l.indent+2 {
			d := r.lines[r.pos]
			if !strings.HasPrefix(d.text, "AssertDescription:") {
				return nil, fmt.Errorf("line %d: %q is not an AssertDescription", d.n, d.text)
			}
			for r.pos++; r.pos < len(r.lines) && r.lines[r.pos].indent > d.indent; r.pos++ {
			}
		}
	}
	return out, nil
}

// holds evaluates a condition. ref resolves a !Ref; cond resolves a
// !Condition, and is nil in a Rule, which cannot name one. Every argument is
// evaluated, so a !Ref to a parameter that does not exist is an error even
// where the result would not need it.
func holds(e expr, ref func(string) (string, error), cond func(string) (bool, error)) (bool, error) {
	switch e.fn {
	case "Equals":
		if len(e.args) != 2 {
			return false, fmt.Errorf("!Equals takes two values, got %d", len(e.args))
		}
		a, err := value(e.args[0], ref)
		if err != nil {
			return false, err
		}
		b, err := value(e.args[1], ref)
		if err != nil {
			return false, err
		}
		return a == b, nil
	case "Not":
		if len(e.args) != 1 {
			return false, fmt.Errorf("!Not takes one condition, got %d", len(e.args))
		}
		v, err := holds(e.args[0], ref, cond)
		return !v, err
	case "And", "Or":
		// CloudFormation takes from 2 to 10 conditions in either.
		if len(e.args) < 2 || len(e.args) > 10 {
			return false, fmt.Errorf("!%s takes 2 to 10 conditions, got %d", e.fn, len(e.args))
		}
		all, some := true, false
		for _, a := range e.args {
			v, err := holds(a, ref, cond)
			if err != nil {
				return false, err
			}
			all, some = all && v, some || v
		}
		if e.fn == "And" {
			return all, nil
		}
		return some, nil
	case "Condition":
		if cond == nil {
			return false, fmt.Errorf("!Condition %s: a Rule cannot name a condition", e.text)
		}
		return cond(e.text)
	}
	return false, fmt.Errorf("!%s is not a condition this reader evaluates", e.fn)
}

// value evaluates a scalar or a !Ref.
func value(e expr, ref func(string) (string, error)) (string, error) {
	switch e.fn {
	case "":
		return e.text, nil
	case "Ref":
		return ref(e.text)
	}
	return "", fmt.Errorf("!%s is not a value this reader evaluates", e.fn)
}

// parameterRef resolves a !Ref in a Rule: a parameter of the template, by the
// value given.
func parameterRef(params map[string]string) func(string) (string, error) {
	return func(name string) (string, error) {
		v, ok := params[name]
		if !ok {
			return "", fmt.Errorf("!Ref %s names no parameter", name)
		}
		return v, nil
	}
}

// parameterValues returns every parameter's Default, as a Rule reads it,
// with the given values on top. A name the template has no parameter for is
// a mistake in the test, not a value.
func parameterValues(t *testing.T, tpl *template, given map[string]string) map[string]string {
	t.Helper()
	out := make(map[string]string, len(tpl.parameters))
	for name, p := range tpl.parameters {
		out[name] = literal(p.fields["Default"])
	}
	for name, v := range given {
		if _, ok := tpl.parameters[name]; !ok {
			t.Fatalf("the template has no parameter %s", name)
		}
		out[name] = v
	}
	return out
}

// refusedBy returns the names of the Rules that refuse a change set with these
// parameter values, sorted: those with no condition or one that holds, and an
// assertion that does not. Every condition and assertion is evaluated, whether
// or not the outcome needs it.
func refusedBy(t *testing.T, rules []cfnRule, params map[string]string) []string {
	t.Helper()
	ref := parameterRef(params)
	var out []string
	for _, rule := range rules {
		applies := true
		if rule.condition != nil {
			v, err := holds(*rule.condition, ref, nil)
			if err != nil {
				t.Fatalf("Rule %s, RuleCondition: %v", rule.name, err)
			}
			applies = v
		}
		ok := true
		for _, a := range rule.asserts {
			v, err := holds(a, ref, nil)
			if err != nil {
				t.Fatalf("Rule %s, Assert: %v", rule.name, err)
			}
			ok = ok && v
		}
		if applies && !ok {
			out = append(out, rule.name)
		}
	}
	slices.Sort(out)
	return out
}

// renderEnv evaluates the named variables of a function's environment as
// CloudFormation would for these parameter values, leaving out each one that
// comes to !Ref 'AWS::NoValue'. It reads one-line definitions of the forms
// !If [Condition, value, value], !Ref Parameter and a scalar, and the one-line
// Conditions they name; anything else fails the test.
func renderEnv(t *testing.T, tpl *template, function string, params map[string]string, names ...string) map[string]string {
	t.Helper()
	fn := tpl.resources[function]
	if fn == nil {
		t.Fatalf("%s is gone", function)
	}
	blocks := envBlocks(t, fn)
	ref := parameterRef(params)
	var cond func(string) (bool, error)
	cond = func(name string) (bool, error) {
		def, ok := tpl.conditions[name]
		if !ok {
			return false, fmt.Errorf("no one-line condition %s", name)
		}
		e, err := parseFlow(def)
		if err != nil {
			return false, fmt.Errorf("condition %s: %w", name, err)
		}
		return holds(e, ref, cond)
	}
	var render func(e expr) (string, bool, error)
	render = func(e expr) (string, bool, error) {
		switch {
		case e.fn == "Ref" && e.text == "AWS::NoValue":
			return "", false, nil
		case e.fn == "If":
			if len(e.args) != 3 || e.args[0].fn != "" {
				return "", false, errors.New("!If takes a condition name and two values")
			}
			v, err := cond(e.args[0].text)
			if err != nil {
				return "", false, err
			}
			if v {
				return render(e.args[1])
			}
			return render(e.args[2])
		}
		v, err := value(e, ref)
		return v, err == nil, err
	}
	env := map[string]string{}
	for _, name := range names {
		def, ok := blocks[name]
		if !ok {
			t.Fatalf("%s sets no %s", function, name)
		}
		_, rest, _ := strings.Cut(def, ":")
		if strings.Contains(rest, "\n") {
			t.Fatalf("%s's %s is defined over several lines, which renderEnv does not read:\n%s", function, name, def)
		}
		e, err := parseFlow(strings.TrimSpace(rest))
		if err != nil {
			t.Fatalf("%s's %s: %v", function, name, err)
		}
		v, set, err := render(e)
		if err != nil {
			t.Fatalf("%s's %s: %v", function, name, err)
		}
		if set {
			env[name] = v
		}
	}
	return env
}

// TestEveryRuleIsReadAndTheDefaultsPassThem keeps the reader honest: it must
// read every Rule in the section, and the template's own defaults — the stack
// a first deploy creates — must pass every one of them.
func TestEveryRuleIsReadAndTheDefaultsPassThem(t *testing.T) {
	t.Parallel()
	tpl := load(t)
	rules := readRules(t)
	if got := refusedBy(t, rules, parameterValues(t, tpl, nil)); len(got) != 0 {
		t.Errorf("the defaults are refused by %v", got)
	}
}

// TestTheRuleReaderReadsWhatTheRulesAreWrittenIn pins the reader itself on the
// shapes the section uses: flow and block forms, nesting, quoting, and an
// unconditional Rule.
func TestTheRuleReaderReadsWhatTheRulesAreWrittenIn(t *testing.T) {
	t.Parallel()
	lines := func(src string) []ruleLine {
		var out []ruleLine
		for i, l := range strings.Split(src, "\n") {
			if skip(l) {
				continue
			}
			text := strings.TrimLeft(l, " ")
			out = append(out, ruleLine{indent: len(l) - len(text), text: strings.TrimSpace(text), n: i + 1})
		}
		return out
	}
	src := `
  Flow:
    RuleCondition: !Not [!Equals [!Ref A, '']]
    Assertions:
      - Assert: !Equals [!Ref B, 'it''s']
        AssertDescription: >-
          text: with a colon, and !a tag.
  Blocks:
    RuleCondition: !And
      - !Or
        - !Equals [!Ref A, 'x']
        - !Equals [!Ref B, 'y']
      - !Equals [!Ref C, '']
    Assertions:
      - Assert: !Not
          - !And
            - !Equals [!Ref A, 'x']
            - !Equals [!Ref B, 'y']
        AssertDescription: text
      - Assert: !Not [!Equals [!Ref B, 'z']]
        AssertDescription: text
  Always:
    Assertions:
      - Assert: !Or
          - !Equals [!Ref A, '']
          - !Equals [!Ref B, '']
        AssertDescription: text
`
	r := rulesReader{lines: lines(src)}
	rules, err := r.rules()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(rules) != 3 || rules[2].condition != nil || len(rules[1].asserts) != 2 {
		t.Fatalf("read %+v", rules)
	}
	for _, c := range []struct {
		params map[string]string
		want   []string
	}{
		{map[string]string{"A": "", "B": "", "C": ""}, nil},
		{map[string]string{"A": "x", "B": "", "C": ""}, []string{"Flow"}},
		{map[string]string{"A": "x", "B": "it's", "C": ""}, []string{"Always"}},
		// The first assertion of Blocks fails, then the second alone.
		{map[string]string{"A": "x", "B": "y", "C": ""}, []string{"Always", "Blocks", "Flow"}},
		{map[string]string{"A": "x", "B": "z", "C": ""}, []string{"Always", "Blocks", "Flow"}},
		// The same failing assertion, under a condition that does not hold.
		{map[string]string{"A": "x", "B": "z", "C": "c"}, []string{"Always", "Flow"}},
		{map[string]string{"A": "z", "B": "y", "C": "c"}, []string{"Always", "Flow"}},
	} {
		if got := refusedBy(t, rules, c.params); !slices.Equal(got, c.want) {
			t.Errorf("%v: refused by %v, want %v", c.params, got, c.want)
		}
	}

	for _, bad := range []string{
		"  NoAssertion:\n    RuleCondition: !Equals [!Ref A, '']\n",
		"  BareTag:\n    Assertions:\n      - Assert: !And\n        AssertDescription: text\n",
		"  Stray:\n    Assertions:\n      - Assert: !Equals [!Ref A, '']\n        Other: x\n",
		"  Plain:\n    Assertions:\n      - Assert: !Equals [!Ref A, AWS::NoValue]\n",
		"  Nested:\n    Assertions:\n      - Assert: !Contains [[a], !Ref A]\n",
	} {
		r := rulesReader{lines: lines(bad)}
		if _, err := r.rules(); err == nil {
			t.Errorf("read without an error:\n%s", bad)
		}
	}
	// Read, but not a function a Rule here is evaluated with.
	r = rulesReader{lines: lines("  Unknown:\n    Assertions:\n      - Assert: !Contains [!Ref A, 'x']\n")}
	unknown, err := r.rules()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := holds(unknown[0].asserts[0], parameterRef(map[string]string{"A": ""}), nil); err == nil {
		t.Error("!Contains evaluated")
	}
	if _, err := holds(expr{fn: "Condition", text: "X"}, parameterRef(nil), nil); err == nil {
		t.Error("a Rule naming a condition evaluated")
	}
	if _, err := holds(expr{fn: "Equals", args: []expr{{fn: "Ref", text: "Missing"}, {text: "x"}}}, parameterRef(map[string]string{}), nil); err == nil {
		t.Error("a !Ref to no parameter evaluated")
	}
}

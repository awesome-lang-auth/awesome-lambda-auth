package sam

// D9c carries, verbatim, the two helpers D9b (PR #13) added to
// template_test.go to accept an alarm gated on a feature's own switch, because
// this branch and D9b's are stacked on the same base and both need them: the
// SSE function's one alarm is gated the same way (SseAlarmsEnabled). The line
// of TestEveryAlarmIsActionableAndGated that calls them is D9b's line, byte for
// byte, so that hunk merges cleanly; this file does not, by design — once both
// PRs are merged it is a duplicate declaration, and the resolution is to delete
// this file, nothing else.

import (
	"os"
	"strings"
	"testing"
)

// conditionDefinition returns the one-line definition of a named condition
// under Conditions:, or "" when there is none. The reader above does not parse
// that section; the conditions an alarm may be gated on are one-liners by
// convention, and a multi-line one simply fails the check that needs it.
func conditionDefinition(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(templateFile)
	if err != nil {
		t.Fatalf("read %s: %v", templateFile, err)
	}
	inConditions := false
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if m := topLevelKey.FindStringSubmatch(line); m != nil {
			inConditions = m[1] == "Conditions"
			continue
		}
		if inConditions && strings.HasPrefix(line, "  "+name+":") {
			return strings.TrimSpace(strings.TrimPrefix(line, "  "+name+":"))
		}
	}
	return ""
}

// gatedOnAlarmsEnabled accepts an alarm condition that is an !And over
// AlarmsEnabled and the switch of the feature the alarm watches. An alarm on a
// resource that exists only with a feature must be gated on that feature too —
// CloudFormation refuses a reference to a resource whose condition is false —
// and EnableAlarms must still turn it off, which the AlarmsEnabled term is.
func gatedOnAlarmsEnabled(t *testing.T, condition string) bool {
	t.Helper()
	def := conditionDefinition(t, condition)
	return strings.HasPrefix(def, "!And") && strings.Contains(def, "!Condition AlarmsEnabled")
}

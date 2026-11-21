package config

import (
	"strconv"
	"strings"
	"testing"
)

// TestCountingWindowsHaveACeiling pins the one-year ceiling on every counting
// window. A window is multiplied by time.Second where it is used; above ~292
// years that overflows int64 and the cap silently becomes a sub-second window
// (review of PR #25: 9223372037 went negative, 18446744074 wrapped to 290 ms).
func TestCountingWindowsHaveACeiling(t *testing.T) {
	for _, tc := range []struct {
		envName, path string
		extra         map[string]string
	}{
		{"AWESOME_AUTH_2FA_LOCKOUT_WINDOW_SECONDS", "twoFactor.lockout.windowSeconds", nil},
		{"AWESOME_AUTH_RATE_LIMIT_WINDOW_SECONDS", "rateLimit.windowSeconds", map[string]string{"AWESOME_AUTH_RATE_LIMIT_ENABLED": "true"}},
	} {
		for _, v := range []int64{9223372037, 18446744074, int64(MaxWindowSeconds) + 1} {
			t.Run(tc.path+"="+strconv.FormatInt(v, 10), func(t *testing.T) {
				env := baseEnv()
				for k, val := range tc.extra {
					env[k] = val
				}
				env[tc.envName] = strconv.FormatInt(v, 10)
				_, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)})
				if v > 1<<62 && err != nil && !strings.Contains(err.Error(), tc.path) {
					// An env value that does not fit an int is refused by the env parser,
					// which is just as good: the point is that it never loads.
					return
				}
				ve := validationError(t, err)
				found := false
				for _, d := range ve.Diagnostics {
					if d.Path == tc.path && d.Severity == SeverityError {
						found = true
						if d.Remedy == "" || !strings.Contains(d.Problem, "ceiling") && !strings.Contains(d.Problem, "integer") {
							t.Errorf("diagnostic at %s does not explain the ceiling: %+v", tc.path, d)
						}
					}
				}
				if !found {
					t.Fatalf("%s=%d loaded without an error at %s:\n%v", tc.envName, v, tc.path, ve)
				}
			})
		}
		t.Run(tc.path+" at the ceiling loads", func(t *testing.T) {
			env := baseEnv()
			for k, val := range tc.extra {
				env[k] = val
			}
			env[tc.envName] = strconv.Itoa(MaxWindowSeconds)
			if _, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env)}); err != nil {
				t.Fatalf("one year exactly must load: %v", err)
			}
		})
	}
}

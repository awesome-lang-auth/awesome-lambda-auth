package main

import "testing"

// TestTheConsoleFollowsTheDeploymentEnvironment: the reference's NODE_ENV rule
// in this product's spelling, with unset meaning production — the quiet side
// and the product's own default.
func TestTheConsoleFollowsTheDeploymentEnvironment(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		env  map[string]string
		want bool
	}{
		{map[string]string{}, false},
		{map[string]string{"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": ""}, false},
		{map[string]string{"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": "production"}, false},
		{map[string]string{"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT": "development"}, true},
	} {
		lookup := func(k string) (string, bool) { v, ok := tc.env[k]; return v, ok }
		if got := consoleEnabled(lookup); got != tc.want {
			t.Errorf("consoleEnabled(%v) = %v, want %v", tc.env, got, tc.want)
		}
	}
}

package config

import (
	"strings"
	"testing"
)

// The four knobs awesome-go-auth v0.16.0 opened: email.languages,
// security.forgotPassword.minResponseMs, twoFactor.enrolmentTokenTtlMinutes and
// sessions.revokeOnPasswordReset. Each defaults to the core's zero value — the
// behaviour of every earlier release — and each is refused here, by path, for
// the values the core would refuse at New with no key named.

func loadDoc(t *testing.T, doc Document, env map[string]string) (*Config, error) {
	t.Helper()
	return Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env)})
}

func warningsAt(cfg *Config, path string) []Diagnostic {
	var out []Diagnostic
	for _, w := range cfg.Warnings() {
		if w.Path == path {
			out = append(out, w)
		}
	}
	return out
}

func TestPasswordResetKnobsAreOffByDefault(t *testing.T) {
	cfg, err := loadDoc(t, baseDoc(), baseEnv())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Email.Languages) != 0 || cfg.Security.ForgotPassword.MinResponseMs != 0 ||
		cfg.TwoFactor.EnrolmentTokenTTLMinutes != 0 || cfg.Sessions.RevokeOnPasswordReset {
		t.Fatalf("a v0.16.0 knob is on by default: languages=%v floor=%d window=%d revoke=%v",
			cfg.Email.Languages, cfg.Security.ForgotPassword.MinResponseMs,
			cfg.TwoFactor.EnrolmentTokenTTLMinutes, cfg.Sessions.RevokeOnPasswordReset)
	}
	for _, path := range []string{"email.languages", "security.forgotPassword.minResponseMs", "twoFactor.enrolmentTokenTtlMinutes", "sessions.revokeOnPasswordReset"} {
		if w := warningsAt(cfg, path); len(w) != 0 {
			t.Errorf("the default document warns about %s: %v", path, w)
		}
	}
}

// TestPasswordResetKnobsLoadFromTheEnvironment: each knob has a variable, named
// to the convention of its block, and the list one splits and trims as every
// list variable does.
func TestPasswordResetKnobsLoadFromTheEnvironment(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_EMAIL_LANGUAGES"] = " it, en ,,"
	env["AWESOME_AUTH_SECURITY_FORGOT_PASSWORD_MIN_RESPONSE_MS"] = "1500"
	env["AWESOME_AUTH_2FA_ENROL_ON_LOGIN"] = "true"
	env["AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES"] = "15"
	env["AWESOME_AUTH_SESSIONS_REVOKE_ON_PASSWORD_RESET"] = "true"
	cfg, err := Load(t.Context(), Options{
		Document: baseDoc(),
		Getenv:   getenvFrom(env),
		// The capability is the store layer's; this test is about the variables.
		Capabilities: func(string) StoreCapabilities { return StoreCapabilities{ListUsers: true, RevokeUserSessions: true} },
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := strings.Join(cfg.Email.Languages, ","); got != "it,en" {
		t.Errorf("email.languages = %q, want it,en", got)
	}
	if cfg.Security.ForgotPassword.MinResponseMs != 1500 {
		t.Errorf("security.forgotPassword.minResponseMs = %d, want 1500", cfg.Security.ForgotPassword.MinResponseMs)
	}
	if cfg.TwoFactor.EnrolmentTokenTTLMinutes != 15 {
		t.Errorf("twoFactor.enrolmentTokenTtlMinutes = %d, want 15", cfg.TwoFactor.EnrolmentTokenTTLMinutes)
	}
	if !cfg.Sessions.RevokeOnPasswordReset {
		t.Error("sessions.revokeOnPasswordReset did not load from its variable")
	}
	for path, env := range map[string]string{
		"email.languages":                       "AWESOME_AUTH_EMAIL_LANGUAGES",
		"security.forgotPassword.minResponseMs": "AWESOME_AUTH_SECURITY_FORGOT_PASSWORD_MIN_RESPONSE_MS",
		"twoFactor.enrolmentTokenTtlMinutes":    "AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES",
		"sessions.revokeOnPasswordReset":        "AWESOME_AUTH_SESSIONS_REVOKE_ON_PASSWORD_RESET",
	} {
		if got := cfg.Source(path); got != env {
			t.Errorf("source of %s = %q, want %q", path, got, env)
		}
	}
}

// TestEmailLanguagesAreLanguageTags: an entry the core would refuse at New is
// refused here, by index, and a stray space is trimmed rather than refused —
// the entry is what a sender is handed.
func TestEmailLanguagesAreLanguageTags(t *testing.T) {
	for _, tc := range []struct {
		entry string
		ok    bool
	}{
		{"it", true},
		{"EN", true},
		{"it-IT", true},
		{"it_IT", true},
		{"zh-Hant-TW", true},
		{"de-1996", true},
		{" it ", true},
		{"abcdefgh-abcdefgh-abcdefgh-abcdefgh", true}, // 35 characters
		{"", false},
		{"i", false},
		{"1t", false},
		{"it-", false},
		{"-it", false},
		{"it--IT", false},
		{"it IT", false},
		{"it.IT", false},
		{"abcdefghi", false},
		{"it-abcdefghi", false},
		{"abcdefgh-abcdefgh-abcdefgh-abcdefgh-a", false}, // 37 characters
		{"日本", false},
		{`<script>`, false},
	} {
		doc := baseDoc()
		set(doc, "email.languages", []any{"en", tc.entry})
		cfg, err := loadDoc(t, doc, baseEnv())
		if tc.ok {
			if err != nil {
				t.Errorf("email.languages [en %q] refused: %v", tc.entry, err)
				continue
			}
			if got := cfg.Email.Languages[1]; got != strings.TrimSpace(tc.entry) {
				t.Errorf("email.languages[1] loaded as %q, want %q", got, strings.TrimSpace(tc.entry))
			}
			continue
		}
		d := requireRule(t, err, "", "email.languages[1]")
		if !strings.Contains(d.Problem, "not a language tag") {
			t.Errorf("refusal of %q does not say why: %s", tc.entry, d.Problem)
		}
	}
}

func TestForgotPasswordFloorIsBounded(t *testing.T) {
	for _, tc := range []struct {
		floor int
		ok    bool
	}{
		{0, true}, {1, true}, {MaxForgotPasswordMinResponseMs, true},
		{-1, false}, {MaxForgotPasswordMinResponseMs + 1, false},
	} {
		doc := baseDoc()
		set(doc, "security.forgotPassword.minResponseMs", tc.floor)
		_, err := loadDoc(t, doc, baseEnv())
		if tc.ok {
			if err != nil {
				t.Errorf("minResponseMs %d refused: %v", tc.floor, err)
			}
			continue
		}
		requireRule(t, err, "", "security.forgotPassword.minResponseMs")
	}
}

// TestForgotPasswordFloorWarns: whenever the floor is on, the loader says what
// it costs and what bounds that cost; and it says when the floor is too short
// to cover the delivery — below the webhook's timeout plus the allowance, or
// in front of SES, whose call has no deadline of its own here.
func TestForgotPasswordFloorWarns(t *testing.T) {
	const path = "security.forgotPassword.minResponseMs"
	load := func(t *testing.T, floor int, mutate func(Document, map[string]string)) []Diagnostic {
		t.Helper()
		doc, env := baseDoc(), baseEnv()
		set(doc, path, floor)
		if mutate != nil {
			mutate(doc, env)
		}
		cfg, err := loadDoc(t, doc, env)
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		return warningsAt(cfg, path)
	}
	hasCost := func(ws []Diagnostic) bool {
		for _, w := range ws {
			if strings.Contains(w.Problem, "concurrency") && strings.Contains(w.Remedy, "WAF") {
				return true
			}
		}
		return false
	}
	covering := func(ws []Diagnostic, want string) bool {
		for _, w := range ws {
			if strings.Contains(w.Problem, want) {
				return true
			}
		}
		return false
	}

	t.Run("no sender: the cost alone", func(t *testing.T) {
		ws := load(t, 300, nil)
		if !hasCost(ws) || len(ws) != 1 {
			t.Fatalf("warnings = %v, want the cost warning alone", ws)
		}
	})
	t.Run("a webhook slower than the floor", func(t *testing.T) {
		ws := load(t, 3000, func(doc Document, env map[string]string) {
			withWebhook(doc, env) // timeoutMs stays at its default, 5000
		})
		if !hasCost(ws) {
			t.Errorf("no cost warning: %v", ws)
		}
		if !covering(ws, "below email.deliveryWebhook.timeoutMs (5000 ms)") {
			t.Fatalf("no coverage warning for a floor under the webhook timeout: %v", ws)
		}
		for _, w := range ws {
			if strings.Contains(w.Problem, "below email.deliveryWebhook.timeoutMs") &&
				(!strings.Contains(w.Remedy, "at least 5250 ms") || !strings.Contains(w.Remedy, "at most 2750 ms")) {
				t.Errorf("the remedy does not size the fix: %s", w.Remedy)
			}
		}
	})
	t.Run("a webhook the floor covers", func(t *testing.T) {
		ws := load(t, 2500, func(doc Document, env map[string]string) {
			withWebhook(doc, env)
			set(doc, "email.deliveryWebhook.timeoutMs", 2000)
		})
		if len(ws) != 1 || !hasCost(ws) {
			t.Fatalf("warnings = %v, want the cost warning alone", ws)
		}
	})
	t.Run("SES has no deadline of its own", func(t *testing.T) {
		ws := load(t, 2000, func(doc Document, _ map[string]string) { withMailer(doc) })
		if !covering(ws, "Amazon SES") {
			t.Fatalf("no SES warning: %v", ws)
		}
	})
}

func TestEnrolmentWindow(t *testing.T) {
	const path = "twoFactor.enrolmentTokenTtlMinutes"
	load := func(t *testing.T, minutes int, enrol bool) (*Config, error) {
		t.Helper()
		doc := baseDoc()
		set(doc, path, minutes)
		set(doc, "twoFactor.enrolOnLogin", enrol)
		return loadDoc(t, doc, baseEnv())
	}

	for _, minutes := range []int{0, MinEnrolmentTokenTTLMinutes, 15, MaxEnrolmentTokenTTLMinutes} {
		if _, err := load(t, minutes, true); err != nil {
			t.Errorf("%d minutes with enrolOnLogin refused: %v", minutes, err)
		}
	}
	for _, minutes := range []int{-1, MaxEnrolmentTokenTTLMinutes + 1} {
		_, err := load(t, minutes, true)
		d := requireRule(t, err, "", path)
		if !strings.Contains(d.Problem, "outside") {
			t.Errorf("%d minutes refused without saying the range: %s", minutes, d.Problem)
		}
	}
	// Without enrolOnLogin no enrolment token is minted: the knob would bound
	// nothing, so it is refused, and 0 — the default — is not.
	_, err := load(t, 15, false)
	d := requireRule(t, err, "", path)
	if !strings.Contains(d.Problem, "enrolOnLogin is off") {
		t.Errorf("the refusal does not name the missing switch: %s", d.Problem)
	}
	if _, err := load(t, 0, false); err != nil {
		t.Errorf("the default window without enrolOnLogin refused: %v", err)
	}

	// Longer than the core's default widens every token's exposure, and says
	// so; the default and shorter windows say nothing of their own.
	for _, tc := range []struct {
		minutes int
		warns   bool
	}{{0, false}, {3, false}, {DefaultEnrolmentTokenTTLMinutes, false}, {15, true}} {
		cfg, err := load(t, tc.minutes, true)
		if err != nil {
			t.Fatalf("load %d: %v", tc.minutes, err)
		}
		ws := warningsAt(cfg, path)
		if got := len(ws) > 0; got != tc.warns {
			t.Errorf("%d minutes: warned %v, want %v (%v)", tc.minutes, got, tc.warns, ws)
		}
		for _, w := range ws {
			if !strings.Contains(w.Problem, "keeps it after the token has expired") || !strings.Contains(w.Remedy, "leaked factor") {
				t.Errorf("the warning does not state the trade-off: %s / %s", w.Problem, w.Remedy)
			}
		}
	}
}

// TestRevokeOnPasswordResetNeedsTheCapability: the key is refused on a driver
// whose session store cannot end every session of an account at once, and
// accepted where it can — whichever driver that is, which is the store layer's
// to say.
func TestRevokeOnPasswordResetNeedsTheCapability(t *testing.T) {
	const path = "sessions.revokeOnPasswordReset"
	for _, capable := range []bool{false, true} {
		doc := baseDoc()
		set(doc, path, true)
		_, err := Load(t.Context(), Options{
			Document: doc,
			Getenv:   getenvFrom(baseEnv()),
			Capabilities: func(string) StoreCapabilities {
				return StoreCapabilities{ListUsers: true, MigrationMarker: true, RevokeUserSessions: capable}
			},
		})
		if capable {
			if err != nil {
				t.Errorf("refused on a capable driver: %v", err)
			}
			continue
		}
		d := requireRule(t, err, RuleStoreRequired, path)
		if !strings.Contains(d.Problem, "UserSessionRevoker") {
			t.Errorf("the refusal does not name what the driver lacks: %s", d.Problem)
		}
	}

	// Off, nothing is asked of the driver.
	if _, err := Load(t.Context(), Options{
		Document:     baseDoc(),
		Getenv:       getenvFrom(baseEnv()),
		Capabilities: func(string) StoreCapabilities { return StoreCapabilities{ListUsers: true} },
	}); err != nil {
		t.Errorf("the default refused on an incapable driver: %v", err)
	}
}

// TestBuiltinSessionRevocationCapabilities pins the built-in table: the memory
// driver's store is the core's, whose listing the core revokes from; the
// postgres driver has no implementation at all.
func TestBuiltinSessionRevocationCapabilities(t *testing.T) {
	want := map[string]bool{
		StoreDriverMemory:   true,
		StoreDriverPostgres: false,
		StoreDriverDynamoDB: false,
	}
	for driver, capable := range want {
		if got := builtinCapabilities[driver].RevokeUserSessions; got != capable {
			t.Errorf("builtinCapabilities[%q].RevokeUserSessions = %v, want %v", driver, got, capable)
		}
	}
}

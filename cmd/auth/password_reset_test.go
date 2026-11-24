package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The four knobs awesome-go-auth v0.16.0 opened, end to end: email.languages,
// security.forgotPassword.minResponseMs, twoFactor.enrolmentTokenTtlMinutes and
// sessions.revokeOnPasswordReset. internal/config's password_reset_test.go pins
// the loader; these pin what reaches the core and what it then does on the
// wire.

// coreAccepts builds a bare core with opts and reports what New said.
func coreAccepts(opts ...auth.Option) error {
	_, err := auth.New(append([]auth.Option{
		auth.WithSecret(testAccessSecret),
		auth.WithUserStore(auth.NewMemoryUserStore()),
		auth.WithSessionStore(auth.NewMemorySessionStore()),
	}, opts...)...)
	return err
}

// appFromDocument runs the whole composition over a configuration document, the
// way the binary does, and reports whether it started.
func appFromDocument(t *testing.T, doc map[string]any, env map[string]string) error {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	app, err := New(context.Background(), Options{
		Getenv: envFunc(with(env, ConfigJSONEnv, string(raw))),
		Logger: discardLogger(),
		Stores: memoryStores,
	})
	if err == nil {
		app.Close()
	}
	return err
}

// TestTheLoaderAcceptsOnlyWhatTheCoreAccepts holds the loader's copies of the
// core's rules to the core. Whatever the loader accepts, the whole composition
// must start with — a value that validated and then failed its cold start
// would be a refusal with no key named — and for the two rules the loader
// copies rather than tightens (the language-tag shape and the enrolment
// window's range) whatever it refuses, the core refuses too. The floor's
// ceiling is the product's own and is pinned as such: the core takes more.
func TestTheLoaderAcceptsOnlyWhatTheCoreAccepts(t *testing.T) {
	t.Parallel()

	t.Run("email.languages", func(t *testing.T) {
		t.Parallel()
		for _, entry := range []string{
			"it", "EN", "it-IT", "it_IT", "zh-Hant-TW", "de-1996", " it ",
			"abcdefgh-abcdefgh-abcdefgh-abcdefgh",
			"", "i", "1t", "it-", "-it", "it--IT", "it IT", "it.IT", "abcdefghi",
			"it-abcdefghi", "abcdefgh-abcdefgh-abcdefgh-abcdefgh-a", "日本", "<script>",
		} {
			doc := map[string]any{"schemaVersion": 1, "email": map[string]any{"languages": []any{entry}}}
			_, loadErr := config.Load(context.Background(), config.Options{Document: doc, Getenv: envFunc(baseEnv())})
			coreErr := coreAccepts(auth.WithEmailLangs(strings.TrimSpace(entry)))
			if (loadErr == nil) != (coreErr == nil) {
				t.Errorf("%q: the loader says %v and the core says %v", entry, loadErr, coreErr)
				continue
			}
			if loadErr == nil {
				if err := appFromDocument(t, doc, baseEnv()); err != nil {
					t.Errorf("%q loaded and then did not start: %v", entry, err)
				}
			}
		}
	})

	t.Run("twoFactor.enrolmentTokenTtlMinutes", func(t *testing.T) {
		t.Parallel()
		if got, want := time.Duration(config.MinEnrolmentTokenTTLMinutes)*time.Minute, auth.MinEnrolmentTokenTTL; got != want {
			t.Errorf("config.MinEnrolmentTokenTTLMinutes is %s, the core's floor is %s", got, want)
		}
		if got, want := time.Duration(config.MaxEnrolmentTokenTTLMinutes)*time.Minute, auth.MaxEnrolmentTokenTTL; got != want {
			t.Errorf("config.MaxEnrolmentTokenTTLMinutes is %s, the core's ceiling is %s", got, want)
		}
		if got, want := time.Duration(config.DefaultEnrolmentTokenTTLMinutes)*time.Minute, auth.DefaultConfig(testAccessSecret).TempTokenTTL; got != want {
			t.Errorf("config.DefaultEnrolmentTokenTTLMinutes is %s, what 0 keeps (the core's TempTokenTTL) is %s", got, want)
		}
		for _, minutes := range []int{-1, 0, 1, 30, 31} {
			env := with(baseEnv(), "AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true",
				"AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES", fmt.Sprint(minutes))
			_, loadErr := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
			coreErr := coreAccepts(auth.WithEnrolOnLogin(true), auth.WithEnrolmentTokenTTL(time.Duration(minutes)*time.Minute))
			if (loadErr == nil) != (coreErr == nil) {
				t.Errorf("%d minutes: the loader says %v and the core says %v", minutes, loadErr, coreErr)
				continue
			}
			if loadErr == nil {
				app, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: discardLogger(), Stores: memoryStores})
				if err != nil {
					t.Errorf("%d minutes loaded and then did not start: %v", minutes, err)
					continue
				}
				app.Close()
			}
		}
	})

	t.Run("security.forgotPassword.minResponseMs", func(t *testing.T) {
		t.Parallel()
		for _, ms := range []int{-1, 0, 1, config.MaxForgotPasswordMinResponseMs, config.MaxForgotPasswordMinResponseMs + 1} {
			env := with(baseEnv(), "AWESOME_AUTH_SECURITY_FORGOT_PASSWORD_MIN_RESPONSE_MS", fmt.Sprint(ms))
			_, loadErr := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
			coreErr := coreAccepts(auth.WithForgotPasswordMinResponseTime(time.Duration(ms) * time.Millisecond))
			switch {
			case loadErr == nil:
				if coreErr != nil {
					t.Errorf("%d ms loaded, and the core refuses it: %v", ms, coreErr)
				}
				app, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: discardLogger(), Stores: memoryStores})
				if err != nil {
					t.Errorf("%d ms loaded and then did not start: %v", ms, err)
					continue
				}
				app.Close()
			case ms < 0 && coreErr == nil:
				t.Errorf("%d ms: the loader refuses a negative floor the core accepts", ms)
			case ms > config.MaxForgotPasswordMinResponseMs && coreErr != nil:
				t.Errorf("%d ms: the core refuses it too (%v); the ceiling was supposed to be the product's own", ms, coreErr)
			}
		}
	})

	t.Run("sessions.revokeOnPasswordReset", func(t *testing.T) {
		t.Parallel()
		env := with(baseEnv(), "AWESOME_AUTH_SESSIONS_REVOKE_ON_PASSWORD_RESET", "true")
		if _, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)}); err != nil {
			t.Fatalf("the memory driver refuses the key: %v", err)
		}
		app, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: discardLogger(), Stores: memoryStores})
		if err != nil {
			t.Fatalf("the key loaded and then did not start: %v", err)
		}
		app.Close()
	})
}

// deliveredLang reads the lang of the last password-reset delivery the
// receiver got; present reports whether the delivery carried one at all.
func deliveredLang(t *testing.T, rec *webhookReceiver) (lang string, present bool) {
	t.Helper()
	var last json.RawMessage
	for _, d := range rec.deliveries() {
		if d.request.Kind == auth.DeliveryKindPasswordReset {
			last = d.request.Delivery
		}
	}
	if last == nil {
		t.Fatal("no password-reset delivery reached the receiver")
	}
	var body map[string]any
	if err := json.Unmarshal(last, &body); err != nil {
		t.Fatalf("decode delivery: %v", err)
	}
	v, ok := body["lang"]
	if !ok {
		return "", false
	}
	s, _ := v.(string)
	return s, true
}

// TestEmailLanguagesBoundTheDeliveredLanguage: with email.languages set, the
// language a stranger names in emailLang reaches the delivery webhook as one of
// the configured entries — matched by case and primary subtag — or not at all,
// so the receiver falls back to its own default; unset, it passes through as
// sent, which is the control.
func TestEmailLanguagesBoundTheDeliveredLanguage(t *testing.T) {
	t.Parallel()
	const owner = "languages@example.test"
	ask := func(t *testing.T, d *deliveryApp, rec *webhookReceiver, emailLang string) (string, bool) {
		t.Helper()
		resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil,
			fmt.Sprintf(`{"email":%q,"emailLang":%q}`, owner, emailLang))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("forgot-password with emailLang %q answered %d %s", emailLang, resp.StatusCode, resp.Body)
		}
		return deliveredLang(t, rec)
	}

	t.Run("bounded", func(t *testing.T) {
		t.Parallel()
		rec := newWebhookReceiver(t)
		d := newDeliveryAppWith(t, webhookEnv(baseEnv(), rec.srv.URL, "AWESOME_AUTH_EMAIL_LANGUAGES", "it,en"),
			func(o *Options) { o.HTTPClient = rec.srv.Client() })
		d.register(t, owner)
		for _, tc := range []struct {
			asked, want string
			present     bool
		}{
			{"IT-it", "it", true},
			{"en_GB", "en", true},
			{"de-DE", "", false},
			{"<script>alert(1)</script>", "", false},
		} {
			if got, present := ask(t, d, rec, tc.asked); got != tc.want || present != tc.present {
				t.Errorf("emailLang %q reached the receiver as %q (present %v), want %q (present %v)", tc.asked, got, present, tc.want, tc.present)
			}
		}
	})

	t.Run("unset passes the request's value through", func(t *testing.T) {
		t.Parallel()
		rec := newWebhookReceiver(t)
		d := newDeliveryAppWith(t, webhookEnv(baseEnv(), rec.srv.URL), func(o *Options) { o.HTTPClient = rec.srv.Client() })
		d.register(t, owner)
		if got, present := ask(t, d, rec, "de-DE"); got != "de-DE" || !present {
			t.Errorf("without email.languages, emailLang de-DE reached the receiver as %q (present %v)", got, present)
		}
	})
}

// TestForgotPasswordFloorHoldsEveryAnswer: with the floor set, an address no
// account holds — the branch that used to answer right after a lookup — is held
// until the floor has passed. The control, with no floor, answers well inside
// it.
func TestForgotPasswordFloorHoldsEveryAnswer(t *testing.T) {
	t.Parallel()
	const floor = 400 * time.Millisecond
	ask := func(t *testing.T, app *App) time.Duration {
		t.Helper()
		start := time.Now()
		resp := invoke(t, app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil, `{"email":"nobody@example.test"}`)
		elapsed := time.Since(start)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("forgot-password answered %d %s", resp.StatusCode, resp.Body)
		}
		return elapsed
	}

	held := newTestApp(t, with(baseEnv(), "AWESOME_AUTH_SECURITY_FORGOT_PASSWORD_MIN_RESPONSE_MS", fmt.Sprint(floor.Milliseconds())))
	if got := ask(t, held); got < floor {
		t.Errorf("an unknown address was answered after %s, under the %s floor", got, floor)
	}
	if got := ask(t, newTestApp(t, baseEnv())); got >= floor {
		t.Errorf("with no floor an unknown address took %s; the control cannot tell the floor from a slow run", got)
	}
}

// tokenLifetime reads exp - iat out of a JWT without verifying it: the test
// asserts what the client is told, and the core verified it when it minted it.
func tokenLifetime(t *testing.T, token string) time.Duration {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode claims: %v", err)
	}
	var claims struct {
		Iat int64 `json:"iat"`
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatalf("unmarshal claims: %v", err)
	}
	return time.Duration(claims.Exp-claims.Iat) * time.Second
}

// TestEnrolmentWindowIsTheTokensLifetime: twoFactor.enrolmentTokenTtlMinutes is
// the lifetime of the enrolment token a 2FA_SETUP_REQUIRED login hands out under
// enrolOnLogin — its exp, which is what a client can show — and the enrolment
// completes with it; 0 keeps the core's five minutes.
func TestEnrolmentWindowIsTheTokensLifetime(t *testing.T) {
	t.Parallel()
	realm := with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true", "AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true")
	for _, tc := range []struct {
		minutes string
		want    time.Duration
	}{
		{"", 5 * time.Minute},
		{"15", 15 * time.Minute},
		{"1", time.Minute},
	} {
		env := realm
		if tc.minutes != "" {
			env = with(realm, "AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES", tc.minutes)
		}
		app := newTestApp(t, env)
		email := "window-" + tc.minutes + "@example.test"
		if reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email)); reg.StatusCode != http.StatusCreated {
			t.Fatalf("register answered %d %s", reg.StatusCode, reg.Body)
		}
		login := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, loginBody(email, testPassword))
		temp, _ := decodeBody(t, login)["tempToken"].(string)
		if login.StatusCode != http.StatusForbidden || temp == "" {
			t.Fatalf("login answered %d %s, want 403 2FA_SETUP_REQUIRED with a tempToken", login.StatusCode, login.Body)
		}
		if got := tokenLifetime(t, temp); got != tc.want {
			t.Errorf("enrolmentTokenTtlMinutes %q: the enrolment token lives %s, want %s", tc.minutes, got, tc.want)
		}
	}
	// And the longer window is a working one: the whole forced enrolment
	// completes on it.
	forcedEnrolment(t, newTestApp(t, with(realm, "AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES", "15")), "window-complete@example.test")
}

// TestRevokingResetEndsTheSessions: with sessions.revokeOnPasswordReset on, a
// session opened with the old password is refused at its next refresh once the
// reset has gone through — 401 SESSION_REVOKED — and the new password opens a
// session that works. Off, the old session goes on refreshing, which is the
// reference's answer and the control. The memory driver: the core's listing
// path.
func TestRevokingResetEndsTheSessions(t *testing.T) {
	t.Parallel()
	const newPassword = "another-correct-horse-battery"
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)

	for _, revoke := range []bool{true, false} {
		t.Run(fmt.Sprintf("revokeOnPasswordReset=%v", revoke), func(t *testing.T) {
			t.Parallel()
			d := newDeliveryApp(t, mailerEnv(baseEnv(), "AWESOME_AUTH_SESSIONS_REVOKE_ON_PASSWORD_RESET", fmt.Sprint(revoke)))
			const owner = "revoked@example.test"
			login := registerAndLogin(t, d.app, bearerJSON, owner)
			refresh, _ := decodeBody(t, login)["refreshToken"].(string)
			if refresh == "" {
				t.Fatalf("login answered no refresh token: %s", login.Body)
			}

			if resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil, fmt.Sprintf(`{"email":%q}`, owner)); resp.StatusCode != http.StatusOK {
				t.Fatalf("forgot-password answered %d %s", resp.StatusCode, resp.Body)
			}
			token := tokenIn(t, linkIn(t, d.mail.only(t).Body))
			if resp := invoke(t, d.app, http.MethodPost, "/auth/reset-password", bearerJSON, nil,
				fmt.Sprintf(`{"token":%q,"password":%q}`, token, newPassword)); resp.StatusCode != http.StatusOK {
				t.Fatalf("reset-password answered %d %s", resp.StatusCode, resp.Body)
			}

			old := invoke(t, d.app, http.MethodPost, "/auth/refresh", bearerJSON, nil, fmt.Sprintf(`{"refreshToken":%q}`, refresh))
			if revoke {
				if old.StatusCode != http.StatusUnauthorized || decodeBody(t, old)["code"] != "SESSION_REVOKED" {
					t.Errorf("the old session's refresh after a revoking reset answered %d %s, want 401 SESSION_REVOKED", old.StatusCode, old.Body)
				}
			} else if old.StatusCode != http.StatusOK {
				t.Errorf("the old session's refresh after a reset with the key off answered %d %s, want 200", old.StatusCode, old.Body)
			}

			fresh := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, newPassword))
			if fresh.StatusCode != http.StatusOK {
				t.Fatalf("login with the new password answered %d %s", fresh.StatusCode, fresh.Body)
			}
			again, _ := decodeBody(t, fresh)["refreshToken"].(string)
			if resp := invoke(t, d.app, http.MethodPost, "/auth/refresh", bearerJSON, nil, fmt.Sprintf(`{"refreshToken":%q}`, again)); resp.StatusCode != http.StatusOK {
				t.Errorf("the new password's session does not refresh: %d %s", resp.StatusCode, resp.Body)
			}
		})
	}
}

// TestAResourceServerReportsTheResetKnobs: resource-server mode mounts none of
// the routes three of the knobs shape, so each is reported at cold start rather
// than silently read by nothing; email.languages is not, because /link-request
// stays mounted there and its mail carries the request's language.
func TestAResourceServerReportsTheResetKnobs(t *testing.T) {
	t.Parallel()
	env := map[string]string{
		"AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT":                   "development",
		"AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL":                    "https://api.example.test",
		"AWESOME_AUTH_JWT_ACCESS_SECRET":                        testAccessSecret,
		"AWESOME_AUTH_RS_ENABLED":                               "true",
		"AWESOME_AUTH_RS_JWKS_URL":                              "https://issuer.example.test/.well-known/jwks.json",
		"AWESOME_AUTH_EMAIL_LANGUAGES":                          "it,en",
		"AWESOME_AUTH_SECURITY_FORGOT_PASSWORD_MIN_RESPONSE_MS": "1000",
		"AWESOME_AUTH_2FA_ENROL_ON_LOGIN":                       "true",
		"AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES":          "15",
		"AWESOME_AUTH_SESSIONS_REVOKE_ON_PASSWORD_RESET":        "true",
	}
	got := map[string]bool{}
	for _, g := range unwiredKnobs(loadTestConfig(t, env)) {
		got[g.Path] = true
	}
	for _, want := range []string{"security.forgotPassword.minResponseMs", "sessions.revokeOnPasswordReset", "twoFactor.enrolmentTokenTtlMinutes"} {
		if !got[want] {
			t.Errorf("a resource server does not report %s", want)
		}
	}
	if got["email.languages"] {
		t.Error("a resource server reports email.languages, which /link-request still reads there")
	}

	// Off resource-server mode, the same knobs act and nothing is reported.
	delete(env, "AWESOME_AUTH_RS_ENABLED")
	delete(env, "AWESOME_AUTH_RS_JWKS_URL")
	env["AWESOME_AUTH_JWT_REFRESH_SECRET"] = testRefreshSecret
	for _, g := range unwiredKnobs(loadTestConfig(t, env)) {
		switch g.Path {
		case "security.forgotPassword.minResponseMs", "sessions.revokeOnPasswordReset", "twoFactor.enrolmentTokenTtlMinutes", "email.languages":
			t.Errorf("the issuing deployment reports %s, which it honours", g.Path)
		}
	}
}

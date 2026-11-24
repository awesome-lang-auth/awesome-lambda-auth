package main

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// TestTOTPSetupAdvertisesTheConfiguredIssuer drives the knob all the way to the
// only place it is observable: the otpauth:// URI POST /2fa/setup hands a
// client, which is what an authenticator app labels the enrolment with.
//
// Both places the issuer appears are checked, because they are separate pieces
// of the URI and a client that reads one is not reading the other: the label
// prefix (otpauth://totp/<issuer>:<account>) is what older apps display, and the
// issuer query parameter is what the current ones prefer. otplib writes both,
// the reference emits otplib's URI, and a port that filled in one of them would
// look right in one app and wrong in the next.
func TestTOTPSetupAdvertisesTheConfiguredIssuer(t *testing.T) {
	t.Parallel()

	const issuer = "Example Identity"
	app := newTestApp(t, with(baseEnv(), "AWESOME_AUTH_2FA_APP_NAME", issuer))

	reg := registerAndLogin(t, app, jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), "totp@example.test")
	token, _ := decodeBody(t, reg)["accessToken"].(string)

	setup := invoke(t, app, http.MethodPost, "/auth/2fa/setup", bearer(token), nil, "")
	if setup.StatusCode != http.StatusOK {
		t.Fatalf("2fa/setup status = %d (body %s)", setup.StatusCode, setup.Body)
	}
	raw, _ := decodeBody(t, setup)["otpauthUrl"].(string)
	if raw == "" {
		t.Fatalf("2fa/setup returned no otpauthUrl: %s", setup.Body)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("otpauthUrl %q does not parse: %v", raw, err)
	}
	if got := u.Query().Get("issuer"); got != issuer {
		t.Errorf("otpauthUrl issuer parameter = %q, want %q (from %s)", got, issuer, raw)
	}
	// The label is "<issuer>:<account>", percent-encoded in the path.
	label := strings.TrimPrefix(u.Path, "/")
	if !strings.HasPrefix(label, issuer+":") {
		t.Errorf("otpauthUrl label = %q, want it prefixed with %q: (from %s)", label, issuer+":", raw)
	}
}

// TestTOTPIssuerDefaultsToTheSchemaLiteral: with no twoFactor block at all, the
// URI still carries the reference's own issuer.
//
// This is what makes the core deviation totp-issuer-defaults-to-config-issuer
// invisible on this product. The core falls back to Config.Issuer when
// TwoFactorAppName is unset, and Config.Issuer is "awesome-go-auth"; the
// schema's default for twoFactor.appName is the reference's literal
// "awesome-node-auth", and twoFactorOptions passes it unconditionally, so the
// fallback is never reached and an operator who configures nothing gets the
// same label the reference gives them.
func TestTOTPIssuerDefaultsToTheSchemaLiteral(t *testing.T) {
	t.Parallel()

	app := newTestApp(t, baseEnv())
	reg := registerAndLogin(t, app, jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), "totp-default@example.test")
	token, _ := decodeBody(t, reg)["accessToken"].(string)

	setup := invoke(t, app, http.MethodPost, "/auth/2fa/setup", bearer(token), nil, "")
	raw, _ := decodeBody(t, setup)["otpauthUrl"].(string)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("otpauthUrl %q does not parse: %v", raw, err)
	}
	if got := u.Query().Get("issuer"); got != "awesome-node-auth" {
		t.Errorf("otpauthUrl issuer = %q, want the schema default %q — the core's Config.Issuer fallback is showing through (from %s)",
			got, "awesome-node-auth", raw)
	}
}

// TestTwoFactorOptionsIsUnconditional: there is no configuration in which the
// issuer is not passed, because there is no configuration in which it is empty
// — validate.go refuses that — and a gate here could only disagree with
// validation. The policy options ride with it, as written, so the count is
// four on every document — the enrolment window included, whose 0 is the core's
// own default; TestTwoFactorOptionsCarryThePolicy (realm_test.go) pins what they
// carry.
func TestTwoFactorOptionsIsUnconditional(t *testing.T) {
	t.Parallel()

	for _, env := range []map[string]string{
		baseEnv(),
		with(baseEnv(), "AWESOME_AUTH_2FA_APP_NAME", "Example Identity"),
		with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true", "AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true"),
		with(baseEnv(), "AWESOME_AUTH_2FA_REQUIRED", "true", "AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true", "AWESOME_AUTH_2FA_ENROLMENT_TOKEN_TTL_MINUTES", "15"),
	} {
		cfg := loadTestConfig(t, env)
		if got := len(twoFactorOptions(cfg)); got != 4 {
			t.Errorf("twoFactorOptions returned %d options, want exactly 4 (issuer, require2FA, enrolOnLogin, enrolment window) for appName %q", got, cfg.TwoFactor.AppName)
		}
	}
}

// TestBcryptCostReachesTheCore is the other half of closing that knob gap: the
// warning is gone from unwiredKnobs (TestUnwiredKnobs), and this proves the
// reason it is gone.
//
// The check reads the cost out of the stored hash rather than timing anything.
// bcrypt writes its cost into the modular-crypt prefix of every hash it
// produces, so the stored value states what it was hashed at — and that is the
// number the knob is about, since a hash verifies at whatever cost it carries
// regardless of what the configuration says today.
//
// A non-default value is used deliberately: with 12 on both sides the test
// would pass against a build that ignored the knob entirely and hashed at the
// product default by coincidence.
//
// The unset case is here for the opposite reason, and it is the only place in
// the package that covers it. baseEnv pins bcryptSaltRounds to 10 for every
// other test, for time, so the shipped schema default reaches coreOptions in no
// other test at all: a change that let a value below the core's floor through
// at the default, or that dropped WithBcryptCost from the option list, would
// still leave a green package. The case costs one hash at 12 and closes that.
func TestBcryptCostReachesTheCore(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		// env is the value of AWESOME_AUTH_BCRYPT_SALT_ROUNDS; empty means the
		// knob is not set at all and the schema default decides.
		env  string
		want int
	}{
		{"the floor of the supported range", "10", 10},
		{"a value that is neither default nor floor", "11", 11},
		{"unset, so the schema default decides", "", config.Defaults().Security.Password.BcryptSaltRounds},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			env := baseEnv()
			if tc.env == "" {
				delete(env, "AWESOME_AUTH_BCRYPT_SALT_ROUNDS")
			} else {
				env["AWESOME_AUTH_BCRYPT_SALT_ROUNDS"] = tc.env
			}

			users := auth.NewMemoryUserStore()
			app, err := New(context.Background(), Options{
				Getenv: envFunc(env),
				Logger: discardLogger(),
				Stores: storeFactory(users, auth.NewMemorySessionStore()),
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			email := fmt.Sprintf("cost-%d@example.test", tc.want)
			if resp := invoke(t, app, http.MethodPost, "/auth/register",
				jsonHeaders(), nil, registerBody(email)); resp.StatusCode != http.StatusCreated {
				t.Fatalf("register status = %d (body %s)", resp.StatusCode, resp.Body)
			}

			user, err := users.GetUserByEmail(context.Background(), email, "")
			if err != nil {
				t.Fatalf("GetUserByEmail: %v", err)
			}
			if cost := bcryptCostOf(t, user.PasswordHash); cost != tc.want {
				t.Errorf("password hashed at bcrypt cost %d, want %d", cost, tc.want)
			}

			// And the account still logs in, which is the part a cost change
			// breaks if the hash and the verifier disagree.
			if resp := invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(), nil,
				registerBody(email)); resp.StatusCode != http.StatusOK {
				t.Errorf("login status = %d, want 200 (body %s)", resp.StatusCode, resp.Body)
			}
		})
	}
}

// bcryptCostOf reads the cost out of a modular-crypt bcrypt hash,
// "$2<variant>$<cost>$<22 salt><31 digest>" (PHC/crypt format).
//
// Parsed here rather than through golang.org/x/crypto/bcrypt.Cost so that the
// test does not turn an indirect dependency of this module into a direct one
// for two digits. The format is fixed and self-describing; a hash this does not
// recognise fails the test rather than returning a number.
func bcryptCostOf(t *testing.T, hash string) int {
	t.Helper()
	parts := strings.Split(hash, "$")
	// "", "2a", "10", "<salt><digest>"
	if len(parts) != 4 || !strings.HasPrefix(parts[1], "2") {
		t.Fatalf("the stored password hash is not a bcrypt hash: %q", hash)
	}
	cost, err := strconv.Atoi(parts[2])
	if err != nil {
		t.Fatalf("bcrypt hash carries no numeric cost: %q", hash)
	}
	return cost
}

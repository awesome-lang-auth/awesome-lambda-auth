package main

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// settingsEnv is the smallest environment with the settings store on.
func settingsEnv(kv ...string) map[string]string {
	return with(with(baseEnv(), "AWESOME_AUTH_STORES_ENABLE_SETTINGS", "true"), kv...)
}

// settingsCfg builds a configuration directly rather than loading one, for the
// cases that are about settingsOptions alone: a loaded document drags in the
// whole refuse-to-start set, and none of it is what is under test here.
func settingsCfg(mutate func(*config.Config)) *config.Config {
	cfg := config.Defaults()
	cfg.Deployment.Environment = config.EnvironmentDevelopment
	cfg.Stores.Enable.Settings = true
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

// TestRuntimeSettingsSeedReachesTheCore drives the knob all the way to the only
// place it is observable today: POST <prefix>/2fa/disable, which the core
// answers 403 2FA_REQUIRED on when the settings store holds require2FA
// (auth.router.ts:890-896).
//
// It is the whole chain in one assertion — the document loads at all, which it
// could not while the phase gate refused it; the declared seed is written into
// the store; the store is handed to the core through auth.WithSettingsStore; and
// the core consults it on the route. It is also what fails if the settings slot
// of coreOptionSets is ever emptied, which nothing else would catch:
// Config.Settings is an ordinary field, and a nil one makes the core skip the
// check rather than complain.
func TestRuntimeSettingsSeedReachesTheCore(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, settingsEnv("AWESOME_AUTH_RUNTIME_SETTINGS_REQUIRE_2FA", "true"))

	reg := invoke(t, app, http.MethodPost, "/auth/register",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody("settings@example.test"))
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d (body %s)", reg.StatusCode, reg.Body)
	}
	token, _ := decodeBody(t, reg)["accessToken"].(string)

	resp := invoke(t, app, http.MethodPost, "/auth/2fa/disable", bearer(token), nil, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("2fa/disable status = %d, want 403 — the seeded require2FA never reached the core (body %s)",
			resp.StatusCode, resp.Body)
	}
	if code, _ := decodeBody(t, resp)["code"].(string); code != "2FA_REQUIRED" {
		t.Errorf("2fa/disable code = %q, want %q (body %s)", code, "2FA_REQUIRED", resp.Body)
	}
}

// The mirror image: with no seed, the route answers as it always has. The
// settings store is wired and empty, so this also pins that an empty document
// reads as "not required" rather than as a fault.
func TestNoRuntimeSettingsSeedLeavesTheRouteAlone(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, settingsEnv())

	reg := invoke(t, app, http.MethodPost, "/auth/register",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody("unseeded@example.test"))
	if reg.StatusCode != http.StatusCreated {
		t.Fatalf("register status = %d (body %s)", reg.StatusCode, reg.Body)
	}
	token, _ := decodeBody(t, reg)["accessToken"].(string)

	resp := invoke(t, app, http.MethodPost, "/auth/2fa/disable", bearer(token), nil, "")
	if resp.StatusCode != http.StatusOK {
		t.Errorf("2fa/disable status = %d, want 200 with an empty settings store (body %s)", resp.StatusCode, resp.Body)
	}
}

// TestRuntimeSettingsSeedOnlyFillsAbsentKeys is the registered deviation, tested
// where it is decided.
//
// A Lambda cold-starts constantly, so "the document wins on every cold start"
// would mean an administrator's toggle reverting at an unpredictable moment. The
// store wins, for good, and the seed says which keys it left alone.
func TestRuntimeSettingsSeedOnlyFillsAbsentKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bundle := newMemoryStoreBundle()

	// An administrator switched it off at run time, against a document that
	// declares it on.
	off := false
	if _, err := bundle.Settings().UpdateSettings(ctx, auth.AuthSettings{Require2FA: &off}); err != nil {
		t.Fatalf("UpdateSettings: %v", err)
	}

	cfg := settingsCfg(func(c *config.Config) {
		c.RuntimeSettings.Require2FA = true
		c.RuntimeSettings.LazyEmailVerificationGracePeriodDays = 30
	})
	seed, err := seedRuntimeSettings(ctx, cfg, bundle.Settings())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}

	if !reflect.DeepEqual(seed.kept, []string{"runtimeSettings.require2fa"}) {
		t.Errorf("kept = %v, want the key the administrator had already set", seed.kept)
	}
	if !reflect.DeepEqual(seed.seeded, []string{"runtimeSettings.lazyEmailVerificationGracePeriodDays"}) {
		t.Errorf("seeded = %v, want only the key the store did not hold", seed.seeded)
	}

	got, err := bundle.Settings().GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Require2FA == nil || *got.Require2FA {
		t.Errorf("require2FA = %v, want the administrator's false: a cold start must not undo a runtime edit", got.Require2FA)
	}
	if got.LazyEmailVerificationGracePeriodDays == nil || *got.LazyEmailVerificationGracePeriodDays != 30 {
		t.Errorf("grace period = %v, want the declared 30", got.LazyEmailVerificationGracePeriodDays)
	}

	// And it is per key rather than per document: a second cold start over the
	// same store writes nothing at all, because every declared key is now held.
	again, err := seedRuntimeSettings(ctx, cfg, bundle.Settings())
	if err != nil {
		t.Fatalf("second seed: %v", err)
	}
	if len(again.seeded) != 0 {
		t.Errorf("the second cold start seeded %v, want nothing", again.seeded)
	}
}

// A key the document leaves at its schema default is not seeded at all, so a
// seed added to the document later is not inert on arrival: the store has no
// value for it yet, and the next cold start writes it.
func TestRuntimeSettingsSeedIgnoresUndeclaredKeys(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bundle := newMemoryStoreBundle()

	// Only require2fa is moved off its default; the grace period keeps the
	// schema's 7 and enabledWebhookActions is absent.
	declaring := settingsCfg(func(c *config.Config) { c.RuntimeSettings.Require2FA = true })
	if _, err := seedRuntimeSettings(ctx, declaring, bundle.Settings()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := bundle.Settings().GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Require2FA == nil || !*got.Require2FA {
		t.Errorf("require2FA = %v, want the declared true", got.Require2FA)
	}
	if got.LazyEmailVerificationGracePeriodDays != nil {
		t.Errorf("grace period = %v, want absent: the document left it at the schema default and a default is not a declaration",
			got.LazyEmailVerificationGracePeriodDays)
	}
	if got.EnabledWebhookActions != nil {
		t.Errorf("enabledWebhookActions = %v, want absent", got.EnabledWebhookActions)
	}

	// The document gains the key later. Because nothing was written for it, the
	// next cold start applies it.
	later := settingsCfg(func(c *config.Config) {
		c.RuntimeSettings.Require2FA = true
		c.RuntimeSettings.LazyEmailVerificationGracePeriodDays = 21
	})
	seed, err := seedRuntimeSettings(ctx, later, bundle.Settings())
	if err != nil {
		t.Fatalf("later seed: %v", err)
	}
	if !reflect.DeepEqual(seed.seeded, []string{"runtimeSettings.lazyEmailVerificationGracePeriodDays"}) {
		t.Errorf("seeded = %v, want the newly declared key", seed.seeded)
	}
	if got, err = bundle.Settings().GetSettings(ctx); err != nil {
		t.Fatal(err)
	} else if got.LazyEmailVerificationGracePeriodDays == nil || *got.LazyEmailVerificationGracePeriodDays != 21 {
		t.Errorf("grace period = %v, want the newly declared 21", got.LazyEmailVerificationGracePeriodDays)
	}
}

// With nothing declared the seed does no I/O at all: there is no document to
// compare against, so the read that would compare it is not worth a cold start.
func TestRuntimeSettingsSeedWithNothingDeclaredTouchesNothing(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	store := &countingSettingsStore{SettingsStore: auth.NewMemorySettingsStore()}
	seed, err := seedRuntimeSettings(ctx, settingsCfg(nil), store)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if len(seed.seeded) != 0 || len(seed.kept) != 0 {
		t.Errorf("seed = %+v, want nothing", seed)
	}
	if store.gets != 0 || store.updates != 0 {
		t.Errorf("the seed made %d reads and %d writes for a document that declares nothing", store.gets, store.updates)
	}
}

// An explicitly empty enabledWebhookActions is a declaration, not an absence:
// it is the administrator switching every inbound-webhook action off, and the
// core keeps nil and empty apart all the way to the stored document. A seed that
// treated it as "unset" would leave the allowlist open.
func TestRuntimeSettingsClearedWebhookAllowlistIsADeclaredSeed(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	bundle := newMemoryStoreBundle()

	cfg := settingsCfg(func(c *config.Config) { c.RuntimeSettings.EnabledWebhookActions = []string{} })
	seed, err := seedRuntimeSettings(ctx, cfg, bundle.Settings())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !reflect.DeepEqual(seed.seeded, []string{"runtimeSettings.enabledWebhookActions"}) {
		t.Fatalf("seeded = %v, want the explicitly empty allowlist", seed.seeded)
	}
	got, err := bundle.Settings().GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.EnabledWebhookActions == nil {
		t.Fatal("the cleared allowlist was seeded as absent, which reads as \"no allowlist\" rather than \"every action off\"")
	}
	if len(got.EnabledWebhookActions) != 0 {
		t.Errorf("enabledWebhookActions = %v, want empty", got.EnabledWebhookActions)
	}

	// The seeded slice must not alias the configuration, or a later reader of
	// cfg would see whatever the store did to it.
	list := []string{"user.created"}
	cfg2 := settingsCfg(func(c *config.Config) { c.RuntimeSettings.EnabledWebhookActions = list })
	fresh := newMemoryStoreBundle()
	if _, err := seedRuntimeSettings(ctx, cfg2, fresh.Settings()); err != nil {
		t.Fatal(err)
	}
	list[0] = "mutated through the config"
	stored, err := fresh.Settings().GetSettings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if stored.EnabledWebhookActions[0] != "user.created" {
		t.Error("the seed handed the store the configuration's own slice")
	}
}

// A driver with no settings store is a refused cold start, not a deployment that
// comes up and stops honouring require2FA. Same refusal, and the same reason, as
// emailOptions' for a driver with no template store.
func TestSettingsStoreRefusesADriverWithoutOne(t *testing.T) {
	t.Parallel()

	// A bare user store: it satisfies auth.UserStore and nothing else this
	// binary asserts for.
	_, err := settingsOptions(context.Background(), settingsCfg(nil), auth.NewMemoryUserStore(), discardLogger())
	if err == nil {
		t.Fatal("a cold start came up with stores.enable.settings on and no settings store behind it")
	}
	for _, want := range []string{"stores.enable.settings", "require2FA"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not mention %q:\n%v", want, err)
		}
	}
}

// With the store switched off nothing is wired, and that is not a degraded mode
// but the reference's own behaviour with no store passed: the settings check on
// /2fa/disable is skipped altogether.
func TestSettingsStoreOffWiresNothing(t *testing.T) {
	t.Parallel()

	cfg := settingsCfg(func(c *config.Config) { c.Stores.Enable.Settings = false })
	opts, err := settingsOptions(context.Background(), cfg, newMemoryStoreBundle(), discardLogger())
	if err != nil {
		t.Fatalf("settingsOptions: %v", err)
	}
	if len(opts) != 0 {
		t.Errorf("settingsOptions returned %d options with the store off, want none", len(opts))
	}
}

// A settings store that cannot be reached at cold start is a failed init in
// every environment, unlike a templates directory that cannot be read.
//
// The asymmetry is deliberate: unreadable templates cost the deployment its
// custom mail bodies and the built-ins render, while an unreachable settings
// store makes the core fail /2fa/disable closed with a 500 on every call. Coming
// up would be pretending.
func TestUnreachableSettingsStoreRefusesTheColdStart(t *testing.T) {
	t.Parallel()

	cfg := settingsCfg(func(c *config.Config) { c.RuntimeSettings.Require2FA = true })
	for _, environment := range []string{config.EnvironmentDevelopment, config.EnvironmentProduction} {
		cfg.Deployment.Environment = environment
		users := settingsStoreStub{UserStore: auth.NewMemoryUserStore(), settings: failingSettingsStore{}}
		_, err := settingsOptions(context.Background(), cfg, users, discardLogger())
		if err == nil {
			t.Fatalf("%s: a cold start came up against a settings store it could not read", environment)
		}
		if !strings.Contains(err.Error(), "runtimeSettings") {
			t.Errorf("%s: the error does not name the block:\n%v", environment, err)
		}
	}
}

// TestRuntimeSettingsKnobGaps: the keys that reach the store and are then read
// by nothing this build mounts are reported, and the one the core does act on is
// not — a report that cried wolf about require2FA would send an operator to
// remove the one setting that is in force.
func TestRuntimeSettingsKnobGaps(t *testing.T) {
	t.Parallel()

	cfg := settingsCfg(func(c *config.Config) {
		c.RuntimeSettings.Require2FA = true
		c.RuntimeSettings.EnabledWebhookActions = []string{"user.created"}
		c.RuntimeSettings.LazyEmailVerificationGracePeriodDays = 30
	})
	paths := map[string]bool{}
	for _, g := range unwiredKnobs(cfg) {
		paths[g.Path] = true
		if g.Problem == "" || g.Remedy == "" {
			t.Errorf("gap %s has an empty problem or remedy", g.Path)
		}
	}
	for _, want := range []string{
		"runtimeSettings.enabledWebhookActions",
		"runtimeSettings.lazyEmailVerificationGracePeriodDays",
	} {
		if !paths[want] {
			t.Errorf("unwiredKnobs did not report %s, so a seeded key nothing reads is silently inert", want)
		}
	}
	if paths["runtimeSettings.require2fa"] {
		t.Error("unwiredKnobs reported runtimeSettings.require2fa, which POST /2fa/disable does honour")
	}

	// D9d: with the inbound route mounted the allowlist has its reader, and
	// reporting it would send an operator to remove the list the route
	// intersects with every webhook's allowedActions.
	mounted := settingsCfg(func(c *config.Config) {
		c.RuntimeSettings.EnabledWebhookActions = []string{"user.created"}
		c.Tools.Enabled = true
		c.Tools.InboundWebhooks.Enabled = true
		c.Tools.InboundWebhooks.ScriptRunnerFunction = "stack-script-runner"
	})
	for _, g := range unwiredKnobs(mounted) {
		if g.Path == "runtimeSettings.enabledWebhookActions" {
			t.Error("unwiredKnobs reported runtimeSettings.enabledWebhookActions with the inbound route mounted")
		}
	}

	// Undeclared keys are not reported: the warning is about what the operator
	// set, and a line about a default nobody wrote is noise.
	for _, g := range unwiredKnobs(settingsCfg(nil)) {
		if strings.HasPrefix(g.Path, "runtimeSettings.") {
			t.Errorf("unwiredKnobs reported %s, which was never configured", g.Path)
		}
	}
}

// TestDynamoDBStoreSatisfiesTheSettingsStore pins the third capability the core
// does not discover by type assertion. Config.Settings is an ordinary field set
// by auth.WithSettingsStore, so a store that drifted out of shape would not fail
// to build: the deployment would simply stop consulting require2FA, and
// /2fa/disable would start answering 200 where it used to answer 403.
func TestDynamoDBStoreSatisfiesTheSettingsStore(t *testing.T) {
	t.Parallel()
	store, err := ddbstore.New(stubDynamoAPI{}, ddbstore.Options{TableName: "unused", Logger: discardLogger()})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	if !asserts[auth.SettingsStore](store) {
		t.Fatal("*dynamodb.Store does not satisfy auth.SettingsStore, so auth.WithSettingsStore could never receive it")
	}
	if !asserts[settingsStoreProvider](store) {
		t.Fatal("*dynamodb.Store does not satisfy settingsStoreProvider, so the composition root could never find it")
	}
	if store.Settings() != auth.SettingsStore(store) {
		t.Fatal("Settings() returned something other than the store itself; the methods are meant to be on *Store")
	}
	// The development driver must not offer a narrower set than the production
	// one, or a stack would behave differently on the way to production.
	if !asserts[settingsStoreProvider](newMemoryStoreBundle()) {
		t.Fatal("memoryStoreBundle does not satisfy settingsStoreProvider")
	}
}

// settingsStoreStub pairs an arbitrary settings store with a user store, for the
// cases that need a provider the memory bundle cannot express.
type settingsStoreStub struct {
	auth.UserStore
	settings auth.SettingsStore
}

func (s settingsStoreStub) Settings() auth.SettingsStore { return s.settings }

// failingSettingsStore is unreachable, the shape a cold start sees when the
// table is not there or the execution role cannot read it.
type failingSettingsStore struct{}

func (failingSettingsStore) GetSettings(context.Context) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errSettingsStoreUnreachable
}

func (failingSettingsStore) UpdateSettings(context.Context, auth.AuthSettings) (auth.AuthSettings, error) {
	return auth.AuthSettings{}, errSettingsStoreUnreachable
}

var errSettingsStoreUnreachable = errStub("settings store is unreachable")

type errStub string

func (e errStub) Error() string { return string(e) }

// countingSettingsStore counts the calls the seed makes, so "does no I/O" is an
// assertion rather than a claim.
type countingSettingsStore struct {
	auth.SettingsStore
	gets, updates int
}

func (c *countingSettingsStore) GetSettings(ctx context.Context) (auth.AuthSettings, error) {
	c.gets++
	return c.SettingsStore.GetSettings(ctx)
}

func (c *countingSettingsStore) UpdateSettings(ctx context.Context, patch auth.AuthSettings) (auth.AuthSettings, error) {
	c.updates++
	return c.SettingsStore.UpdateSettings(ctx, patch)
}

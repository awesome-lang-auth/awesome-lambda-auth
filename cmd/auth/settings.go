package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// Runtime settings: the one layer of this product's configuration that an
// administrator changes without a deployment. This is the `runtimeSettings`
// block of the schema (§1.19) and `stores.enable.settings`, which
// internal/config/phases.go no longer refuses.
//
// ── what the settings store is, and what reads it ────────────────────────────
//
// The store is auth.SettingsStore (awesome-go-auth settings_store.go), the
// reference's ISettingsStore: one global document the admin Control panel
// patches (settings-store.interface.ts:28-40). It is optional to the core, and
// its absence is not a degraded mode but a different one — with no store the
// settings check on /2fa/disable is skipped altogether (auth.router.ts:890), so
// a deployment either has one or the question is never asked.
//
// Exactly one key is read by anything mounted today: require2FA, by
// POST <prefix>/2fa/disable, which answers 403 2FA_REQUIRED when it is true
// (Auth.TwoFactorPolicy). The rest is stored and handed back: the reference's
// GET /ui/config reads the ui block and its tools router reads
// enabledWebhookActions, and neither of those surfaces is mounted here yet;
// requireEmailVerification, emailVerificationMode and
// lazyEmailVerificationGracePeriodDays are read by nothing anywhere, in the
// reference included, which §1.19 records as two [MISMATCH] rows and the core's
// settings_store.go reproduces rather than fixes. unwiredKnobs is where an
// operator is told which of the keys they seeded this build can act on.
//
// ── the seed, and why it never overwrites ────────────────────────────────────
//
// config.RuntimeSettings holds the boot-time seeds, and its own doc comment
// states the rule this file implements: "The settings store wins over these once
// the stack is up; they are listed here so a fresh deployment starts from a
// declared state instead of whatever the store happens to contain."
//
// A Lambda has no deploy step that runs code, so cold start is the only moment a
// declared seed can be applied — the same position email.templatesDir is in. It
// is also the moment that recurs: a Lambda cold-starts constantly, on a scale-out
// and after every idle period, so a seed that overwrote would not revert an
// administrator's toggle at the next deployment but at an unpredictable time in
// between, which is worse than the templates case rather than equal to it. So
// the seed only fills keys the store does not already hold, and it is registered
// as the product deviation runtime-settings-seed-only-fills-absent-keys
// (deviations.go), the sibling of templates-dir-only-seeds-absent-ids.
//
// Two things about the seed are decided differently from that sibling, and both
// follow from settings being one document rather than a directory of them.
//
// **Per key, not per item.** A template is an item and "the store already holds
// this id" is a question about an item. Here the whole document is one item, so
// the equivalent question would freeze every key on the first cold start —
// including the keys no block has a knob for yet. AuthSettings answers it at the
// right granularity for free: a nil field is absent, so the seed builds a patch
// carrying only the keys the store answered nil for, and MergeSettings leaves
// the rest untouched.
//
// **Only keys the document actually declares.** runtimeSettings.require2fa is a
// bool and lazyEmailVerificationGracePeriodDays an int with a default of 7, so
// every document "has" them whether or not anyone wrote them. Seeding the
// schema's defaults into a runtime-mutable store would not be starting from a
// declared state, it would be inventing one — and worse, it would make a seed
// added to the document *later* inert on arrival, because by then the store
// would hold a key nobody ever asked for. Declared means "moved away from the
// default", which is the same test internal/config uses to decide whether the
// block was configured at all (domainConfigured) and whether it requires a store
// (checkStoreRequirements). The three agreeing is the point: the block that is
// configured is the block that needs the store and the block that is seeded.
//
// One key §1.19 lists a boot seed for is deliberately not seeded here:
// emailVerificationMode, whose reference seed is email.verification.mode. That
// key is one of §1.19's two [MISMATCH] rows — nothing reads it, in the reference
// or here — and email.verification.mode is already reported by unwiredKnobs as a
// knob the imported core exposes no option for. Copying it into a store nothing
// reads would give the same non-effect a second place to be discovered from,
// and the value that does decide a login here is the static one. If the admin
// surface needs to show an effective mode, that is where it comes from.

// settingsStoreProvider is what this binary needs from a store to back
// stores.enable.settings: a SettingsStore view, handed to the core through
// auth.WithSettingsStore.
//
// A structural assertion on the user store rather than a wider StoreFactory
// signature, for the reasons oauthStoreProvider, templateStoreProvider and
// authCodeStoreProvider give: the composition root is the only place that knows
// which driver is in play, and a driver that lacks the view refuses to start
// rather than advertising a store its routes cannot reach.
type settingsStoreProvider interface {
	Settings() auth.SettingsStore
}

// settingsOptions wires the settings store and seeds it from runtimeSettings.
//
// It fills the settings slot of coreOptionSets, after idpOptions. It can refuse
// twice: for a driver with no settings store, exactly as emailOptions refuses
// for one with no template store, and for a store that cannot be read or
// written at cold start.
//
// That second refusal is stricter than emailOptions', which downgrades a
// templatesDir failure to a warning outside production. The cases are not
// alike. A templates directory that cannot be read costs the deployment its
// custom mail bodies and the built-ins render; a settings store that cannot be
// reached is not a degraded feature but a broken one — the core fails
// /2fa/disable closed with a 500 on every call rather than reading a require2FA
// it cannot see — so coming up would be pretending, and an init failure the
// deployment can see is the honest answer in every environment.
func settingsOptions(ctx context.Context, cfg *config.Config, users auth.UserStore, log *slog.Logger) ([]auth.Option, error) {
	if !cfg.Stores.Enable.Settings {
		// No store, and therefore no runtime-mutable layer: the core skips the
		// settings check on /2fa/disable entirely, which is the reference's own
		// behaviour with no store passed. Validation has already refused a
		// document that declares a seed without the store to put it in
		// (internal/config RS, checkStoreRequirements), so there is nothing here
		// that could be silently dropped.
		log.Info("runtime settings not wired",
			slog.String("path", "stores.enable.settings"),
			slog.String("effect", "no settings store, so POST /2fa/disable never consults one and nothing is runtime-mutable"))
		return nil, nil
	}

	provider, ok := users.(settingsStoreProvider)
	if !ok || provider.Settings() == nil {
		return nil, fmt.Errorf(
			"config: refusing to start: stores.enable.settings is on, but the %s driver does not provide a settings store in this build, "+
				"so every runtime setting an administrator saved would be unreachable and POST /2fa/disable would stop honouring require2FA "+
				"-- turn it off until the driver grows one",
			cfg.Stores.Driver)
	}
	store := provider.Settings()

	seed, err := seedRuntimeSettings(ctx, cfg, store)
	if err != nil {
		return nil, err
	}

	log.Info("runtime settings wired",
		slog.String("settingsStore", cfg.Stores.Driver),
		slog.String("seeded", strings.Join(seed.seeded, ",")),
		slog.String("keptFromTheStore", strings.Join(seed.kept, ",")),
		slog.String("readByThisBuild", "require2FA (POST /2fa/disable); every other key is stored and served, see unwiredKnobs"))

	return []auth.Option{auth.WithSettingsStore(store)}, nil
}

// settingsSeed reports what the seed did, key by key: seeded is what the
// document declared and the store did not hold, kept is what the document
// declared and the store already held — a runtime edit the seed left alone.
type settingsSeed struct {
	seeded []string
	kept   []string
}

// seedRuntimeSettings applies the declared seeds the store does not already
// hold. See the file header for why it is per key, why it never overwrites, and
// why an undeclared key is not seeded at its default.
//
// With nothing declared it does no I/O at all: there is no document to compare
// against, so the read that would compare it is not worth a cold start.
func seedRuntimeSettings(ctx context.Context, cfg *config.Config, store auth.SettingsStore) (settingsSeed, error) {
	var seed settingsSeed

	declared := declaredRuntimeSettings(cfg)
	if len(declared) == 0 {
		return seed, nil
	}

	current, err := store.GetSettings(ctx)
	if err != nil {
		return seed, fmt.Errorf("runtimeSettings: settings store: %w", err)
	}

	var patch auth.AuthSettings
	for _, key := range declared {
		if key.stored(current) {
			seed.kept = append(seed.kept, key.path)
			continue
		}
		key.apply(&patch)
		seed.seeded = append(seed.seeded, key.path)
	}
	if len(seed.seeded) == 0 {
		return seed, nil
	}
	if _, err := store.UpdateSettings(ctx, patch); err != nil {
		return settingsSeed{}, fmt.Errorf("runtimeSettings: settings store: %w", err)
	}
	return seed, nil
}

// runtimeSettingsKey is one declared seed: the path it is written at, the test
// for the store already holding it, and how it goes into the patch.
//
// A table rather than three hand-written branches because the three have to
// agree with each other and with unwiredKnobs about what "declared" means, and
// because a fourth key added to config.RuntimeSettings is then one row instead
// of three places to remember.
type runtimeSettingsKey struct {
	path   string
	stored func(auth.AuthSettings) bool
	apply  func(*auth.AuthSettings)
}

// declaredRuntimeSettings returns the runtimeSettings keys this document
// actually declares, in schema order.
//
// Declared is "differs from the schema default", for the reason the file header
// gives. It is also exactly what internal/config's checkStoreRequirements asks
// before insisting on stores.enable.settings, so a declared seed always has
// somewhere to go.
func declaredRuntimeSettings(cfg *config.Config) []runtimeSettingsKey {
	defaults := config.Defaults().RuntimeSettings
	rs := cfg.RuntimeSettings

	var keys []runtimeSettingsKey
	if rs.Require2FA != defaults.Require2FA {
		v := rs.Require2FA
		keys = append(keys, runtimeSettingsKey{
			path:   "runtimeSettings.require2fa",
			stored: func(s auth.AuthSettings) bool { return s.Require2FA != nil },
			apply:  func(p *auth.AuthSettings) { p.Require2FA = &v },
		})
	}
	// Non-nil rather than non-empty: an explicit empty list is the administrator
	// switching every inbound-webhook action off, which is a different declared
	// state from saying nothing, and the core keeps that difference alive all the
	// way to the stored item (AuthSettings.MarshalJSON, and the store's L
	// encoding).
	if rs.EnabledWebhookActions != nil {
		// make+copy rather than append to a nil slice: append with nothing to
		// append returns nil, which would turn the declared empty list back into
		// "unset" — the one distinction this key exists to carry.
		v := make([]string, len(rs.EnabledWebhookActions))
		copy(v, rs.EnabledWebhookActions)
		keys = append(keys, runtimeSettingsKey{
			path:   "runtimeSettings.enabledWebhookActions",
			stored: func(s auth.AuthSettings) bool { return s.EnabledWebhookActions != nil },
			apply:  func(p *auth.AuthSettings) { p.EnabledWebhookActions = v },
		})
	}
	if rs.LazyEmailVerificationGracePeriodDays != defaults.LazyEmailVerificationGracePeriodDays {
		v := rs.LazyEmailVerificationGracePeriodDays
		keys = append(keys, runtimeSettingsKey{
			path:   "runtimeSettings.lazyEmailVerificationGracePeriodDays",
			stored: func(s auth.AuthSettings) bool { return s.LazyEmailVerificationGracePeriodDays != nil },
			apply:  func(p *auth.AuthSettings) { p.LazyEmailVerificationGracePeriodDays = &v },
		})
	}
	return keys
}

// runtimeSettingsKnobGaps reports the declared seeds that reach the store and
// are then read by nothing this build mounts.
//
// They are not dropped and not ignored: the seed writes them, the store keeps
// them, and the admin surface will serve them. What no route does is *act* on
// them, and the difference between "stored" and "in force" is precisely what an
// operator cannot see from outside — which is the whole reason this report
// exists. require2FA is absent from the list because the core does act on it,
// on POST /2fa/disable.
//
// The remedy is "leave it set" in both cases, for the reason deliveryKnobGaps
// gives for the mailer credentials: the same document is deployed to other ports
// in the family, and both keys become live here without the document changing.
func runtimeSettingsKnobGaps(cfg *config.Config) []knobGap {
	defaults := config.Defaults().RuntimeSettings
	rs := cfg.RuntimeSettings
	var gaps []knobGap

	if rs.EnabledWebhookActions != nil {
		gaps = append(gaps, knobGap{
			Path: "runtimeSettings.enabledWebhookActions",
			Problem: "this is the global allowlist the inbound-webhook sandbox intersects with each webhook's own allowedActions " +
				"(tools.router.ts:261-266), and this build never mounts that one route -- POST <tools>/webhook/{provider} is refused at " +
				"cold start until a script runner exists (RS-15, deviation inbound-webhooks-are-refused-without-a-runner), whether or " +
				"not the rest of the tools router is mounted -- so the list is stored and read by nothing",
			Remedy: "leave it set -- it is seeded into the settings store and becomes live when the inbound-webhook runner lands (D9d), " +
				"which retires RS-15; nothing in this build reads it today",
		})
	}
	if rs.LazyEmailVerificationGracePeriodDays != defaults.LazyEmailVerificationGracePeriodDays {
		gaps = append(gaps, knobGap{
			Path: "runtimeSettings.lazyEmailVerificationGracePeriodDays",
			Problem: "nothing computes an email-verification deadline from this, here or in the reference: the reference's admin UI " +
				"displays it and its server never reads it (config-schema.md §1.19 [MISMATCH]), and the imported core stores it " +
				"and hands it back unchanged",
			Remedy: "leave it set -- it is seeded into the settings store so the admin surface shows a declared value rather than a " +
				"blank; do not expect a login to be refused on it, in this port or in the reference",
		})
	}
	return gaps
}

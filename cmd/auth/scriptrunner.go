package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// D9d: the inbound-webhook script runner, as the auth function wires it.
//
// The core runs no inbound-webhook script in process and fails closed without
// an InboundScriptRunner — 400, nothing tracked, and the provider redelivers
// (tools_webhook.go, the deviation inbound-webhook-script-runs-out-of-process).
// D9a left ToolsOptions.ScriptRunner nil and RS-15 refused the route for that
// reason. This block fills the field with awsintegration.LambdaScriptRunner,
// which invokes cmd/script-runner synchronously, and RS-15 now refuses only a
// document that mounts the route without naming that function
// (tools.inboundWebhooks.scriptRunnerFunction).
//
// The runner is a separate Lambda for the reason the whole block exists: the
// repository owner decided on 2026-09-12 that no JavaScript engine enters this
// process, which holds the signing keys, the session store and the password
// hashes. The runner holds the engine, and its IAM role — logging only, plus
// whatever an action added to its manifest needs — is the sandbox. This binary
// links no engine at all; TestTheAuthBinaryLinksNoJavaScriptEngine walks the
// import graph and fails the day it does. What crosses is exactly what the
// core's seam carries: the provider, the webhook id, the script, the raw body
// and the resolved allowlist — never the webhook secret, the settings store or
// the request headers.

// newScriptRunner returns the InboundScriptRunner the tools router is handed,
// or nil when the inbound route has nothing to run.
//
// Nil in three cases, each of which leaves the core's own behaviour standing:
// the tools block is off (nothing is mounted), inbound webhooks are off (the
// route is not mounted, DisableWebhook), or — unreachable through the loader,
// which RS-15 guarantees — no function is named. In that last case the core
// fails closed on a row with a script, which is the behaviour RS-15 exists to
// keep off a deployed wire, and nothing here pretends otherwise.
//
// injected is Options.ScriptRunner. Like Mail and SMS it decides only which
// implementation is used, never whether one is wired: a test cannot exercise a
// composition the binary would not build.
func newScriptRunner(cfg *config.Config, injected auth.InboundScriptRunner) (auth.InboundScriptRunner, error) {
	ib := cfg.Tools.InboundWebhooks
	if !cfg.Tools.Enabled || !ib.Enabled || ib.ScriptRunnerFunction == "" {
		return nil, nil
	}
	if injected != nil {
		return injected, nil
	}
	return awsintegration.NewLambdaScriptRunner(awsintegration.LambdaScriptRunnerOptions{
		FunctionName: ib.ScriptRunnerFunction,
	})
}

// logScriptRunnerSurface says, at cold start, whether the inbound route is
// mounted and where its scripts run. It is its own line rather than an
// attribute of "tools surface mounted" so that the three transport blocks
// (D9b, D9c, D9d) each own one line of the cold-start log.
func logScriptRunnerSurface(cfg *config.Config, tw *toolsWiring, log *slog.Logger) {
	if tw == nil {
		return
	}
	mount := toolsPath(cfg)
	if !cfg.Tools.InboundWebhooks.Enabled {
		log.Info("inbound webhooks not mounted",
			slog.String("path", "tools.inboundWebhooks.enabled"),
			slog.String("effect", "POST "+mount+"/webhook/{provider} answers 404"))
		return
	}
	log.Info("inbound webhooks mounted",
		slog.String("route", "POST "+mount+"/webhook/{provider}"),
		slog.String("scriptRunner", cfg.Tools.InboundWebhooks.ScriptRunnerFunction),
		slog.Int("scriptTimeoutMs", cfg.Tools.InboundWebhooks.ScriptTimeoutMs),
		slog.String("sandbox", "the runner function's IAM role: a script reaches only what its manifest's actions call and that role allows (docs/inbound-webhooks.md)"),
		slog.String("unauthenticated", "the route has no guard and verifies no provider signature, as the reference's does not (tools.router.ts:251); what a caller can do is run the stored script for the provider it names"))
}

// scriptRunnerKnobGaps reports the two knobs of the inbound route that only
// the mounted route reads, when they are set and nothing reads them: with the
// tools block or the inbound route off, no webhook ever reaches the runner.
// scriptRunnerFunction is reported whenever it is set; scriptTimeoutMs only
// when it differs from its default, because every document carries the
// default and a default is not a decision (the rule runtimeSettingsKnobGaps
// applies to lazyEmailVerificationGracePeriodDays). Harmless, and the way a
// document is staged, so reported rather than refused — the rule
// toolsKnobGaps applies to the tools stores.
func scriptRunnerKnobGaps(cfg *config.Config) []knobGap {
	ib := cfg.Tools.InboundWebhooks
	if cfg.Tools.Enabled && ib.Enabled {
		return nil
	}
	var gaps []knobGap
	if ib.ScriptRunnerFunction != "" {
		gaps = append(gaps, knobGap{
			Path:    "tools.inboundWebhooks.scriptRunnerFunction",
			Problem: "a script runner is named and nothing invokes it: the inbound route is mounted only with tools.enabled and tools.inboundWebhooks.enabled both on",
			Remedy:  "turn both on to run inbound-webhook scripts, or leave it set for the deploy that does; until then it costs nothing and does nothing",
		})
	}
	if ib.ScriptTimeoutMs != config.Defaults().Tools.InboundWebhooks.ScriptTimeoutMs {
		gaps = append(gaps, knobGap{
			Path:    "tools.inboundWebhooks.scriptTimeoutMs",
			Problem: "the script deadline is set and nothing runs a script: it bounds the inbound route's runs, and that route is mounted only with tools.enabled and tools.inboundWebhooks.enabled both on",
			Remedy:  "turn both on to run inbound-webhook scripts, or leave it set for the deploy that does; until then it is read by nothing",
		})
	}
	return gaps
}

// inboundWebhookScope is the counter scope of the inbound-webhook limiter, a
// sibling of adminLoginScope for the same reason: a name the shared counter
// keys on that no document can spell.
const inboundWebhookScope = "inbound-webhook"

// newInboundWebhookLimiter puts the rateLimit block in front of
// POST <tools>/webhook/{provider}, as a middleware over the mux — the way
// newAdminLoginLimiter covers the console login — because the core mounts the
// tools router bare, outside the adapter's RateLimiter slot, and the route has
// no guard and checks no signature (core tools_webhook.go, "no rate limiter on
// this router at all"). It registers no pattern and matches one method on one
// path shape, so the adapter still owns the route.
//
// ── why this route, of all the tools routes ─────────────────────────────────
//
// It is the one whose cost a stranger chooses. Every request naming a
// provider whose row has a script invokes the runner synchronously: two
// execution environments held for the length of the script, at a rate the
// caller picks (docs/cost-model.md §3.3). ScriptRunnerReservedConcurrency is
// the hard cap on what that can spend; this is the budget per caller in
// front of it, so that one address cannot keep the cap full on its own.
//
// ── the subject is the client address and the provider ───────────────────────
//
// The body is the provider's, not a credential flow's, so keyBy has nothing
// to read there and the address is the subject under either keyBy, as on the
// promote route. The provider is part of it so that one provider's burst does
// not spend another's budget from the same address — a billing provider and a
// CRM behind one egress are two senders. It enters as a short hash, because
// the path segment is the caller's to choose and the store bounds the subject
// (maxRateLimitSubjectLen). An event with no source address is passed
// through, as rateLimitTier.serve does for every route.
//
// ── what it costs a legitimate provider ──────────────────────────────────────
//
// The budget is rateLimit.max per rateLimit.windowSeconds — ten a minute by
// default — per address and provider. A provider that sends more than that
// from one address in one window is answered the pinned 429 and, like every
// provider for every non-2xx, redelivers later; nothing is lost, it arrives
// late. A deployment whose provider is that busy raises rateLimit.max, which
// is shared with the credential flows, or turns rateLimit off — and then the
// reservation alone caps the spend. Registered with the other 429s
// (rate-limited-routes-answer-429), since the reference's route never answers
// one.
//
// Identity when rateLimit is off or the route is not mounted.
func newInboundWebhookLimiter(cfg *config.Config, counter rateLimitCounter, log *slog.Logger) func(http.Handler) http.Handler {
	identity := func(next http.Handler) http.Handler { return next }
	if !cfg.RateLimit.Enabled || !cfg.Tools.Enabled || !cfg.Tools.InboundWebhooks.Enabled {
		return identity
	}
	tier := newRateLimitTier(cfg.RateLimit.Max, time.Duration(cfg.RateLimit.WindowSeconds)*time.Second, counter, log)
	prefix := toolsPath(cfg) + "/webhook/"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			provider, ok := strings.CutPrefix(r.URL.Path, prefix)
			if r.Method != http.MethodPost || !ok || provider == "" || strings.Contains(provider, "/") {
				next.ServeHTTP(w, r)
				return
			}
			tier.serve(w, r, inboundWebhookScope, inboundWebhookSubject(r, provider), next)
		})
	}
}

// inboundWebhookSubject is the client address and a 64-bit hash of the
// provider, or "" — pass through — with no address.
func inboundWebhookSubject(r *http.Request, provider string) string {
	addr := clientAddress(r)
	if addr == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(provider))
	return addr + "|" + hex.EncodeToString(sum[:8])
}

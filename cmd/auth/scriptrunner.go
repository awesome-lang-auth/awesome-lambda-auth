package main

import (
	"log/slog"

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

// scriptRunnerKnobGaps reports tools.inboundWebhooks.scriptRunnerFunction when
// it is set and nothing reads it: with the tools block or the inbound route
// off, no webhook ever reaches the runner. Harmless, and the way a document is
// staged, so reported rather than refused — the rule toolsKnobGaps applies to
// the tools stores.
func scriptRunnerKnobGaps(cfg *config.Config) []knobGap {
	ib := cfg.Tools.InboundWebhooks
	if ib.ScriptRunnerFunction == "" || (cfg.Tools.Enabled && ib.Enabled) {
		return nil
	}
	return []knobGap{{
		Path:    "tools.inboundWebhooks.scriptRunnerFunction",
		Problem: "a script runner is named and nothing invokes it: the inbound route is mounted only with tools.enabled and tools.inboundWebhooks.enabled both on",
		Remedy:  "turn both on to run inbound-webhook scripts, or leave it set for the deploy that does; until then it costs nothing and does nothing",
	}}
}

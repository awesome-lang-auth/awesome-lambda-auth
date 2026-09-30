// Command script-runner is the Lambda that runs inbound-webhook scripts for
// awesome-lambda-auth (block D9d). It is the product's implementation of the
// core's InboundScriptRunner seam, reached by the auth function's
// LambdaScriptRunner (internal/integration/aws) with a synchronous Invoke.
//
// # The IAM role is the sandbox
//
// This binary holds a JavaScript engine (goja, internal/scriptrunner) and the
// auth function does not, by the repository owner's decision of 2026-09-12:
// administrator-authored script does not share an address space with the
// signing keys, the session store and the password hashes. What bounds a
// script is therefore not the engine, which only promises that a script has no
// primitive to reach anything with, but this function's execution role —
// infra/sam/template.yaml, ScriptRunnerRole — which grants writing this
// function's own log group and nothing else. No table, no secret, no key, no
// other function. An action (internal/scriptrunner, Shipped) is the one door
// out, and adding one means granting its IAM to that role in the same change.
//
// # What it reads at cold start
//
// One variable: AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT, for the reference's rule
// that the sandbox's console writes outside production and is silent in it
// (tools.router.ts:272-282, NODE_ENV). Unset is production, which is the
// product's own default (deviation production-by-default) and the quiet side.
// It reads no configuration document and no secret: there is none it needs,
// and a runner that could read one would widen what a compromised script
// could reach through a bug in this binary.
//
// # Failing
//
// The handler returns an error for a run that could not be completed — the
// deadline, a malformed request — and a Response for every run that could,
// including a script that threw. The Lambda service turns the error into
// FunctionError on the invoker's response, which the invoker maps to the
// core's refusal: 400, and the provider redelivers. See
// internal/scriptrunner/wire for why that is the one channel for it.
package main

import (
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"

	"github.com/nik2208/awesome-lambda-auth/internal/scriptrunner"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(slog.String("component", "cmd/script-runner"))

	runner, err := scriptrunner.New(scriptrunner.Options{
		Manifest: scriptrunner.Shipped(),
		Console:  consoleEnabled(os.LookupEnv),
		Log:      log,
	})
	if err != nil {
		// A manifest that does not validate is a build defect; failing the
		// init makes it a failed deployment rather than a failed webhook.
		log.Error("script runner cannot start", slog.String("error", err.Error()))
		os.Exit(1)
	}
	lambda.Start(runner.Run)
}

// consoleEnabled is the reference's `process.env['NODE_ENV'] !== 'production'`
// read from this product's own spelling of the same fact. Unset is production.
func consoleEnabled(lookup func(string) (string, bool)) bool {
	env, ok := lookup("AWESOME_AUTH_DEPLOYMENT_ENVIRONMENT")
	return ok && env != "" && env != "production"
}

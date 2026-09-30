// Command auth is the Lambda entrypoint for awesome-lambda-auth.
//
// It composes four things and adds nothing of its own to the auth surface: the
// declarative configuration (internal/config), the DynamoDB stores
// (internal/store/dynamodb), the imported auth core
// (github.com/nik2208/awesome-go-auth and its net/http adapter) and the event
// normalisation layer (internal/lambdahttp).
//
// # Cold start versus request
//
// Everything expensive happens once, in New, before lambda.Start is reached:
// reading and validating the configuration document, resolving secrets,
// building the AWS client and its connection pool, constructing the store, the
// auth core and the routing table. The per-invocation path attaches a request
// id and dispatches. See the App type for why that split is a correctness
// property and not only a performance one.
//
// # Failing to start
//
// A configuration the loader refuses aborts the init with a non-zero exit,
// which the Lambda service reports as an init failure. That is deliberate: a
// refuse-to-start rule that surfaced as a 500 per request would look like an
// outage instead of a bad deployment, and would keep serving the routes that
// happened not to touch the broken knob.
//
// # Routes
//
// The auth routes come entirely from the imported adapter — this binary must
// never add one, because a route that exists here and not in the other family
// ports is a wire divergence by construction. The only local route is
// GET /healthz, which answers from memory.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
)

func main() {
	// The logger is built before anything can fail, so that a cold-start
	// failure is reported in the same JSON shape as everything else. App builds
	// its own from the same inputs; this one exists only for the fatal path.
	log := newLogger(os.Stdout, logLevel(os.LookupEnv))

	ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
	defer cancel()

	app, err := New(ctx, Options{})
	if err != nil {
		fatal(log, err)
		return // unreachable: fatal exits. Present so the nil deref below cannot compile away.
	}

	// D9c: the SSE function is this composition with the Function URL
	// response-streaming contract instead of JSON in, JSON out (stream.go).
	if app.Streams() {
		log.Debug("starting streaming lambda handler", slog.String("component", "cmd/auth"), slog.String("entrypoint", entrypointStream))
		lambda.StartHandlerFunc(app.StreamHandler())
		return
	}

	log.Debug("starting lambda handler", slog.String("component", "cmd/auth"))
	lambda.Start(app.Handle)
}

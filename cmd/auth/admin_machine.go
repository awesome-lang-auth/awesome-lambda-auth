package main

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	"github.com/nik2208/awesome-lambda-auth/internal/lambdahttp"
)

// Machine access to the admin API: admin.machineAccess.iam.principals, mapped
// onto the core's AdminOptions.MachineAccess (core v0.14.0, deviation
// admin-machine-access-is-a-host-seam).
//
// ── what it is for ───────────────────────────────────────────────────────────
//
// A back-office service — an identity service that invites operators, deletes
// users, revokes sessions — has nothing to call the admin API with in the
// reference: the deprecated adminSecret is one shared bearer string with no
// identity behind it, and a session policy wants a person's account, with a
// password and a second factor the service has to keep in a vault and
// automate. The core's seam lets a host say "this request is that service" on
// a credential the host verified itself, and audits every grant as
// identity.admin.machine.access.
//
// ── what verifies the caller ─────────────────────────────────────────────────
//
// API Gateway does. On a route with AWS_IAM authorization it checks the SigV4
// signature and the caller's execute-api:Invoke permission before the function
// runs, and only then writes the caller into requestContext.authorizer.iam of
// the payload 2.0 event. Nothing a client sends can put a value there: the
// request context is the gateway's, not a header. iamCallerARN reads it back
// out of the event lambdahttp attached to the request context, and the
// principal list decides who among the verified callers is admitted.
//
// Only that shape is read. A REST API (payload 1.0) reports IAM callers in
// requestContext.identity, a Function URL in its own authorizer block, and an
// ALB in neither; none of them is what the SAM template routes here, and
// reading a second shape would be a second thing to get wrong for no
// deployment that exists. TestIAMCallerARNReadsTheHTTPAPIAuthorizerOnly pins
// the refusals.
//
// The SAM template gives the route an API of its own — AdminMachineApi, an
// HTTP API whose single route is ANY /admin/{proxy+} with AWS_IAM — rather
// than a route on the public API, for two reasons that are both about
// CloudFront: this stack's distribution sends every path to the public API, so
// a route there would be routed by it, and a public-API route under /admin
// would put the whole console behind IAM for the people who use it. The
// internal API is an origin of nothing (infra/sam
// TestAdminMachineApiIsNotACloudFrontOrigin).
//
// ── what it admits, and what it does not ─────────────────────────────────────
//
// A matched caller is admitted to every route behind the admin guard, with no
// token, cookie, CSRF pair, user-store read or policy evaluation — the core's
// contract for the seam — and the principal handed to the core, and so to the
// audit event, is the caller's own ARN, session name included, because that
// is what attributes the call. An unmatched caller, and every request without
// the IAM block, is left to the guard as if the seam were absent: on the
// public API that is the session policy, as before. A request a browser
// originated (an Origin header, or Sec-Fetch-Site other than none) is never
// offered to the function — the core's backstop.
//
// Two things it deliberately does not do. It does not exempt the request from
// http.originVerify: with the front-door check on, the machine caller sends
// the front door's header too, like every other caller, because the check is
// outermost by design and loosening it for one door is a decision for its
// owner, not a side effect of this one (config-reference §16.9, §19). And it
// grants nothing outside the admin mount: the IAM block on a request to
// <prefix>/me means nothing to the auth router, whose gate reads tokens.

// adminMachineAccess builds AdminOptions.MachineAccess out of
// admin.machineAccess.iam.principals, or nil when none is configured — which
// is the core's "no machine access", the reference's guard exactly.
//
// It is total and does no I/O, for the reason adminHTTPOptions is: the
// configuration loader has already refused a principal it cannot read, so the
// keys are computed once here and the request path is two map lookups.
func adminMachineAccess(cfg *config.Config) func(*http.Request) (string, bool) {
	if !cfg.Admin.MachineAccess.Enabled() {
		return nil
	}
	admitted := map[string]bool{}
	for _, arn := range cfg.Admin.MachineAccess.IAM.Principals {
		if key, ok := config.IAMPrincipalKey(arn); ok {
			admitted[key] = true
		}
	}
	if len(admitted) == 0 {
		return nil
	}
	return func(r *http.Request) (string, bool) {
		caller, ok := iamCallerARN(lambdahttp.EventFrom(r.Context()))
		if !ok {
			return "", false
		}
		key, ok := config.IAMPrincipalKey(caller)
		if !ok || !admitted[key] {
			return "", false
		}
		return caller, true
	}
}

// iamCallerARN reads requestContext.authorizer.iam.userArn out of an API
// Gateway HTTP API (payload 2.0) event, and nothing out of any other shape.
func iamCallerARN(event any) (string, bool) {
	var rc events.APIGatewayV2HTTPRequestContext
	switch e := event.(type) {
	case events.APIGatewayV2HTTPRequest:
		rc = e.RequestContext
	case *events.APIGatewayV2HTTPRequest:
		if e == nil {
			return "", false
		}
		rc = e.RequestContext
	default:
		return "", false
	}
	if rc.Authorizer == nil || rc.Authorizer.IAM == nil {
		return "", false
	}
	arn := strings.TrimSpace(rc.Authorizer.IAM.UserARN)
	return arn, arn != ""
}

// logAdminMachineAccess says at cold start who may call the admin API without
// a session, and how they get there. Nothing when the block is off.
func logAdminMachineAccess(cfg *config.Config, mount string, log *slog.Logger) {
	if !cfg.Admin.MachineAccess.Enabled() {
		return
	}
	front := "no front-door check is configured"
	if cfg.HTTP.OriginVerify.Enabled() {
		front = "http.originVerify is on, so a machine caller sends " + cfg.HTTP.OriginVerify.Header + " too, like every caller; without it the request is refused with a bare 403 before the guard"
	}
	log.Info("admin machine access",
		slog.String("path", "admin.machineAccess.iam.principals"),
		slog.String("principals", strings.Join(cfg.Admin.MachineAccess.IAM.Principals, ",")),
		slog.String("admits", "a caller API Gateway verified on an AWS_IAM route (requestContext.authorizer.iam of a payload 2.0 event) whose role or user is listed, to every route behind the guard under "+mount+", with no session, cookie or CSRF pair"),
		slog.String("audit", "each grant is identity.admin.machine.access on the event bus with tools.enabled, and a line of this log otherwise"),
		slog.String("frontDoor", front))
}

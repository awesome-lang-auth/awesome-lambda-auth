package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	"github.com/nik2208/awesome-lambda-auth/internal/lambdahttp"
)

// admin.machineAccess.iam.principals (admin_machine.go): a caller API Gateway
// verified on an AWS_IAM route, matched against the list, admitted to the
// guarded admin routes ahead of the session policy.

const (
	// testMachineRole is the role the identity service runs as, written the
	// way an operator writes it: with a path, which the caller ARN API
	// Gateway reports does not carry.
	testMachineRole = "arn:aws:iam::123456789012:role/service/identity-service"
	// testMachineCaller is a session of that role, as requestContext.authorizer.iam.userArn
	// reports it: the sts form, no path, a session name the assumer chose.
	testMachineCaller = "arn:aws:sts::123456789012:assumed-role/identity-service/1795000000123"
)

// iamEvent is v2Event with requestContext.authorizer.iam filled the way API
// Gateway fills it on an AWS_IAM route — caller is empty for a request with no
// authorizer block at all, which is every request on the public API.
func iamEvent(method, path string, headers map[string]string, caller, body string) json.RawMessage {
	var evt events.APIGatewayV2HTTPRequest
	if err := json.Unmarshal(v2Event(method, path, headers, nil, body), &evt); err != nil {
		panic(err)
	}
	if caller != "" {
		evt.RequestContext.Authorizer = &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
			IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{
				AccessKey: "ASIAEXAMPLEEXAMPLE00",
				AccountID: "123456789012",
				CallerID:  "AROAEXAMPLEEXAMPLE000:1795000000123",
				UserARN:   caller,
				UserID:    "AROAEXAMPLEEXAMPLE000:1795000000123",
			},
		}
	}
	raw, err := json.Marshal(evt)
	if err != nil {
		panic(err)
	}
	return raw
}

func invokeIAM(t *testing.T, app *App, method, path string, headers map[string]string, caller, body string) events.APIGatewayV2HTTPResponse {
	t.Helper()
	raw, err := app.Handle(context.Background(), iamEvent(method, path, headers, caller, body))
	if err != nil {
		t.Fatalf("Handle %s %s: %v", method, path, err)
	}
	var resp events.APIGatewayV2HTTPResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	return resp
}

// TestIAMCallerARNReadsTheHTTPAPIAuthorizerOnly: the caller is read from the
// one place API Gateway writes it on an AWS_IAM route of an HTTP API, and from
// no other event shape — a REST API's identity block, a Function URL's
// authorizer, an ALB — none of which the template routes to the console.
func TestIAMCallerARNReadsTheHTTPAPIAuthorizerOnly(t *testing.T) {
	t.Parallel()
	withIAM := events.APIGatewayV2HTTPRequest{RequestContext: events.APIGatewayV2HTTPRequestContext{
		Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
			IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{UserARN: testMachineCaller},
		},
	}}
	jwtOnly := events.APIGatewayV2HTTPRequest{RequestContext: events.APIGatewayV2HTTPRequestContext{
		Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
			JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{Claims: map[string]string{"sub": testMachineCaller}},
		},
	}}
	blankIAM := events.APIGatewayV2HTTPRequest{RequestContext: events.APIGatewayV2HTTPRequestContext{
		Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
			IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{UserARN: "  "},
		},
	}}
	rest := events.APIGatewayProxyRequest{RequestContext: events.APIGatewayProxyRequestContext{
		Identity: events.APIGatewayRequestIdentity{UserArn: testMachineCaller},
	}}
	functionURL := events.LambdaFunctionURLRequest{RequestContext: events.LambdaFunctionURLRequestContext{
		Authorizer: &events.LambdaFunctionURLRequestContextAuthorizerDescription{
			IAM: &events.LambdaFunctionURLRequestContextAuthorizerIAMDescription{UserARN: testMachineCaller},
		},
	}}
	var nilV2 *events.APIGatewayV2HTTPRequest

	for name, tc := range map[string]struct {
		event any
		want  string
	}{
		"an HTTP API event with the IAM block":    {withIAM, testMachineCaller},
		"the same event by pointer":               {&withIAM, testMachineCaller},
		"an HTTP API event with no authorizer":    {events.APIGatewayV2HTTPRequest{}, ""},
		"an HTTP API event with a JWT authorizer": {jwtOnly, ""},
		"an IAM block with a blank ARN":           {blankIAM, ""},
		"a REST API event's identity block":       {rest, ""},
		"a Function URL's IAM authorizer":         {functionURL, ""},
		"an ALB event":                            {events.ALBTargetGroupRequest{}, ""},
		"a nil pointer":                           {nilV2, ""},
		"no event at all":                         {nil, ""},
	} {
		got, ok := iamCallerARN(tc.event)
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: iamCallerARN = %q, %v; want %q", name, got, ok, tc.want)
		}
	}
}

// TestIAMPrincipalMatching walks the match the function makes: a role is its
// partition, account and name, so every session of a configured role is
// admitted whatever path the role was written with; a user is its whole ARN;
// and nothing else is a principal.
func TestIAMPrincipalMatching(t *testing.T) {
	t.Parallel()
	cfg := loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS", testMachineRole+",arn:aws:iam::123456789012:user/ops/backfill"))
	decide := adminMachineAccess(cfg)
	if decide == nil {
		t.Fatal("adminMachineAccess is nil with two principals configured")
	}
	for caller, admitted := range map[string]bool{
		testMachineCaller: true,
		"arn:aws:sts::123456789012:assumed-role/identity-service/another-session":     true,
		"arn:aws:iam::123456789012:user/ops/backfill":                                 true,
		"arn:aws:sts::210987654321:assumed-role/identity-service/1795000000123":       false, // same name, another account
		"arn:aws-cn:sts::123456789012:assumed-role/identity-service/1795000000123":    false, // another partition
		"arn:aws:sts::123456789012:assumed-role/identity-service-admin/1795000000123": false, // a name it is a prefix of
		"arn:aws:sts::123456789012:assumed-role/IDENTITY-SERVICE/1795000000123":       false, // IAM reports the name as created
		"arn:aws:iam::123456789012:user/backfill":                                     false, // the user's path is part of it
		"arn:aws:iam::123456789012:user/identity-service":                             false, // a user is not the role of its name
		"arn:aws:sts::123456789012:federated-user/identity-service":                   false,
		"arn:aws:iam::123456789012:root":                                              false,
		"arn:aws:sts::123456789012:assumed-role/identity-service":                     false, // no session: not a caller ARN
		"arn:aws:sts::123456789012:assumed-role/identity-service/a/b":                 false,
		"identity-service": false,
		"arn:aws:sts::12345678901x:assumed-role/identity-service/1795000000123":               false,
		"arn:aws:sts::123456789012:assumed-role/identity-service/1795000000123 trailing junk": false,
	} {
		req, err := lambdahttp.NewRequest(context.Background(), events.APIGatewayV2HTTPRequest{
			RawPath: "/admin/api/ping",
			RequestContext: events.APIGatewayV2HTTPRequestContext{
				HTTP: events.APIGatewayV2HTTPRequestContextHTTPDescription{Method: http.MethodGet, Path: "/admin/api/ping"},
				Authorizer: &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
					IAM: &events.APIGatewayV2HTTPRequestContextAuthorizerIAMDescription{UserARN: caller},
				},
			},
		}, lambdahttp.Options{})
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		principal, ok := decide(req)
		if ok != admitted {
			t.Errorf("caller %q admitted = %v, want %v", caller, ok, admitted)
		}
		if ok && principal != caller {
			t.Errorf("caller %q was admitted as %q; the audit principal is the caller's own ARN", caller, principal)
		}
	}
	if adminMachineAccess(loadAdmin(t, adminEnv(config.AdminAccessPolicyIsAdmin))) != nil {
		t.Error("adminMachineAccess is not nil with no principal configured; nil is the reference's guard")
	}
}

// machineApp is an App with the console under is-admin-flag and the identity
// service's role admitted.
func machineApp(t *testing.T, kv ...string) *App {
	t.Helper()
	return newTestApp(t, adminEnv(config.AdminAccessPolicyIsAdmin,
		append([]string{"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS", testMachineRole}, kv...)...))
}

// TestAdminMachineAccessEndToEnd drives the route the identity service uses —
// list the users, delete one — through New and a payload 2.0 event carrying
// the IAM block, with no token and no cookie, and the refusals around it: a
// role nobody listed, a request a browser originated, a request with no IAM
// block (every request on the public API), and the same request on a console
// with no principal configured.
func TestAdminMachineAccessEndToEnd(t *testing.T) {
	t.Parallel()
	app := machineApp(t)
	t.Cleanup(app.Close)

	reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody("doomed@example.test"))
	userID, _ := decodeBody(t, reg)["userId"].(string)
	if userID == "" {
		t.Fatalf("register answered no userId: %s", reg.Body)
	}

	list := invokeIAM(t, app, http.MethodGet, "/admin/api/users", jsonHeaders(), testMachineCaller, "")
	if list.StatusCode != http.StatusOK || !strings.Contains(list.Body, userID) {
		t.Fatalf("GET /admin/api/users as the identity service answered %d %s, want 200 listing %s", list.StatusCode, list.Body, userID)
	}
	for name, tc := range map[string]struct {
		headers map[string]string
		caller  string
	}{
		"a role nobody listed":       {jsonHeaders(), "arn:aws:sts::123456789012:assumed-role/somebody-else/s"},
		"a request a browser made":   {jsonHeaders("origin", "https://evil.example.test"), testMachineCaller},
		"a cross-site fetch":         {jsonHeaders("sec-fetch-site", "cross-site"), testMachineCaller},
		"no IAM block (public API)":  {jsonHeaders(), ""},
		"no IAM block, bogus bearer": {jsonHeaders("authorization", "Bearer not-a-token"), ""},
	} {
		if got := invokeIAM(t, app, http.MethodGet, "/admin/api/users", tc.headers, tc.caller, ""); got.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: GET /admin/api/users answered %d %s, want the guard's 401", name, got.StatusCode, got.Body)
		}
	}

	del := invokeIAM(t, app, http.MethodDelete, "/admin/api/users/"+userID, jsonHeaders(), testMachineCaller, "")
	if del.StatusCode != http.StatusOK {
		t.Fatalf("DELETE /admin/api/users/%s as the identity service answered %d %s, want 200", userID, del.StatusCode, del.Body)
	}
	if after := invokeIAM(t, app, http.MethodGet, "/admin/api/users/"+userID, jsonHeaders(), testMachineCaller, ""); after.StatusCode != http.StatusNotFound {
		t.Errorf("the deleted user's detail answered %d %s, want 404", after.StatusCode, after.Body)
	}

	// The IAM block means nothing outside the console: the auth router's gate
	// reads tokens.
	if me := invokeIAM(t, app, http.MethodGet, "/auth/me", jsonHeaders(), testMachineCaller, ""); me.StatusCode == http.StatusOK {
		t.Errorf("GET /auth/me with only the IAM block answered 200: %s", me.Body)
	}

	// And with no principal configured the IAM block admits nobody.
	plain := newTestApp(t, adminEnv(config.AdminAccessPolicyIsAdmin))
	t.Cleanup(plain.Close)
	if got := invokeIAM(t, plain, http.MethodGet, "/admin/api/users", jsonHeaders(), testMachineCaller, ""); got.StatusCode != http.StatusUnauthorized {
		t.Errorf("a console with no machine principal answered %d to the IAM block, want 401", got.StatusCode)
	}
}

// TestAdminMachineAccessMeetsTheOriginCheck pins the combination as built: the
// origin check is outermost, and machine access does not lift it. With
// http.originVerify on, a verified machine caller without the front door's
// header is refused with the bare 403 before the guard is reached, and with
// the header it is admitted. Exempting the IAM door from the front-door check
// is a decision this change leaves to the check's owner (config-reference
// §16.9 and §19 say what a deployment sends meanwhile).
func TestAdminMachineAccessMeetsTheOriginCheck(t *testing.T) {
	t.Parallel()
	secret := newFakeOriginSecret(testOriginCurrent, "")
	env := with(adminEnv(config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS", testMachineRole),
		"AWESOME_AUTH_HTTP_ORIGIN_VERIFY_SECRET_ARN", testOriginARN)
	app := newOriginApp(t, env, secret, nil)

	bare := invokeIAM(t, app, http.MethodGet, "/admin/api/users", jsonHeaders(), testMachineCaller, "")
	if bare.StatusCode != http.StatusForbidden || bare.Body != "" {
		t.Errorf("a verified machine call without the front door's header answered %d %q, want the bare 403", bare.StatusCode, bare.Body)
	}
	through := invokeIAM(t, app, http.MethodGet, "/admin/api/users", jsonHeaders(config.DefaultOriginVerifyHeader, testOriginCurrent), testMachineCaller, "")
	if through.StatusCode != http.StatusOK {
		t.Errorf("a verified machine call with the header answered %d %s, want 200", through.StatusCode, through.Body)
	}
}

// TestAdminMachineAccessIsAuditedOnTheBus: with the tools block on, each grant
// is raised as identity.admin.machine.access — outside the identity.*
// vocabulary EventNames lists — and the bridge carries it into the telemetry
// store like any other event, once, with the principal, method and path.
func TestAdminMachineAccessIsAuditedOnTheBus(t *testing.T) {
	t.Parallel()
	bundle := newToolsBundle()
	app := newToolsApp(t, with(toolsEnv(),
		"AWESOME_AUTH_ADMIN_ENABLED", "true",
		"AWESOME_AUTH_ADMIN_ACCESS_POLICY", config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS", testMachineRole,
		"AWESOME_AUTH_RATE_LIMIT_ENABLED", "false",
	), bundle)

	if got := invokeIAM(t, app, http.MethodGet, "/admin/api/users", jsonHeaders(), testMachineCaller, ""); got.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/api/users as the identity service answered %d %s", got.StatusCode, got.Body)
	}
	var rows []auth.TelemetryEvent
	deadline := time.Now().Add(2 * time.Second)
	for {
		var err error
		rows, err = bundle.bundle.telemetry.Query(context.Background(), auth.TelemetryFilter{EventName: auth.EventAdminMachineAccess})
		if err != nil {
			t.Fatalf("telemetry query: %v", err)
		}
		if len(rows) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(rows) != 1 {
		t.Fatalf("the grant left %d telemetry rows named %s, want exactly 1", len(rows), auth.EventAdminMachineAccess)
	}
	data, _ := json.Marshal(rows[0].Meta)
	for _, want := range []string{testMachineCaller, `"GET"`, "/api/users"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("the audit row does not carry %s: %s", want, data)
		}
	}
}

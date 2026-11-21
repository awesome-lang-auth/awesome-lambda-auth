package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The staff realm invitations exist for: registration closed, a second factor
// required with enrolment at first sign-in, and a back office that provisions
// people through the admin API on an IAM-verified request. No root user and no
// bootstrap secret, which RS-20 refuses beside twoFactor.required; no sender,
// so the back office is the delivery (admin.revealInvitationToken).
func staffRealmEnv(kv ...string) map[string]string {
	return with(baseEnv(), append([]string{
		"AWESOME_AUTH_ADMIN_ENABLED", "true",
		"AWESOME_AUTH_ADMIN_ACCESS_POLICY", config.AdminAccessPolicyIsAdmin,
		"AWESOME_AUTH_ADMIN_MACHINE_ACCESS_IAM_PRINCIPALS", testMachineRole,
		"AWESOME_AUTH_REGISTRATION_CLOSED", "true",
		"AWESOME_AUTH_2FA_REQUIRED", "true",
		"AWESOME_AUTH_2FA_ENROL_ON_LOGIN", "true",
		"AWESOME_AUTH_INVITATIONS_ENABLED", "true",
		"AWESOME_AUTH_INVITATIONS_TTL", "48h",
		"AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN", "true",
		"AWESOME_AUTH_RATE_LIMIT_ENABLED", "false",
	}, kv...)...)
}

// staffInvitationFlow drives the realm end to end: invite by machine access,
// accept, forced TOTP enrolment with the acceptance's own token, the session,
// and the refusals around them. It returns the token so a caller holding the
// table can show the token is nowhere in it.
func staffInvitationFlow(t *testing.T, app *App, email string) string {
	t.Helper()

	// The realm is closed: the public route creates nobody.
	if reg := invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(email)); reg.StatusCode != http.StatusNotFound {
		t.Fatalf("POST /auth/register in a closed realm answered %d %s, want 404", reg.StatusCode, reg.Body)
	}
	// Nobody but the listed principal invites.
	body := fmt.Sprintf(`{"email":%q,"role":"staff"}`, email)
	if anon := invokeIAM(t, app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), "", body); anon.StatusCode != http.StatusUnauthorized {
		t.Fatalf("an invitation with no IAM block answered %d %s, want the guard's 401", anon.StatusCode, anon.Body)
	}

	invite := invokeIAM(t, app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, body)
	if invite.StatusCode != http.StatusCreated {
		t.Fatalf("POST /admin/api/users/invitations as the identity service answered %d %s, want 201", invite.StatusCode, invite.Body)
	}
	answer := decodeBody(t, invite)
	token, _ := answer["token"].(string)
	invitationID, _ := answer["invitationId"].(string)
	acceptURL, _ := answer["acceptUrl"].(string)
	if token == "" || invitationID == "" || !strings.Contains(acceptURL, "/invitations/accept?token=") {
		t.Fatalf("the revealed invitation carries no token, id or accept URL: %s", invite.Body)
	}
	// The same address again is a conflict: reinvite is off.
	if dup := invokeIAM(t, app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, body); dup.StatusCode != http.StatusConflict {
		t.Fatalf("inviting %s twice answered %d %s, want 409", email, dup.StatusCode, dup.Body)
	}
	list := invokeIAM(t, app, http.MethodGet, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, "")
	if list.StatusCode != http.StatusOK || !strings.Contains(list.Body, invitationID) || strings.Contains(list.Body, token) {
		t.Fatalf("the listing answered %d %s, want 200 naming %s and never the token", list.StatusCode, list.Body, invitationID)
	}
	// Before acceptance the pending account cannot sign in.
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	if pre := invoke(t, app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, testPassword)); pre.StatusCode == http.StatusOK || pre.StatusCode == http.StatusForbidden {
		t.Fatalf("the pending account signed in before accepting: %d %s", pre.StatusCode, pre.Body)
	}

	// A wrong token and a weak password are refused before anything is spent.
	if bad := invoke(t, app, http.MethodPost, "/auth/invitations/accept", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, token+"x", testPassword)); bad.StatusCode != http.StatusUnauthorized || decodeBody(t, bad)["code"] != auth.CodeInvalidInvitation {
		t.Fatalf("a wrong token answered %d %s, want 401 INVALID_INVITATION", bad.StatusCode, bad.Body)
	}
	if weak := invoke(t, app, http.MethodPost, "/auth/invitations/accept", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"password":"x"}`, token)); weak.StatusCode != http.StatusBadRequest {
		t.Fatalf("a weak password answered %d %s, want 400", weak.StatusCode, weak.Body)
	}

	// Accepting sets the password and answers the login's own next step: the
	// realm requires a factor the invitee has not enrolled, so 403
	// 2FA_SETUP_REQUIRED with an enrolment token, and no session.
	accept := invoke(t, app, http.MethodPost, "/auth/invitations/accept", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, token, testPassword))
	if accept.StatusCode != http.StatusForbidden || decodeBody(t, accept)["code"] != "2FA_SETUP_REQUIRED" {
		t.Fatalf("POST /auth/invitations/accept answered %d %s, want 403 2FA_SETUP_REQUIRED", accept.StatusCode, accept.Body)
	}
	if decodeBody(t, accept)["accessToken"] != nil || len(sessionCookies(accept)) > 0 {
		t.Fatalf("the acceptance opened a session before the factor: %s", accept.Body)
	}
	temp, _ := decodeBody(t, accept)["tempToken"].(string)
	if temp == "" {
		t.Fatalf("the acceptance carried no enrolment token: %s", accept.Body)
	}
	// Single use: the replay is the one refusal.
	if replay := invoke(t, app, http.MethodPost, "/auth/invitations/accept", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, token, testPassword+"2")); replay.StatusCode != http.StatusUnauthorized || decodeBody(t, replay)["code"] != auth.CodeInvalidInvitation {
		t.Fatalf("a replayed acceptance answered %d %s, want 401 INVALID_INVITATION", replay.StatusCode, replay.Body)
	}

	// Forced enrolment with the acceptance's token opens the session.
	withTemp := jsonHeaders("authorization", "Bearer "+temp, auth.AuthStrategyHeader, auth.AuthStrategyBearer)
	setup := invoke(t, app, http.MethodPost, "/auth/2fa/setup", withTemp, nil, "{}")
	if setup.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/2fa/setup with the acceptance's token answered %d %s, want 200", setup.StatusCode, setup.Body)
	}
	secret, _ := decodeBody(t, setup)["secret"].(string)
	verify := invoke(t, app, http.MethodPost, "/auth/2fa/verify-setup", withTemp, nil,
		fmt.Sprintf(`{"secret":%q,"token":%q}`, secret, totpCodeNow(t, secret)))
	access, _ := decodeBody(t, verify)["accessToken"].(string)
	if verify.StatusCode != http.StatusOK || access == "" {
		t.Fatalf("POST /auth/2fa/verify-setup answered %d %s, want 200 and a session", verify.StatusCode, verify.Body)
	}
	me := invoke(t, app, http.MethodGet, "/auth/me", bearer(access), nil, "")
	if me.StatusCode != http.StatusOK || decodeBody(t, me)["isTotpEnabled"] != true || decodeBody(t, me)["isEmailVerified"] != true {
		t.Fatalf("GET /auth/me answered %d %s, want the enrolled, verified account", me.StatusCode, me.Body)
	}
	if role, _ := decodeBody(t, me)["role"].(string); role != "" && role != "staff" {
		t.Fatalf("the account carries role %q, want the invited staff", role)
	}

	// The invitation is spent: no longer listed, and its revocation is 409.
	after := invokeIAM(t, app, http.MethodGet, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, "")
	if after.StatusCode != http.StatusOK || strings.Contains(after.Body, invitationID) {
		t.Fatalf("the accepted invitation is still listed: %d %s", after.StatusCode, after.Body)
	}
	if rev := invokeIAM(t, app, http.MethodDelete, "/admin/api/users/invitations/"+invitationID, jsonHeaders(), testMachineCaller, ""); rev.StatusCode != http.StatusConflict {
		t.Fatalf("revoking the accepted invitation answered %d %s, want 409", rev.StatusCode, rev.Body)
	}

	// The next login is the challenge for the factor just enrolled.
	again := invoke(t, app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(email, testPassword))
	if again.StatusCode != http.StatusOK || decodeBody(t, again)["requiresTwoFactor"] != true {
		t.Fatalf("the next login answered %d %s, want the challenge", again.StatusCode, again.Body)
	}

	// A second invitation, revoked before use, takes its untouched account
	// with it and its token is refused.
	other := "revoked-" + email
	second := invokeIAM(t, app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, fmt.Sprintf(`{"email":%q}`, other))
	secondToken, _ := decodeBody(t, second)["token"].(string)
	secondID, _ := decodeBody(t, second)["invitationId"].(string)
	if second.StatusCode != http.StatusCreated || secondToken == "" {
		t.Fatalf("the second invitation answered %d %s", second.StatusCode, second.Body)
	}
	rev := invokeIAM(t, app, http.MethodDelete, "/admin/api/users/invitations/"+secondID, jsonHeaders(), testMachineCaller, "")
	if rev.StatusCode != http.StatusOK || decodeBody(t, rev)["accountRemoved"] != true {
		t.Fatalf("revoking an unused invitation answered %d %s, want 200 accountRemoved true", rev.StatusCode, rev.Body)
	}
	if late := invoke(t, app, http.MethodPost, "/auth/invitations/accept", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, secondToken, testPassword)); late.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a revoked invitation was accepted: %d %s", late.StatusCode, late.Body)
	}
	return token
}

func TestStaffInvitationRealmEndToEnd(t *testing.T) {
	t.Parallel()
	app := newTestApp(t, staffRealmEnv())
	t.Cleanup(app.Close)
	staffInvitationFlow(t, app, "staff@example.test")
}

// TestStaffInvitationRealmOnDynamoDB is the same realm on the store a
// deployment runs — the consume, the release and the per-user read are
// DynamoDB conditions there, not a mutex — and shows the token is nowhere in
// the table afterwards, only its hash.
func TestStaffInvitationRealmOnDynamoDB(t *testing.T) {
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run invitations on the deployed driver")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_cmd_auth_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for %s: %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at %s (%v)", table, endpoint, err)
	}
	app, err := New(ctx, Options{
		Getenv: envFunc(staffRealmEnv(
			"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
			"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
			"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
			"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
		)),
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("New with the dynamodb driver: %v", err)
	}
	t.Cleanup(app.Close)
	token := staffInvitationFlow(t, app, "staff-ddb@example.test")

	scan, err := client.Scan(ctx, &awsddb.ScanInput{TableName: aws.String(table)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	invitations := 0
	for _, it := range scan.Items {
		for name, av := range it {
			if s := fmt.Sprintf("%v", av); strings.Contains(s, token) {
				t.Fatalf("the plaintext token is stored in attribute %s", name)
			}
		}
		if pk := fmt.Sprintf("%v", it["PK"]); strings.Contains(pk, "INV#") {
			invitations++
		}
	}
	if invitations == 0 {
		t.Fatal("no invitation record reached the table: the DynamoDB store was not the one handed to the core")
	}
}

// The slot refuses a driver whose store offers no invitation store, and is
// silent with the feature off.
func TestInvitationOptionsRefuseADriverWithoutTheStore(t *testing.T) {
	t.Parallel()
	cfg := config.Defaults()
	if opts, err := invitationOptions(cfg, nil, discardLogger()); err != nil || len(opts) != 0 {
		t.Fatalf("invitations off: %d options, %v", len(opts), err)
	}
	cfg.Invitations.Enabled = true
	if _, err := invitationOptions(cfg, auth.NewMemoryUserStore(), discardLogger()); err == nil {
		t.Fatal("a store with no Invitations() was accepted")
	}
	opts, err := invitationOptions(cfg, newMemoryStoreBundle(), discardLogger())
	if err != nil || len(opts) != 3 {
		t.Fatalf("memory bundle: %d options, %v", len(opts), err)
	}
}

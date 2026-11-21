package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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

// TestPendingInvitationOutlivesTheTTLSweep: DynamoDB TTL never reaps a pending
// invitation. The sweep is simulated at the end of time — every item that
// carries a ttl is deleted — and the invitation must still be what the core
// says a pending one is until it is revoked: listed, holding its account
// against /forgot-password (a reset there would leave a password on an
// unverified address, which neither the login nor an invitation accepts),
// replaceable by a re-invitation, and revocable with its account.
func TestPendingInvitationOutlivesTheTTLSweep(t *testing.T) {
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run invitations on the deployed driver")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_cmd_auth_sweep_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for %s: %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at %s (%v)", table, endpoint, err)
	}
	t.Cleanup(func() {
		_, _ = client.DeleteTable(context.Background(), &awsddb.DeleteTableInput{TableName: aws.String(table)})
	})
	d := newDeliveryAppWith(t, mailerEnv(staffRealmEnv(
		"AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN", "false",
		"AWESOME_AUTH_INVITATIONS_REINVITE", "true",
		"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
		"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
		"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
	)), func(o *Options) { o.Stores = nil })
	t.Cleanup(d.app.Close)

	sweep := func() {
		t.Helper()
		var start map[string]types.AttributeValue
		for {
			page, err := client.Scan(ctx, &awsddb.ScanInput{TableName: aws.String(table), ExclusiveStartKey: start})
			if err != nil {
				t.Fatalf("scan: %v", err)
			}
			for _, it := range page.Items {
				if _, hasTTL := it["ttl"]; !hasTTL {
					continue
				}
				if _, err := client.DeleteItem(ctx, &awsddb.DeleteItemInput{
					TableName: aws.String(table),
					Key:       map[string]types.AttributeValue{"PK": it["PK"], "SK": it["SK"]},
				}); err != nil {
					t.Fatalf("delete: %v", err)
				}
			}
			if start = page.LastEvaluatedKey; len(start) == 0 {
				return
			}
		}
	}
	invite := func(want int) string {
		t.Helper()
		resp := invokeIAM(t, d.app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, `{"email":"lapsed@example.test","role":"staff"}`)
		id, _ := decodeBody(t, resp)["invitationId"].(string)
		if resp.StatusCode != want || id == "" {
			t.Fatalf("invite answered %d %s, want %d and an invitation id", resp.StatusCode, resp.Body, want)
		}
		return id
	}
	listed := func() string {
		t.Helper()
		resp := invokeIAM(t, d.app, http.MethodGet, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("the listing answered %d %s", resp.StatusCode, resp.Body)
		}
		return resp.Body
	}

	first := invite(http.StatusCreated)
	sweep()
	if !strings.Contains(listed(), first) {
		t.Fatalf("the sweep took the pending invitation %s out of the listing", first)
	}
	d.mail.reset()
	if fp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil, `{"email":"lapsed@example.test"}`); fp.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password answered %d %s", fp.StatusCode, fp.Body)
	}
	if msgs := d.mail.messages(); len(msgs) != 0 {
		t.Fatalf("after the sweep /forgot-password mailed the reserved account %d message(s); a reset would lock the invitee out", len(msgs))
	}

	// The account is still the invitation's: a re-invitation replaces it.
	second := invite(http.StatusOK)
	sweep()
	if body := listed(); !strings.Contains(body, second) || strings.Contains(body, first) {
		t.Fatalf("after the re-invitation the listing is %s, want %s and not the retired %s", body, second, first)
	}
	rev := invokeIAM(t, d.app, http.MethodDelete, "/admin/api/users/invitations/"+second, jsonHeaders(), testMachineCaller, "")
	if rev.StatusCode != http.StatusOK || decodeBody(t, rev)["accountRemoved"] != true {
		t.Fatalf("revoking the swept-over invitation answered %d %s, want 200 accountRemoved true", rev.StatusCode, rev.Body)
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

// The sender path: with a mailer and no reveal, the invite answer carries no
// token, exactly one mail does, and that token is the one the accept route
// honours. The link is built on the mailer's base (the hosted UI's path when
// ui.enabled, the site URL otherwise); no page ships for it.
func TestInvitationTravelsByTheMailer(t *testing.T) {
	t.Parallel()
	d := newDeliveryApp(t, mailerEnv(staffRealmEnv("AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN", "false")))
	t.Cleanup(d.app.Close)

	invite := invokeIAM(t, d.app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, `{"email":"mailed@example.test"}`)
	if invite.StatusCode != http.StatusCreated {
		t.Fatalf("invite answered %d %s, want 201", invite.StatusCode, invite.Body)
	}
	if strings.Contains(invite.Body, `"token"`) || strings.Contains(invite.Body, "acceptUrl") {
		t.Fatalf("a deployment with a mailer handed the token to the admin caller: %s", invite.Body)
	}
	msg := d.mail.only(t)
	if msg.To != "mailed@example.test" {
		t.Fatalf("the invitation went to %q", msg.To)
	}
	match := regexp.MustCompile(`/invitations/accept\?token=([A-Za-z0-9_\-]+)`).FindStringSubmatch(msg.Body + msg.Text)
	if match == nil {
		t.Fatalf("the invitation mail carries no accept link: %s", msg.Body)
	}
	accept := invoke(t, d.app, http.MethodPost, "/auth/invitations/accept", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, match[1], testPassword))
	if accept.StatusCode != http.StatusForbidden || decodeBody(t, accept)["code"] != "2FA_SETUP_REQUIRED" {
		t.Fatalf("the mailed token answered %d %s, want 403 2FA_SETUP_REQUIRED", accept.StatusCode, accept.Body)
	}
	if strings.Contains(d.log.String(), match[1]) {
		t.Fatal("the invitation token reached the log")
	}
}

// webhookStaffRealmEnv is the staff realm with no mailer: the delivery webhook
// at url is the sender, and nothing is revealed to the admin caller.
// email.mailer.defaultLang is set, as a stack may carry it with no mailer
// block: it belongs to the mailer, and the webhook test shows it never reaches
// the webhook.
func webhookStaffRealmEnv(url string) map[string]string {
	return webhookEnv(staffRealmEnv(
		"AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN", "false",
		"AWESOME_AUTH_MAILER_DEFAULT_LANG", "it",
	), url)
}

// invitationDeliveries returns what reached the receiver, failing unless every
// request is one invitation, each decoded into the type the core sent and
// with the keys of its delivery object.
func invitationDeliveries(t *testing.T, rec *webhookReceiver) ([]auth.InvitationDelivery, []map[string]json.RawMessage, []webhookDelivery) {
	t.Helper()
	var (
		typed []auth.InvitationDelivery
		raw   []map[string]json.RawMessage
	)
	got := rec.deliveries()
	for _, d := range got {
		if d.request.Kind != auth.DeliveryKindInvitation {
			t.Fatalf("the receiver got kind %q, want %q: %s", d.request.Kind, auth.DeliveryKindInvitation, d.body)
		}
		var one auth.InvitationDelivery
		var keys map[string]json.RawMessage
		if err := json.Unmarshal(d.request.Delivery, &one); err != nil {
			t.Fatalf("decode the invitation delivery: %v", err)
		}
		if err := json.Unmarshal(d.request.Delivery, &keys); err != nil {
			t.Fatalf("decode the invitation delivery's keys: %v", err)
		}
		typed, raw = append(typed, one), append(raw, keys)
	}
	return typed, raw, got
}

// TestInvitationTravelsByTheDeliveryWebhook covers the staff realm when it runs
// with no mailer. The delivery webhook is the sender, twoFactor.required is on
// with enrolOnLogin, and nothing is revealed. Each invitation leaves as one
// signed POST of kind "invitation", and its body has everything a receiver
// needs to write the mail: the recipient, the token, the link base, the
// language and the expiry. None of it reaches the admin caller, a mailer or the
// log. config-reference §21.2 documents this payload, field by field.
func TestInvitationTravelsByTheDeliveryWebhook(t *testing.T) {
	t.Parallel()
	rec := newWebhookReceiver(t)
	d := newDeliveryAppWith(t, webhookStaffRealmEnv(rec.srv.URL), func(o *Options) { o.HTTPClient = rec.srv.Client() })
	t.Cleanup(d.app.Close)

	before := time.Now()
	invite := invokeIAM(t, d.app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller,
		`{"email":" New.Staff@Example.test ","role":"staff","metadata":{"team":"ops"},"emailLang":"it"}`)
	if invite.StatusCode != http.StatusCreated {
		t.Fatalf("invite answered %d %s, want 201", invite.StatusCode, invite.Body)
	}
	if strings.Contains(invite.Body, `"token"`) || strings.Contains(invite.Body, "acceptUrl") {
		t.Fatalf("a deployment with a delivery webhook handed the token to the admin caller: %s", invite.Body)
	}
	answer := decodeBody(t, invite)

	typed, raw, got := invitationDeliveries(t, rec)
	if len(typed) != 1 {
		t.Fatalf("the receiver got %d requests, want exactly one invitation", len(typed))
	}
	delivery, keys, request := typed[0], raw[0], got[0]

	// The envelope: the event, and a signature a receiver can check on its
	// own, over the exact bytes, with the shared secret.
	if event := request.headers.Get("X-Webhook-Event"); event != "delivery."+auth.DeliveryKindInvitation {
		t.Errorf("X-Webhook-Event = %q, want delivery.invitation", event)
	}
	if request.headers.Get("X-Webhook-Delivery") == "" {
		t.Error("X-Webhook-Delivery is empty, so a receiver cannot deduplicate")
	}
	mac := hmac.New(sha256.New, []byte(testWebhookSecret))
	mac.Write(request.body)
	if sig, want := request.headers.Get("X-Webhook-Signature"), "sha256="+hex.EncodeToString(mac.Sum(nil)); sig != want {
		t.Errorf("X-Webhook-Signature = %q, want %q, an independent HMAC over the body", sig, want)
	}

	// The payload. These are exactly the keys §21.2 documents. A new field
	// in a later core fails here until the docs say what it carries.
	want := []string{"email", "expiresAt", "invitationId", "lang", "linkBase", "metadata", "role", "tenantId", "token", "userId"}
	var have []string
	for k := range keys {
		have = append(have, k)
	}
	sort.Strings(have)
	if strings.Join(have, ",") != strings.Join(want, ",") {
		t.Errorf("the delivery's keys are %v, want %v (docs/config-reference.md §21.2)", have, want)
	}
	if delivery.InvitationID != answer["invitationId"] || delivery.UserID != answer["userId"] {
		t.Errorf("the delivery names invitation %q of user %q, the answer %v of %v",
			delivery.InvitationID, delivery.UserID, answer["invitationId"], answer["userId"])
	}
	if delivery.Email != "new.staff@example.test" || delivery.Email != answer["email"] {
		t.Errorf("the recipient is %q, want the normalised address the answer names (%v)", delivery.Email, answer["email"])
	}
	if delivery.Role != "staff" || delivery.Metadata["team"] != "ops" || delivery.TenantID != "" {
		t.Errorf("role %q, metadata %v, tenant %q: want what the invitation was created with", delivery.Role, delivery.Metadata, delivery.TenantID)
	}
	if delivery.Lang != "it" {
		t.Errorf("lang = %q, want the invite body's emailLang", delivery.Lang)
	}
	answered, err := time.Parse(time.RFC3339Nano, fmt.Sprint(answer["expiresAt"]))
	if err != nil || !delivery.ExpiresAt.Equal(answered) {
		t.Errorf("expiresAt = %v, want the answer's %v (%v)", delivery.ExpiresAt, answer["expiresAt"], err)
	}
	if ttl := delivery.ExpiresAt.Sub(before); ttl < 48*time.Hour || ttl > 48*time.Hour+time.Minute {
		t.Errorf("expiresAt is %v after the call, want invitations.ttl (48h)", ttl)
	}
	// There is no link field. The receiver builds the link on linkBase, the
	// site URL a machine caller resolves to (no Origin) plus the API prefix,
	// and the path is the POST-only accept route. That is why a receiver
	// points the mail at its own accept form, as §21.2 says.
	if delivery.LinkBase != testLinkBase {
		t.Errorf("linkBase = %q, want %q", delivery.LinkBase, testLinkBase)
	}
	if link := auth.InvitationURL(delivery.LinkBase, delivery.Token); link != testLinkBase+"/invitations/accept?token="+delivery.Token {
		t.Errorf("the mailer's link would be %q", link)
	}

	// Nothing went anywhere else.
	if msgs := d.mail.messages(); len(msgs) != 0 {
		t.Errorf("%d mail(s) were sent beside the webhook", len(msgs))
	}
	if strings.Contains(d.log.String(), delivery.Token) {
		t.Error("the invitation token reached the log")
	}

	// The delivered token is the one the accept route honours, and the
	// realm's next step follows it: enrolment, no session yet.
	accept := invoke(t, d.app, http.MethodPost, "/auth/invitations/accept", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, delivery.Token, testPassword))
	if accept.StatusCode != http.StatusForbidden || decodeBody(t, accept)["code"] != "2FA_SETUP_REQUIRED" || decodeBody(t, accept)["tempToken"] == nil {
		t.Fatalf("the delivered token answered %d %s, want 403 2FA_SETUP_REQUIRED with an enrolment token", accept.StatusCode, accept.Body)
	}

	// With no emailLang, lang is left out. The receiver picks the language,
	// and email.mailer.defaultLang ("it" here) belongs to the mailer and does
	// not travel with the webhook.
	if second := invokeIAM(t, d.app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller,
		`{"email":"no-lang@example.test"}`); second.StatusCode != http.StatusCreated {
		t.Fatalf("the second invite answered %d %s, want 201", second.StatusCode, second.Body)
	}
	typed, raw, _ = invitationDeliveries(t, rec)
	if len(typed) != 2 {
		t.Fatalf("the receiver got %d requests, want two invitations", len(typed))
	}
	if _, has := raw[1]["lang"]; has || typed[1].Lang != "" {
		t.Errorf("an invitation sent with no emailLang carries lang %q, want the key left out", typed[1].Lang)
	}
	if _, has := raw[1]["role"]; has {
		t.Error("an invitation with no role carries a role key, want it left out")
	}
}

// TestInvitationWebhookFailureUndoesTheInvitation: the receiver's answer is the
// delivery, so anything but a 2xx fails the invitation with a 502 and leaves
// nothing behind. The invitation is revoked, so the token the receiver saw is
// dead. The account it created is removed, so the same call works again. The
// log carries no token.
func TestInvitationWebhookFailureUndoesTheInvitation(t *testing.T) {
	t.Parallel()
	rec := newWebhookReceiver(t)
	rec.setStatus(http.StatusServiceUnavailable)
	d := newDeliveryAppWith(t, webhookStaffRealmEnv(rec.srv.URL), func(o *Options) { o.HTTPClient = rec.srv.Client() })
	t.Cleanup(d.app.Close)

	const body = `{"email":"bounced@example.test","role":"staff"}`
	failed := invokeIAM(t, d.app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, body)
	if failed.StatusCode != http.StatusBadGateway {
		t.Fatalf("an invitation the receiver refused answered %d %s, want 502", failed.StatusCode, failed.Body)
	}
	typed, _, _ := invitationDeliveries(t, rec)
	if len(typed) != 1 || typed[0].Token == "" {
		t.Fatalf("the receiver got %d requests, want the one it refused", len(typed))
	}
	refused := typed[0]

	list := invokeIAM(t, d.app, http.MethodGet, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, "")
	if list.StatusCode != http.StatusOK || strings.Contains(list.Body, refused.InvitationID) || strings.Contains(list.Body, "bounced@") {
		t.Fatalf("the undelivered invitation is still listed: %d %s", list.StatusCode, list.Body)
	}
	if late := invoke(t, d.app, http.MethodPost, "/auth/invitations/accept", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, refused.Token, testPassword)); late.StatusCode != http.StatusUnauthorized {
		t.Fatalf("the undelivered token answered %d %s, want 401", late.StatusCode, late.Body)
	}
	if strings.Contains(d.log.String(), refused.Token) {
		t.Error("the undelivered token reached the log")
	}

	// Without reinvite, an account left behind would make this a 409.
	rec.setStatus(0)
	if again := invokeIAM(t, d.app, http.MethodPost, "/admin/api/users/invitations", jsonHeaders(), testMachineCaller, body); again.StatusCode != http.StatusCreated {
		t.Fatalf("repeating the call once the receiver answers 2xx answered %d %s, want 201", again.StatusCode, again.Body)
	}
}

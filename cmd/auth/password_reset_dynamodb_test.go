package main

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// TestRevokingResetEndsTheSessionsOnDynamoDB is TestRevokingResetEndsTheSessions
// on the deployed composition: the real store factory, the DynamoDB driver,
// sessions.revokeOnPasswordReset on and sessions.checkOn: allcalls. The core
// finds auth.UserSessionRevoker by type assertion on the session store the
// factory hands it, so this is what fails if that value stops being one —
// the reset would then fall back to the capped, eventually consistent listing
// without a build error. Both sessions opened with the old password are refused
// at their next refresh (401 SESSION_REVOKED) and their access token at its
// next request; the new password opens a session that works.
func TestRevokingResetEndsTheSessionsOnDynamoDB(t *testing.T) {
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run this end-to-end case")
	}
	// No t.Parallel, for the reason TestDynamoDBBackedRoutesFindEveryStore gives.
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

	env := mailerEnv(baseEnv(),
		"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
		"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
		"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
		"AWESOME_AUTH_SESSIONS_CHECK_ON", "allcalls",
		"AWESOME_AUTH_SESSIONS_REVOKE_ON_PASSWORD_RESET", "true",
	)
	// The session store the real factory builds for this driver is a revoker.
	// The end-to-end case below cannot tell the revoker from the core's
	// fallback on its own — two sessions on DynamoDB Local are listed
	// completely either way — so the composition is asked directly.
	cfg := &config.Config{Stores: config.Stores{
		Driver:     config.StoreDriverDynamoDB,
		Connection: config.StoreConnection{TableName: table, Region: "us-east-1", Endpoint: endpoint},
	}}
	if _, sessions, err := defaultStoreFactory(ctx, cfg, discardLogger()); err != nil {
		t.Fatalf("defaultStoreFactory: %v", err)
	} else if _, ok := sessions.(auth.UserSessionRevoker); !ok {
		t.Fatalf("the DynamoDB driver's session store %T is not an auth.UserSessionRevoker: "+
			"a revoking reset would fall back to the capped GSI listing", sessions)
	}

	// The real factory: nothing here injects a store.
	d := newDeliveryAppWith(t, env, func(o *Options) { o.Stores = nil })
	t.Cleanup(d.app.Close)

	const owner = "revoked-ddb@example.test"
	const newPassword = "another-correct-horse-battery"
	bearerJSON := jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer)

	first := decodeBody(t, registerAndLogin(t, d.app, bearerJSON, owner))
	second := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, testPassword))
	if second.StatusCode != http.StatusOK {
		t.Fatalf("second login answered %d %s", second.StatusCode, second.Body)
	}
	type creds struct{ access, refresh string }
	var before []creds
	for _, body := range []map[string]any{first, decodeBody(t, second)} {
		access, _ := body["accessToken"].(string)
		refresh, _ := body["refreshToken"].(string)
		if access == "" || refresh == "" {
			t.Fatalf("login answered no tokens: %v", body)
		}
		before = append(before, creds{access, refresh})
	}
	if me := invoke(t, d.app, http.MethodGet, "/auth/me", bearer(before[0].access), nil, ""); me.StatusCode != http.StatusOK {
		t.Fatalf("/me before the reset answered %d %s", me.StatusCode, me.Body)
	}

	if resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil, fmt.Sprintf(`{"email":%q}`, owner)); resp.StatusCode != http.StatusOK {
		t.Fatalf("forgot-password answered %d %s", resp.StatusCode, resp.Body)
	}
	token := tokenIn(t, linkIn(t, d.mail.only(t).Body))
	if resp := invoke(t, d.app, http.MethodPost, "/auth/reset-password", bearerJSON, nil,
		fmt.Sprintf(`{"token":%q,"password":%q}`, token, newPassword)); resp.StatusCode != http.StatusOK {
		t.Fatalf("reset-password answered %d %s", resp.StatusCode, resp.Body)
	}

	for i, c := range before {
		old := invoke(t, d.app, http.MethodPost, "/auth/refresh", bearerJSON, nil, fmt.Sprintf(`{"refreshToken":%q}`, c.refresh))
		if old.StatusCode != http.StatusUnauthorized || decodeBody(t, old)["code"] != "SESSION_REVOKED" {
			t.Errorf("session %d: refresh after a revoking reset answered %d %s, want 401 SESSION_REVOKED", i, old.StatusCode, old.Body)
		}
		if me := invoke(t, d.app, http.MethodGet, "/auth/me", bearer(c.access), nil, ""); me.StatusCode != http.StatusUnauthorized {
			t.Errorf("session %d: /me with an access token from before the reset answered %d %s, want 401 under checkOn: allcalls", i, me.StatusCode, me.Body)
		}
	}

	fresh := invoke(t, d.app, http.MethodPost, "/auth/login", bearerJSON, nil, loginBody(owner, newPassword))
	if fresh.StatusCode != http.StatusOK {
		t.Fatalf("login with the new password answered %d %s", fresh.StatusCode, fresh.Body)
	}
	body := decodeBody(t, fresh)
	access, _ := body["accessToken"].(string)
	refresh, _ := body["refreshToken"].(string)
	if me := invoke(t, d.app, http.MethodGet, "/auth/me", bearer(access), nil, ""); me.StatusCode != http.StatusOK {
		t.Errorf("/me on the new password's session answered %d %s", me.StatusCode, me.Body)
	}
	if resp := invoke(t, d.app, http.MethodPost, "/auth/refresh", bearerJSON, nil, fmt.Sprintf(`{"refreshToken":%q}`, refresh)); resp.StatusCode != http.StatusOK {
		t.Errorf("the new password's session does not refresh: %d %s", resp.StatusCode, resp.Body)
	}
}

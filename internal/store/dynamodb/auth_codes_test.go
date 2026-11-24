package dynamodb

import (
	"context"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// sampleAuthCode is a code with every field the core records populated, so a
// round-trip test proves the whole record survives rather than the two fields
// the handler happens to read today. The PKCE pair and the scope are exactly
// that case: the core stores them as data it does not verify yet, and a store
// that quietly dropped them would pass every test written against current
// behaviour and break the day verification lands.
func sampleAuthCode(codeHash string) auth.AuthCode {
	return auth.AuthCode{
		CodeHash:            codeHash,
		UserID:              uniqueID("usr"),
		TenantID:            "acme",
		ClientID:            "console",
		Nonce:               "n-" + randomHex(8),
		RedirectURI:         "https://console.example.test/callback",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Scope:               "openid email profile",
		ExpiresAt:           time.Now().UTC().Add(5 * time.Minute).Truncate(time.Millisecond),
		// What /authorize sets under sessions.revokeOnPasswordReset: the
		// password fingerprint /token compares (core v0.16.0).
		Credential: "cred-" + randomHex(16),
	}
}

func TestAuthCodeRoundTrip(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	want := sampleAuthCode(hashOf("code-" + randomHex(8)))
	if err := store.SaveCode(ctx, want); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}

	got, err := store.ConsumeCode(ctx, want.CodeHash)
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}

	// Compared field by field rather than with a struct equality, so a failure
	// names the field that was dropped.
	for _, f := range []struct {
		name      string
		got, want string
	}{
		{"CodeHash", got.CodeHash, want.CodeHash},
		{"UserID", got.UserID, want.UserID},
		{"TenantID", got.TenantID, want.TenantID},
		{"ClientID", got.ClientID, want.ClientID},
		{"Nonce", got.Nonce, want.Nonce},
		{"RedirectURI", got.RedirectURI, want.RedirectURI},
		{"CodeChallenge", got.CodeChallenge, want.CodeChallenge},
		{"CodeChallengeMethod", got.CodeChallengeMethod, want.CodeChallengeMethod},
		{"Scope", got.Scope, want.Scope},
		{"Credential", got.Credential, want.Credential},
	} {
		if f.got != f.want {
			t.Errorf("%s = %q, want %q", f.name, f.got, f.want)
		}
	}
	if !got.ExpiresAt.Equal(want.ExpiresAt) {
		t.Errorf("ExpiresAt = %s, want %s", got.ExpiresAt, want.ExpiresAt)
	}
}

// TestAuthCodeItemShape reads the item raw, because the key layout is a contract
// with docs/spec/data-model.md and with every later migration sweep, and nothing
// in the round trip above would notice if it changed.
func TestAuthCodeItemShape(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	code := sampleAuthCode(hashOf("code-" + randomHex(8)))
	if err := store.SaveCode(ctx, code); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}

	pk := "OIDC#" + code.CodeHash
	m := rawItem(t, client, store.table, pk, "CODE")
	if len(m) == 0 {
		t.Fatalf("nothing at %s/CODE; the key layout moved", pk)
	}
	if got := getS(m, attrType); got != "authcode" {
		t.Errorf("_t = %q, want %q", got, "authcode")
	}
	// The clear-text code must never be derivable from the item: the partition
	// key is the hash and no attribute repeats it.
	if got := getS(m, attrClientID); got != code.ClientID {
		t.Errorf("clientId = %q, want %q", got, code.ClientID)
	}
	if got := getS(m, attrCredential); got != code.Credential {
		t.Errorf("credential = %q, want %q", got, code.Credential)
	}
	if got := getS(m, attrExpiresAt); got != formatTime(code.ExpiresAt) {
		t.Errorf("expiresAt = %q, want the fixed-width %q; the consume condition compares it lexicographically", got, formatTime(code.ExpiresAt))
	}

	// ttl in epoch SECONDS. Milliseconds are accepted silently by DynamoDB and
	// never acted on, so a spent flow would pin a row until somebody noticed the
	// table growing.
	av, ok := m[attrTTL]
	if !ok {
		t.Fatalf("the item carries no %q attribute; DynamoDB will never expire an abandoned authorization flow", attrTTL)
	}
	n, ok := av.(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("%s is of DynamoDB type %T, want N", attrTTL, av)
	}
	ttl, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		t.Fatalf("%s is not an integer: %q", attrTTL, n.Value)
	}
	if ttl != code.ExpiresAt.Unix() {
		t.Errorf("ttl = %d, want %d (epoch seconds); milliseconds would be %d", ttl, code.ExpiresAt.Unix(), code.ExpiresAt.UnixMilli())
	}
}

// TestAuthCodeIsSingleUse is RFC 6749 §4.1.2: a code is redeemable once.
func TestAuthCodeIsSingleUse(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	code := sampleAuthCode(hashOf("code-" + randomHex(8)))
	if err := store.SaveCode(ctx, code); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if _, err := store.ConsumeCode(ctx, code.CodeHash); err != nil {
		t.Fatalf("first ConsumeCode: %v", err)
	}
	if _, err := store.ConsumeCode(ctx, code.CodeHash); !errors.Is(err, auth.ErrInvalidCode) {
		t.Errorf("second ConsumeCode = %v, want %v", err, auth.ErrInvalidCode)
	}
	// And the record is gone, not merely refused: a code that survived its
	// redemption is one an operator dump could still resolve to a user.
	mustNotExist(t, client, store.table, authCodePK(code.CodeHash), skAuthCode)
}

// TestAuthCodeExpiryIsIndistinguishableFromAbsence is the anti-oracle property.
//
// Three situations — never issued, already redeemed, past its deadline — answer
// with the identical error, so a caller holding a code they should not have
// cannot learn which of the three they are in. The expired item is left
// physically in the table first, which is the situation DynamoDB's TTL sweeper
// leaves for up to ~48 hours and the reason the deadline is inside the condition
// rather than trusted to TTL.
func TestAuthCodeExpiryIsIndistinguishableFromAbsence(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	expired := sampleAuthCode(hashOf("expired-" + randomHex(8)))
	expired.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if err := store.SaveCode(ctx, expired); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	// The item is still there: the refusal below is the store's, not TTL's.
	if m := rawItem(t, client, store.table, authCodePK(expired.CodeHash), skAuthCode); len(m) == 0 {
		t.Fatal("the expired item was already swept, so this test proves nothing")
	}

	spent := sampleAuthCode(hashOf("spent-" + randomHex(8)))
	if err := store.SaveCode(ctx, spent); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	if _, err := store.ConsumeCode(ctx, spent.CodeHash); err != nil {
		t.Fatalf("first ConsumeCode: %v", err)
	}

	answers := map[string]error{}
	for name, hash := range map[string]string{
		"never issued":    hashOf("unknown-" + randomHex(8)),
		"already spent":   spent.CodeHash,
		"past its expiry": expired.CodeHash,
		"empty":           "",
	} {
		_, err := store.ConsumeCode(ctx, hash)
		if !errors.Is(err, auth.ErrInvalidCode) {
			t.Errorf("%s: ConsumeCode = %v, want %v", name, err, auth.ErrInvalidCode)
		}
		answers[name] = err
	}
	// Not just the same sentinel: the same rendered text, since that is what a
	// caller logging the error would compare.
	var first string
	for name, err := range answers {
		if err == nil {
			continue
		}
		if first == "" {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Errorf("%s renders as %q, another case renders as %q; the difference is an oracle", name, err.Error(), first)
		}
	}
}

// TestAuthCodeSaveOverwrites pins the contract's own rule: "SaveCode overwrites
// an existing record with the same CodeHash […] the rule exists so an
// implementation need not detect the collision". A conditional put would turn an
// ordinary retry of /authorize into a failure.
func TestAuthCodeSaveOverwrites(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	hash := hashOf("code-" + randomHex(8))
	first := sampleAuthCode(hash)
	second := sampleAuthCode(hash)
	second.ClientID = "second-client"

	if err := store.SaveCode(ctx, first); err != nil {
		t.Fatalf("first SaveCode: %v", err)
	}
	if err := store.SaveCode(ctx, second); err != nil {
		t.Fatalf("second SaveCode: %v", err)
	}
	got, err := store.ConsumeCode(ctx, hash)
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if got.ClientID != second.ClientID {
		t.Errorf("ClientID = %q, want the second write's %q", got.ClientID, second.ClientID)
	}
}

// TestAuthCodeRefusesAnEmptyHash: OIDC# is a partition key every empty-hash
// caller would build, so an empty hash must never address a real row.
func TestAuthCodeRefusesAnEmptyHash(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	code := sampleAuthCode("")
	if err := store.SaveCode(ctx, code); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("SaveCode with an empty hash = %v, want %v", err, ErrInvalidIdentifier)
	}
}

// TestAuthCodeWithoutACredential is the code the core mints with
// sessions.revokeOnPasswordReset off: Credential is empty, the item carries no
// such attribute — the omission rule, so that attribute_not_exists keeps its
// meaning — and the record reads back with it empty, which is what the core
// reads nothing of in that mode.
func TestAuthCodeWithoutACredential(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	code := sampleAuthCode(hashOf("code-" + randomHex(8)))
	code.Credential = ""
	if err := store.SaveCode(ctx, code); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	m := rawItem(t, client, store.table, "OIDC#"+code.CodeHash, "CODE")
	if _, ok := m[attrCredential]; ok {
		t.Errorf("the item carries %q with no credential to keep: %v", attrCredential, m[attrCredential])
	}
	got, err := store.ConsumeCode(ctx, code.CodeHash)
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	if got.Credential != "" {
		t.Errorf("Credential = %q, want empty", got.Credential)
	}
}

// TestAuthCodeKeepsEveryField fills every field of auth.AuthCode by reflection
// and asks for each one back. The round trip above lists the fields this store
// knew when it was written; this one fails on the first pin whose AuthCode
// grows a field the store does not map — which is how AuthCode.Credential
// (core v0.16.0) would have been dropped in silence, and with it every code
// redeemed under sessions.revokeOnPasswordReset.
func TestAuthCodeKeepsEveryField(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	var want auth.AuthCode
	rv := reflect.ValueOf(&want).Elem()
	for i := 0; i < rv.NumField(); i++ {
		f, name := rv.Field(i), rv.Type().Field(i).Name
		switch {
		case name == "CodeHash":
			f.SetString(hashOf("code-" + randomHex(8)))
		case name == "TenantID":
			f.SetString("acme") // the store validates the tenant's shape
		case f.Kind() == reflect.String:
			f.SetString(strings.ToLower(name) + "-" + randomHex(4))
		case f.Type() == reflect.TypeOf(time.Time{}):
			f.Set(reflect.ValueOf(time.Now().UTC().Add(5 * time.Minute).Truncate(time.Millisecond)))
		default:
			t.Fatalf("auth.AuthCode.%s is a %s, which this test does not know how to fill; teach it, and map the field in SaveCode and authCodeFromItem", name, f.Type())
		}
	}
	if err := store.SaveCode(ctx, want); err != nil {
		t.Fatalf("SaveCode: %v", err)
	}
	got, err := store.ConsumeCode(ctx, want.CodeHash)
	if err != nil {
		t.Fatalf("ConsumeCode: %v", err)
	}
	gv := reflect.ValueOf(got)
	for i := 0; i < rv.NumField(); i++ {
		name := rv.Type().Field(i).Name
		w, g := rv.Field(i).Interface(), gv.Field(i).Interface()
		if wt, ok := w.(time.Time); ok {
			if !wt.Equal(g.(time.Time)) {
				t.Errorf("AuthCode.%s = %v, want %v", name, g, w)
			}
			continue
		}
		if !reflect.DeepEqual(w, g) {
			t.Errorf("AuthCode.%s = %#v, want %#v: SaveCode or authCodeFromItem does not map it", name, g, w)
		}
	}
}

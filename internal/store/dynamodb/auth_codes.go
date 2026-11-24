package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// auth.AuthCodeStore: the OIDC authorization codes the IdP mints at /authorize
// and spends at /token (data-model.md §1.7), one item per code at
// OIDC#<sha256(code)> / CODE.
//
// The core's default for this store is a process-local map, and its own comment
// says what that costs here: "correct only while both endpoints are served by
// the same process: a serverless runtime or any deployment with more than one
// instance must supply a shared implementation, or /token will answer
// invalid_grant for every code minted by a sibling process" (store.go,
// IDPConfig.Codes). Under Lambda every invocation may be a different execution
// environment, so the map is not a degraded option, it is a broken one. This is
// the shared implementation.
//
// ── why the record is the item ───────────────────────────────────────────────
//
// Unlike the four single-use token families, an authorization code is not an
// attribute pair on a user profile: it is a record of its own — client, redirect
// URI, nonce, scope, PKCE challenge — with no natural owner to hang it off, and
// it is looked up by a hash that carries no tenant. So the hash is the partition
// key and the whole record is the item, which is also what makes ConsumeCode a
// single conditional DeleteItem.
//
// ── why a replay and an expiry are the same answer ───────────────────────────
//
// ConsumeCode answers auth.ErrInvalidCode for a code that never existed, one
// that has already been redeemed and one whose deadline has passed. That is not
// laziness about error mapping: the three are the same fact — this code cannot
// be exchanged — and any difference between them is an oracle. A caller who
// could tell "expired" from "never existed" could probe which codes were issued;
// a caller who could tell "already redeemed" from "expired" would learn that the
// code they stole had been used, which is the one thing an attacker holding a
// leaked code wants to know. The core's handler maps every error to the same
// 400 invalid_grant (idp.go), so nothing on the wire is lost either way.
//
// ── single use ──────────────────────────────────────────────────────────────
//
// ConsumeCode is a conditional DeleteItem with ALL_OLD, through the same
// consumeItemOnce primitive PendingLinkStore.Get uses, and the expiry is part of
// the condition rather than a check after the read. Exactly one of any number of
// concurrent redemptions can satisfy it, which is the guarantee RFC 6749 §4.1.2
// asks for ("the authorization code MUST NOT be used more than once") and the
// one a read-then-delete cannot provide: two Lambdas racing on a stolen code
// would both pass the read and both mint a session.

// Options.NonAtomicSingleUseTokens does not reach this store, and that is
// deliberate. The flag exists to reproduce the reference's read-then-clear for
// strict-parity testing, and the reference has no authorization server and no
// authorization codes to be strict about; the core's interface, meanwhile,
// requires the atomic form in so many words ("a conditional delete, a row lock,
// or a DEL-and-check pipeline, not a read followed by a delete"). There is
// nothing to be compatible with and a guarantee to keep, so there is no switch.

var _ auth.AuthCodeStore = (*Store)(nil)

// AuthCodes returns the auth.AuthCodeStore view of this store.
//
// A method rather than a bare type assertion at the call site, and the same
// shape Templates() has, because the core does not discover this store: it is
// handed over through IDPConfig.Codes by the composition root, which is the only
// place that knows which driver is in play.
func (s *Store) AuthCodes() auth.AuthCodeStore { return s }

// Attributes of the authorization-code item. Every one of them comes off
// auth.AuthCode and is handed straight back by ConsumeCode; the core records the
// PKCE pair and the scope as data it does not verify yet (store.go, AuthCode),
// and storing them now is what lets it start verifying them without a schema
// change.
//
// credential is AuthCode.Credential (core v0.16.0): under
// sessions.revokeOnPasswordReset the core sets it at /authorize to an HMAC,
// under the access-token secret, of the password hash the login proved, and
// /token refuses a code whose credential is empty or no longer the account's —
// which is how a code minted before a revoking reset opens no session after
// it. A store that dropped it would make every code redeemed under the option
// fail, so it is kept like the rest. It is a fingerprint and not the hash: it
// reveals nothing about the password without the secret, and it lives as long
// as the code does. With the option off the core leaves it empty and the item
// carries no such attribute.
const (
	attrClientID            = "clientId"
	attrRedirectURI         = "redirectUri"
	attrNonce               = "nonce"
	attrScope               = "scope"
	attrCodeChallenge       = "codeChallenge"
	attrCodeChallengeMethod = "codeChallengeMethod"
	attrCredential          = "credential"
)

// SaveCode writes one authorization code.
//
// Unconditional, as MemoryAuthCodeStore is (feature_stores.go): the core mints a
// 24-byte random token and stores its sha256, so "already there" is a collision
// rather than a constraint, and the interface says so out loud — "SaveCode
// overwrites an existing record with the same CodeHash […] the rule exists so an
// implementation need not detect the collision".
//
// The item carries both expiresAt and ttl, for the reason every TTL-bearing item
// in this package does: ttl is DynamoDB's best-effort sweep, which can lag a
// deadline by roughly 48 hours, and expiresAt is what the consume condition
// actually enforces (§4.5).
func (s *Store) SaveCode(ctx context.Context, code auth.AuthCode) error {
	if err := checkHash("authorization code hash", code.CodeHash); err != nil {
		return err
	}
	// The tenant is validated but not keyed on: the code is addressed by its
	// hash, and the tenant travels inside the record and is read back out of it,
	// which is how a capability-keyed item stays tenant-safe (§3).
	if err := s.checkTenant(code.TenantID); err != nil {
		return err
	}

	it := item{}.
		sAlways(attrPK, authCodePK(code.CodeHash)).
		sAlways(attrSK, skAuthCode).
		stamp(typeAuthCode).
		s(attrUserID, code.UserID).
		s(attrTenantID, code.TenantID).
		s(attrClientID, code.ClientID).
		s(attrRedirectURI, code.RedirectURI).
		s(attrNonce, code.Nonce).
		s(attrScope, code.Scope).
		s(attrCodeChallenge, code.CodeChallenge).
		s(attrCodeChallengeMethod, code.CodeChallengeMethod).
		s(attrCredential, code.Credential).
		t(attrExpiresAt, code.ExpiresAt).
		t(attrCreatedAt, s.nowUTC())
	if !code.ExpiresAt.IsZero() {
		it = it.ttl(code.ExpiresAt)
	}

	if _, err := s.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName: aws.String(s.table),
		Item:      it,
	}); err != nil {
		return wrap("save authorization code", err)
	}
	return nil
}

// ConsumeCode redeems a code exactly once.
//
// The conditional DeleteItem is the whole single-use guarantee; see the file
// comment. Both failure shapes consumeItemOnce distinguishes — the item was
// never there, and it was there but past its deadline — are mapped to the same
// auth.ErrInvalidCode on purpose.
//
// An expired item is left in the table for TTL rather than deleted here, which
// is consumeItemOnce's own behaviour: a later call answers ErrInvalidCode either
// way, and a read method that writes is worth avoiding when nothing requires it.
func (s *Store) ConsumeCode(ctx context.Context, codeHash string) (auth.AuthCode, error) {
	if err := checkHash("authorization code hash", codeHash); err != nil {
		// An empty hash must not resolve to whatever such a key happens to hold,
		// and the caller-facing answer is the same either way.
		return auth.AuthCode{}, auth.ErrInvalidCode
	}
	m, err := s.consumeItemOnce(ctx, authCodePK(codeHash), skAuthCode, attrExpiresAt,
		auth.ErrInvalidCode, auth.ErrInvalidCode)
	if err != nil {
		return auth.AuthCode{}, err
	}
	return authCodeFromItem(codeHash, m)
}

// authCodeFromItem decodes the pre-image ConsumeCode deleted.
//
// CodeHash is restored from the argument rather than from an attribute of its
// own: it is the partition key, so storing it twice would be a second copy of
// the same value with nothing keeping the two in step. The core reads the field
// back (it re-checks ExpiresAt and ClientID after a consume, idp.go), so it has
// to be populated.
func authCodeFromItem(codeHash string, m map[string]types.AttributeValue) (auth.AuthCode, error) {
	if err := checkVersion(m, typeAuthCode); err != nil {
		return auth.AuthCode{}, err
	}
	code := auth.AuthCode{
		CodeHash:            codeHash,
		UserID:              getS(m, attrUserID),
		TenantID:            getS(m, attrTenantID),
		ClientID:            getS(m, attrClientID),
		Nonce:               getS(m, attrNonce),
		RedirectURI:         getS(m, attrRedirectURI),
		CodeChallenge:       getS(m, attrCodeChallenge),
		CodeChallengeMethod: getS(m, attrCodeChallengeMethod),
		Scope:               getS(m, attrScope),
		Credential:          getS(m, attrCredential),
	}
	var err error
	if code.ExpiresAt, err = getTime(m, attrExpiresAt); err != nil {
		return auth.AuthCode{}, err
	}
	return code, nil
}

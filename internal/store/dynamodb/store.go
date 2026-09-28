// Package dynamodb implements the awesome-go-auth store interfaces on a single
// DynamoDB table, following docs/spec/data-model.md.
//
// The AWS SDK is confined to this package and to internal/integration/aws: the
// auth core stays cloud-agnostic, so nothing here leaks upward except the
// interfaces the core already declares.
//
// Two rules shape every method below and are worth stating once rather than
// repeating at each call site:
//
//   - No constraint is enforced by reading and then writing. Uniqueness,
//     single-use and rotation are all ConditionExpressions, so two concurrent
//     invocations of the same Lambda cannot both win.
//   - Tenant isolation lives in the partition key, never in a FilterExpression.
//     A query for tenant A physically cannot touch tenant B's partition.
package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// API is the slice of the DynamoDB client this store actually uses. Taking an
// interface rather than *dynamodb.Client keeps the fault-injection tests honest
// and documents the blast radius of the IAM policy the Lambda needs.
type API interface {
	GetItem(ctx context.Context, in *awsddb.GetItemInput, optFns ...func(*awsddb.Options)) (*awsddb.GetItemOutput, error)
	PutItem(ctx context.Context, in *awsddb.PutItemInput, optFns ...func(*awsddb.Options)) (*awsddb.PutItemOutput, error)
	UpdateItem(ctx context.Context, in *awsddb.UpdateItemInput, optFns ...func(*awsddb.Options)) (*awsddb.UpdateItemOutput, error)
	DeleteItem(ctx context.Context, in *awsddb.DeleteItemInput, optFns ...func(*awsddb.Options)) (*awsddb.DeleteItemOutput, error)
	Query(ctx context.Context, in *awsddb.QueryInput, optFns ...func(*awsddb.Options)) (*awsddb.QueryOutput, error)
	TransactWriteItems(ctx context.Context, in *awsddb.TransactWriteItemsInput, optFns ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error)
	BatchGetItem(ctx context.Context, in *awsddb.BatchGetItemInput, optFns ...func(*awsddb.Options)) (*awsddb.BatchGetItemOutput, error)
	BatchWriteItem(ctx context.Context, in *awsddb.BatchWriteItemInput, optFns ...func(*awsddb.Options)) (*awsddb.BatchWriteItemOutput, error)
}

// Defaults for Options. Exported so the config layer can document them without
// duplicating the numbers.
const (
	// DefaultIndexName is the single sparse GSI (data-model.md §2.1).
	DefaultIndexName = "GSI1"

	// DefaultSessionTTLGrace keeps a session item alive past its expiry so a
	// replayed refresh token still finds the family to revoke (§4.5).
	DefaultSessionTTLGrace = 24 * time.Hour

	// DefaultMaxSessionsPerUser caps ListSessionsForUser, whose interface has no
	// cursor parameter (§8.6). One user reaching four digits of live sessions is
	// an incident, not a page to render, so the store refuses rather than
	// silently truncating.
	DefaultMaxSessionsPerUser = 1000

	// DefaultMaxTenants caps TenantStore.GetAllTenants, the first of the two
	// interfaces §8.6 left open.
	//
	// A thousand, and the number is chosen against the partition rather than
	// against the screen: every tenant is one item in the single TENANTS
	// partition (§2.3), so a deployment with six figures of tenants has a hot
	// partition long before it has a slow listing, and the cap is where this
	// store says so. The route above it renders a table; nobody reads four
	// digits of rows.
	DefaultMaxTenants = 1000

	// DefaultMaxUsersPerTenant caps TenantStore.GetUsersForTenant, the second.
	//
	// Ten thousand rather than a thousand, because this one is genuinely a
	// membership list and a tenant with ten thousand members is a customer, not
	// an incident — where a tenant with ten thousand *tenants* is neither. It is
	// still a refusal and not a truncation: a membership list that silently ends
	// early is one the caller cannot tell from a complete one, and the caller
	// here is an admin screen and, in the reference, a user-listing fallback.
	DefaultMaxUsersPerTenant = 10000

	// DefaultMaxMetadataKeysPerUser caps GetMetadata and ClearMetadata, whose
	// interface likewise has no cursor.
	//
	// §6.3 asked for an aggregate byte cap per user instead. That is not what
	// this is, and the change is deliberate: metadata is one item per key, so an
	// aggregate cap could only be enforced by reading the whole set on every
	// UpdateMetadata — turning the one write that has no read into a
	// read-modify-write, to defend a limit that DynamoDB does not impose (the
	// 400 KB item limit binds per item, and a Query result is not an item). What
	// actually needs bounding is the aggregate GetMetadata returns, and a key
	// count plus the per-value cap below bounds it.
	DefaultMaxMetadataKeysPerUser = 1000

	// DefaultTelemetryRetention is how long a recorded event lives before TTL
	// reaps it, and — because a store cannot query what it has deleted — also
	// the default lower bound of TelemetryStore.Query when the filter names no
	// Since.
	//
	// Ninety days is the reference's own nothing: it ships no retention and no
	// implementation, so the number is this port's. It is chosen so that the two
	// meanings agree, which is the property that matters: a query with no time
	// range returns everything the store still holds, exactly as
	// MemoryTelemetryStore's does.
	DefaultTelemetryRetention = 90 * 24 * time.Hour
)

// Options configures a Store. TableName is the only required field.
type Options struct {
	// TableName is the single table every item lives in.
	TableName string

	// IndexName is the sparse by-owner GSI. Defaults to DefaultIndexName.
	IndexName string

	// Now is the clock. Injected so tests can pin expiries; defaults to
	// time.Now.
	Now func() time.Time

	// MultiTenant rejects an empty tenant id at the store boundary. With it
	// off, "" is an ordinary tenant value and maps to its own partition — which
	// is exactly what the auth core does (memory_store.go:32-34), so a
	// single-tenant deployment needs no special case.
	MultiTenant bool

	// NonAtomicSingleUseTokens restores the reference implementation's
	// read-then-clear for single-use tokens, for strict-parity testing. The
	// default (false) makes GetUserBy*TokenHash the consuming write, so two
	// callers racing on the same link cannot both pass (§4.1). Stated as an
	// opt-out because the safe behaviour must be what a zero-value Options
	// gives you.
	NonAtomicSingleUseTokens bool

	// SessionTTLGrace defaults to DefaultSessionTTLGrace.
	SessionTTLGrace time.Duration

	// MaxSessionsPerUser defaults to DefaultMaxSessionsPerUser.
	MaxSessionsPerUser int

	// MaxLinkedAccountsPerUser caps ListForUser, whose interface likewise has no
	// cursor. Defaults to DefaultMaxLinkedAccountsPerUser.
	MaxLinkedAccountsPerUser int

	// MaxPageWindow caps limit+offset on every offset-paged listing — the three
	// v0.8.0 admin listers, APIKeyAdminStore.ListAll and
	// WebhookAdminStore.ListWebhooks. Defaults to DefaultMaxPageWindow; see
	// paging.go for why an offset needs a ceiling at all.
	MaxPageWindow int

	// MaxTenants caps GetAllTenants and MaxUsersPerTenant GetUsersForTenant.
	// Default to DefaultMaxTenants and DefaultMaxUsersPerTenant.
	MaxTenants        int
	MaxUsersPerTenant int

	// MaxMetadataKeysPerUser caps GetMetadata and ClearMetadata. Defaults to
	// DefaultMaxMetadataKeysPerUser.
	MaxMetadataKeysPerUser int

	// TelemetryRetention is the TTL every recorded telemetry event is written
	// with, and the default lower bound of a Query whose filter names no Since.
	// Defaults to DefaultTelemetryRetention.
	TelemetryRetention time.Duration

	// Logger receives the once-per-process warnings this store emits. Defaults
	// to slog.Default().
	Logger *slog.Logger
}

// Store implements every store interface awesome-go-auth v0.8.0 declares, with
// one deliberate exception.
//
// From store.go: UserStore, UserAccountStore, UserPasswordStore, SessionStore,
// SessionLookupStore, SessionAdminStore, MagicLinkStore, SMSStore,
// EmailVerificationStore, EmailChangeStore, TOTPStore, AuthCodeStore,
// UserMetadataStore (metadata.go), RolesPermissionsStore (roles.go), TenantStore
// (tenants.go) and the three v0.8.0 admin listers — AdminUserStore (users.go),
// SessionLister (sessions.go) and RoleLister (roles.go), plus the two one-flag
// profile writers UserAdminFlagStore and UserTwoFactorPolicyStore
// (user_flags.go). From account.go,
// UserPhoneStore. From template_store.go, TemplateStore (templates.go). From
// settings_store.go, SettingsStore (settings.go). From api_keys.go, the
// completed APIKeyStore and three of its four companions (api_keys.go). From
// webhook_store.go, all three webhook stores (webhooks.go). From telemetry.go,
// TelemetryStore (telemetry.go).
//
// The two OAuth stores of oauth.go are reached through Store.LinkedAccounts()
// and Store.PendingLinks(), because their interfaces both declare Save and
// Delete and no single type can satisfy both.
//
// The exception is APIKeyAuditStore, deliberately absent rather than stubbed:
// nothing calls LogUsage yet, and the core discovers the interface by type
// assertion, so a stub returning "not implemented" would make Service advertise
// a feature that fails at runtime where an absent method makes it return
// ErrFeatureNotSupported. interfaces.go carries the full argument.
//
// Implementing an interface is not the same as offering it. Most of these are
// discovered by type assertion and are therefore live the moment the core is
// handed this store; the metadata, RBAC, tenant, API key, webhook and telemetry
// stores are not — the core takes each of those by name — so they reach a route
// only when the composition root passes them, which is the admin surface's
// block and not this one's. The accessors exist (Metadata(), Roles(), Tenants(),
// APIKeys(), Webhooks(), Telemetry()) so that it can.
type Store struct {
	api   API
	table string
	index string
	now   func() time.Time

	multiTenant       bool
	consumeOnRead     bool
	ttlGrace          time.Duration
	maxSessions       int
	maxLinkedAccounts int
	maxPageWindow     int
	maxTenants        int
	maxUsersPerTenant int
	maxMetadataKeys   int
	telemetryTTL      time.Duration

	log                  *slog.Logger
	degradedOnce         sync.Once
	unknownNamespaceOnce sync.Once
	migrationScopeOnce   sync.Once
}

// New validates opts and returns a Store. It performs no I/O: the table is
// expected to exist, because creating it is an infrastructure concern and a
// cold-started Lambda must not pay a DescribeTable on the login path.
func New(api API, opts Options) (*Store, error) {
	if api == nil {
		return nil, errors.New("dynamodb: api client is required")
	}
	if opts.TableName == "" {
		return nil, errors.New("dynamodb: table name is required")
	}
	s := &Store{
		api:               api,
		table:             opts.TableName,
		index:             opts.IndexName,
		now:               opts.Now,
		multiTenant:       opts.MultiTenant,
		consumeOnRead:     !opts.NonAtomicSingleUseTokens,
		ttlGrace:          opts.SessionTTLGrace,
		maxSessions:       opts.MaxSessionsPerUser,
		maxLinkedAccounts: opts.MaxLinkedAccountsPerUser,
		maxPageWindow:     opts.MaxPageWindow,
		maxTenants:        opts.MaxTenants,
		maxUsersPerTenant: opts.MaxUsersPerTenant,
		maxMetadataKeys:   opts.MaxMetadataKeysPerUser,
		telemetryTTL:      opts.TelemetryRetention,
		log:               opts.Logger,
	}
	if s.index == "" {
		s.index = DefaultIndexName
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.ttlGrace == 0 {
		s.ttlGrace = DefaultSessionTTLGrace
	}
	if s.maxSessions == 0 {
		s.maxSessions = DefaultMaxSessionsPerUser
	}
	if s.maxLinkedAccounts == 0 {
		s.maxLinkedAccounts = DefaultMaxLinkedAccountsPerUser
	}
	if s.maxPageWindow == 0 {
		s.maxPageWindow = DefaultMaxPageWindow
	}
	if s.maxTenants == 0 {
		s.maxTenants = DefaultMaxTenants
	}
	if s.maxUsersPerTenant == 0 {
		s.maxUsersPerTenant = DefaultMaxUsersPerTenant
	}
	if s.maxMetadataKeys == 0 {
		s.maxMetadataKeys = DefaultMaxMetadataKeysPerUser
	}
	if s.telemetryTTL == 0 {
		s.telemetryTTL = DefaultTelemetryRetention
	}
	if s.log == nil {
		s.log = slog.Default()
	}
	return s, nil
}

// CompatibilityNotes lists the deviations from the reference implementation that
// are visible on the wire, so the deployment can surface them instead of
// letting a caller discover them. Each entry cites the section that argues it.
func (s *Store) CompatibilityNotes() []string {
	notes := []string{
		"POST /sessions/cleanup always reports deleted:0 — expiry is DynamoDB TTL, which produces no count (data-model.md §4.5).",
		"GET /sessions returns sessions oldest-first by creation time; the reference returns them in unspecified map order (data-model.md §5).",
		"Revoking an already-revoked session keeps the first revocation's timestamp and reason instead of overwriting them (data-model.md §4.4).",
		"POST /change-email/confirm fails rather than applying an empty address when no email change is pending; the reference would overwrite the address (data-model.md §4.1).",
		"POST /change-email/confirm fails if the pending address changed between reading the token and applying it, instead of applying the address it read (data-model.md §1.3 #22).",
		"GET /linked-accounts returns bindings ordered by provider then provider account id; the reference returns them in insertion order (data-model.md §1.5 #54).",
		"Re-linking a provider account that is already linked moves the binding and deletes the previous link id; the reference leaves the old id resolvable and still listed under its old owner (upstream nik2208/awesome-go-auth#37).",
		"POST /link-verify answers INVALID_LINK_TOKEN for an expired account-link token, where the reference answers LINK_TOKEN_EXPIRED: the store refuses to return an entry past its deadline, so the route's own expiry branch is never reached (data-model.md §4.5).",
		"Mail templates list sorted by id and UI translations sorted by page, which GET /admin/api/templates/mail and /ui will expose once the admin surface is mounted; the reference lists both in first-insertion order (data-model.md §1.6).",
		"Listing users without naming a tenant orders them by tenant then id, which GET /admin/api/users and the first-user access policy will expose once the admin surface is mounted; the reference's normative order is id alone (data-model.md §1.4 #47).",
		"Webhook subscriptions are listed, matched and looked up by provider in id order rather than in first-insertion order, so a deployment holding two inbound webhooks for one provider gets whichever has the lower id (data-model.md §1.5 #72).",
		"Telemetry queries treat an absent tenant as the untenanted tenant rather than as every tenant, and refuse outright in multi-tenant mode; the reference reads an absent tenant as no filter at all (data-model.md §1.5 #60).",
	}
	if s.consumeOnRead {
		notes = append(notes,
			"Single-use tokens and SMS codes are consumed by the lookup itself, so a failure in the step that follows burns them and the user must request a new one (data-model.md §4.1). A code that does not match burns nothing.",
			"A replayed refresh token revokes the whole session, not just that token (data-model.md §4.3).",
			"An OAuth state nonce and an account-link token are consumed by PendingLinkStore.Get, so two callers racing on one link produce exactly one winner and the loser sees an invalid token (data-model.md §1.5 #57).",
		)
	}
	return notes
}

// nowUTC is the single clock read per operation. Every timestamp the store
// writes comes from here so an item's attributes cannot disagree with each
// other by a scheduling delay.
func (s *Store) nowUTC() time.Time {
	return s.now().UTC()
}

// transactionConflictAttempts bounds the retry below. Four is enough for the
// contention this store actually sees — the transactional paths are per-login or
// rarer (data-model.md §6.3) — and small enough to stay well inside a Lambda
// deadline.
const transactionConflictAttempts = 4

// transactWrite runs a transaction and retries the one cancellation reason that
// is transient: TransactionConflict, meaning another writer held one of the same
// items and no ConditionExpression was ever evaluated.
//
// Nothing else retries it. The SDK's standard retryer covers
// TransactionInProgressException but not TransactionCanceledException
// (aws-sdk-go-v2/aws/retry/standard.go:76), so without this the constraint that
// every conditional write in this package exists to enforce would go unanswered
// exactly when it matters most — under the concurrency that produces the
// conflict. Two registrations of one address would then report an opaque error
// instead of ErrUserExists, and a losing rotation would never reach
// classifyRotationLoss and so would never revoke the replayed family.
//
// A cancelled transaction writes nothing, so a retry is a fresh attempt rather
// than a partial one, and every condition in this package is either idempotent
// for its own caller or decides the outcome on the retry.
func (s *Store) transactWrite(ctx context.Context, in *awsddb.TransactWriteItemsInput) error {
	for attempt := 0; ; attempt++ {
		_, err := s.api.TransactWriteItems(ctx, in)
		if err == nil {
			return nil
		}
		if attempt == transactionConflictAttempts-1 || !isTransactionConflict(err) {
			return err
		}
		if sleepErr := sleepCtx(ctx, backoff(attempt)); sleepErr != nil {
			return sleepErr
		}
	}
}

// The optimistic-lock primitive the two document stores share.
//
// Both the template directory (templates.go) and the runtime settings
// (settings.go) are read-modify-writes behind an interface that carries only
// the fields a patch changes: the rest has to come from somewhere, and the
// interface does not supply it. What makes the read safe in both is the same
// thing — the write re-asserts it — so the condition is written once here
// rather than hand-rolled per store, which is the same argument tokenFamily
// makes for the five single-use families in keys.go: a reviewer who has checked
// one conditional write has checked both, and a second hand-rolled copy is the
// one that quietly gets it wrong.
//
// These two live in store.go, beside transactWrite, because they are write
// primitives of the store rather than behaviour of either document.

// putIfUnchanged writes it only if the item's lock token is still the one the
// caller observed. With no token observed the condition is that none exists —
// which is also true of an absent item, so create and "an item somebody wrote by
// hand without a token" are one case; with one observed, it must still be the
// one. ALL_OLD on failure is what lets the caller retry from the current item
// without a second read.
func (s *Store) putIfUnchanged(ctx context.Context, it item, observed string) error {
	in := &awsddb.PutItemInput{
		TableName:                           aws.String(s.table),
		Item:                                it,
		ConditionExpression:                 aws.String("attribute_not_exists(#updatedAt)"),
		ExpressionAttributeNames:            exprNames(attrUpdatedAt),
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	}
	if observed != "" {
		in.ConditionExpression = aws.String("#updatedAt = :observed")
		in.ExpressionAttributeValues = map[string]types.AttributeValue{":observed": avS(observed)}
	}
	_, err := s.api.PutItem(ctx, in)
	return err
}

// nextStamp is the lock token a successful patch writes. It is the clock,
// unless the clock has not moved past the token observed — a pinned test clock,
// a coarse one, or a wall clock lagging the previous writer's — in which case it
// is one nanosecond past that token. The condition compares tokens for equality,
// so a token that failed to change would let the next stale patch through, and
// that is the one thing the token exists to prevent.
func (s *Store) nextStamp(observed string) string {
	stamp := formatTime(s.nowUTC())
	if stamp > observed {
		return stamp
	}
	last, err := parseTime(observed)
	if err != nil {
		// Not a timestamp at all, so it cannot equal one; the clock's value is
		// already distinct from it.
		return stamp
	}
	return formatTime(last.Add(time.Nanosecond))
}

// warnUnknownPendingLinkNamespace reports a PendingLinkStore key whose namespace
// this build does not recognise.
//
// It exists because the single-use classification in keys.go is a coupling to key
// builders the auth core does not export, so a core upgrade that adds a namespace
// cannot fail to compile and — since the unrecognised case is treated as
// re-readable — would not fail a test either. If the new namespace turns out to
// carry a credential, it is replayable, and this line is the only thing that says
// so. Once per process, like the rotation warning: it is a deployment-shaped
// problem, not a per-request one.
//
// Only the namespace is logged, never the rest of the key: see
// pendingLinkNamespace.
func (s *Store) warnUnknownPendingLinkNamespace(state string) {
	s.unknownNamespaceOnce.Do(func() {
		s.log.Warn("dynamodb: pending-link key in an unrecognised namespace, treated as re-readable; "+
			"if the auth core now issues a single-use credential under it, that credential can be replayed. "+
			"Add the prefix to pendingLinkSingleUsePrefixes (single-use) or "+
			"pendingLinkReReadablePrefixes (a stash entry) to silence this.",
			slog.String("namespace", pendingLinkNamespace(state)))
	})
}

func (s *Store) warnDegradedRotation() {
	s.degradedOnce.Do(func() {
		s.log.Warn("dynamodb: refresh rotation is running without a precondition; " +
			"install the rotation scope per request (dynamodb.WithRotationScope) or use RotateSession. " +
			"Concurrent refreshes of one token will both succeed and the replay will only be detected on the next use.")
	})
}

func wrap(op string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("dynamodb: %s: %w", op, err)
}

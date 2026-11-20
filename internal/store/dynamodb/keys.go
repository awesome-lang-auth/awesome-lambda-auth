package dynamodb

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// Key attribute names. GSI1's are deliberately generic so their meaning can
// differ per item type and change without renaming the index (data-model.md §7).
const (
	attrPK     = "PK"
	attrSK     = "SK"
	attrGSI1PK = "GSI1PK"
	attrGSI1SK = "GSI1SK"
	attrType   = "_t"
	attrVer    = "_v"
	attrTTL    = "ttl"
)

// keySep separates the fixed prefix from the caller-supplied segments. It is the
// reason identifiers are validated: USER#a#b and USER#a + #b are the same
// string, so a tenant id containing '#' would let one tenant forge another
// tenant's partition key.
const keySep = "#"

// keySepSuccessor is the byte immediately after keySep. It is the upper bound of
// a range query over every key of the form "<fixed-width prefix><keySep><tail>",
// whatever the tail: every such key sorts below it, and every key with a larger
// fixed-width prefix sorts above it. Appending a maximal *character* instead
// would depend on what bytes the tail may contain, which for a caller-supplied
// id is not this package's to assume.
const keySepSuccessor = "$"

// schemaVersion is stamped into _v on every item this build writes. Readers
// accept anything at or below it and must tolerate unknown attributes (§7).
const schemaVersion = 1

// Entity types, written to _t so a migration sweep can filter without inferring
// type from key prefixes (§7).
const (
	typeUser        = "user"
	typeEmail       = "email"
	typeSession     = "session"
	typeRefresh     = "refresh"
	typeToken       = "token"
	typeMember      = "member"
	typeLink        = "link"
	typeLinkID      = "linkid"
	typePendingLink = "plink"

	// The two template-directory item types (data-model.md §1.6). Distinct
	// values rather than one shared "template": they have different attribute
	// sets, and _t exists so a migration sweep can tell them apart without
	// inferring type from the sort-key prefix.
	typeMailTemplate  = "template"
	typeUITranslation = "uitranslation"

	// typeAuthCode is one OIDC authorization code (data-model.md §1.7). Its own
	// type rather than typeToken: a token pointer resolves a hash to a user and
	// is a hint the profile can outlive, while an authorization code IS the
	// record — it carries the client, the redirect URI and the PKCE challenge —
	// and a sweep over the two has nothing in common.
	typeAuthCode = "authcode"

	// typeSessionIndex is the session's directory entry: a second, tiny item in
	// the session's own partition whose only job is to carry a *constant* GSI1
	// partition key, so that SessionLister.GetAllSessions is a Query.
	//
	// Its own type rather than a second "session": a migration sweep that wanted
	// every session would otherwise have to read twice as many items and throw
	// half of them away, and the two have nothing in common but the key prefix.
	typeSessionIndex = "sessionidx"

	// typeAPIKey is the canonical API-key record, keyed by prefix, and
	// typeAPIKeyID its by-id pointer (data-model.md §1.5 #48).
	typeAPIKey   = "apikey"
	typeAPIKeyID = "keyid"

	// typeRole is a role definition and typeRoleAssignment one user's hold on
	// one role in one tenant (§1.4 #29-#37). Two types, because the definition
	// is deployment-global and the assignment is tenant-scoped — CreateRole
	// carries no tenant and AddRoleToUser does.
	typeRole           = "role"
	typeRoleAssignment = "roleassign"

	// typeMeta is one key of one user's metadata (§1.4 #26-#28).
	typeMeta = "meta"

	// typeTenant is a tenant directory entry (§1.4 #38-#42). The membership item
	// that pairs with it is typeMember and predates this: CreateUser has always
	// written one.
	typeTenant = "tenant"

	// typeWebhook is one webhook subscription, outgoing or inbound (§1.5 #72).
	typeWebhook = "webhook"

	// typeTelemetry is one recorded auth event (§1.5 #59).
	typeTelemetry = "telemetry"

	// typeSettings is the deployment's runtime settings document
	// (data-model.md §1.8). There is exactly one of them in the table, which is
	// a reason for _t rather than against it: the singleton is the item a
	// migration sweep is most likely to have to find, and finding it by type is
	// what stops that sweep from hardcoding the key.
	typeSettings = "settings"

	// typeUserID is the by-id user pointer (data-model.md §1.1 #3b): the item
	// auth.UserLookupStore.FindUserByID reads, keyed on the user id alone and
	// naming the tenant the profile lives under. Its own type rather than a
	// second "user": a sweep selecting profiles by _t must not meet it, and the
	// two have nothing in common but the id.
	typeUserID = "userid"
)

// Sort keys and partition-key prefixes for the item types this package writes.
// The full catalogue is data-model.md §2.2.
const (
	pkUserPrefix    = "USER" + keySep
	pkEmailPrefix   = "EMAIL" + keySep
	pkSessionPrefix = "SESSION" + keySep
	pkRefreshPrefix = "REFRESH" + keySep
	pkTenantPrefix  = "TENANT" + keySep

	// pkOAuthPrefix keys the linked-account item by the provider account itself,
	// because FindByProvider(provider, providerID) is the primary lookup and
	// neither it nor ListForUser nor Delete carries a tenant (§2.3, "SK=LINK#").
	pkOAuthPrefix = "OAUTH" + keySep

	// pkLinkIDPrefix is the by-id pointer Delete(id) needs: the id is the only
	// thing that method carries and it is not part of the canonical key.
	pkLinkIDPrefix = "LINKID" + keySep

	// pkPendingLinkPrefix keys the OAuth stash by the opaque state string the
	// core composes (oauth_wire.go:417-426).
	pkPendingLinkPrefix = "PLINK" + keySep

	// pkOIDCPrefix keys an OIDC authorization code by the sha256 of the code the
	// client was handed. The hash is the core's own (AuthCode.CodeHash,
	// hashToken), so a dump of this table cannot be redeemed at /token — the
	// same property the refresh, reset and magic-link partitions have.
	pkOIDCPrefix = "OIDC" + keySep

	// gsi1UserIDPrefix keys the tenant-less by-owner fan-outs. It is distinct
	// from pkUserPrefix because the items that use it (memberships, linked
	// accounts) are reachable from methods that carry no tenant id.
	gsi1UserIDPrefix = "USERID" + keySep

	// templatesPK is the directory partition every mail template and UI
	// translation set lives in (data-model.md §1.6) — a constant, not a prefix,
	// the way TENANTS is. auth.TemplateStore carries no tenant and no owner: a
	// template is deployment-global in the reference too, and one partition is
	// what makes each of the two list methods a single Query.
	templatesPK = "TEMPLATES"

	// The two sort-key namespaces of that partition. Their tails are validated
	// against idPattern, so neither can be forged into the other.
	skMailTemplatePrefix  = "MAIL" + keySep
	skUITranslationPrefix = "UI" + keySep

	// settingsPK is the partition of the runtime settings document
	// (data-model.md §1.8). A constant with no separator and no caller-supplied
	// segment, like templatesPK: auth.SettingsStore carries no tenant, no owner
	// and no id — GetSettings takes a context and nothing else — because the
	// settings are deployment-global in the reference too, one object the admin
	// Control panel patches (settings-store.interface.ts:28-40).
	//
	// Its own partition rather than a second sort key under TEMPLATES, even
	// though both are deployment-global configuration. TEMPLATES is a
	// *directory*: its two list methods are single Queries over the whole
	// partition with a begins_with, and an item that is not a template sitting in
	// it would either have to be excluded by every one of them or be returned to
	// a caller expecting a MailTemplate. A partition that holds exactly one item
	// costs nothing extra — DynamoDB charges per item, not per partition — and
	// keeps both key spaces describable in one line each.
	settingsPK = "SETTINGS"

	// skSettings is the single sort key of that partition. The settings are a
	// singleton, so the sort key is a constant, as SESSION's and PLINK's are;
	// there is nothing to name because there is nothing to distinguish.
	skSettings = "SETTINGS"

	// skAuthCode is the single sort key of the OIDC partition. The partition
	// holds exactly one item — the code — so the sort key is a constant, as
	// SESSION's and PLINK's are.
	skAuthCode = "CODE"

	// The four constant GSI1 partition keys of the directory indexes, and the one
	// prefixed one. Each exists because an interface the core added in v0.8.0
	// enumerates a whole entity type, and a key-value store can only do that as a
	// Query — which needs one partition to query.
	//
	// A constant partition key is a hot key under write load, and that is the
	// honest cost of every one of them: every registration writes to
	// gsi1AllUsersPK, every login to gsi1AllSessionsPK. Sharding (USER#0..USER#n,
	// picked by a hash of the id) is the usual answer and costs an n-way merge on
	// every read to keep the order; it is not done here, because the alternative
	// on the read side is worse and because a deployment that outgrows a single
	// GSI partition's write throughput has a shape this store should be told
	// about rather than guess at. §6.2 carries the numbers.
	//
	// None of them can collide with the prefixed GSI1PK values other item types
	// write — a session's USER#<t>#<u>, a membership's USERID#<u> — because a
	// partition key is only ever matched by equality: a Query for "USER" cannot
	// reach "USER#acme#usr_1", and there is no such thing as a begins_with on a
	// partition key.
	gsi1AllUsersPK    = "USER"
	gsi1AllSessionsPK = "SESSION"
	gsi1AllAPIKeysPK  = "APIKEY"

	// gsi1APIKeyServicePrefix keys the by-service fan-out of
	// APIKeyServiceIndexStore. It is on the *pointer* item rather than on the
	// canonical one, because the canonical one already spends its single GSI1
	// key pair on the all-keys directory; see api_keys.go.
	gsi1APIKeyServicePrefix = "APIKEYSVC" + keySep

	// gsi1RolePrefix keys a role's assignments, so DeleteRole can find every
	// user holding it without a Scan (§1.4 #33).
	gsi1RolePrefix = "ROLE" + keySep

	// rolesPK is the directory partition every role definition lives in, exactly
	// as tenantsPK is for tenants and templatesPK for templates.
	//
	// data-model.md §1.4 originally keyed a definition at PK=ROLE#<role>, one
	// partition each. That was correct for every method that names a role, and
	// impossible for the one that does not: RoleLister.GetAllRoles (core v0.8.0)
	// enumerates the set, and a per-role partition can only be enumerated by a
	// table Scan. The definitions are a bounded, human-authored set written by an
	// administrator, so one partition costs nothing and buys the Query. §2.3's
	// argument for the tenant directory is this argument.
	rolesPK = "ROLES"

	// skRolePrefix is both the sort key of a definition under rolesPK and the
	// sort key of an assignment under USER#<t>#<u>. One constant, because the
	// role name is the tail of both and a second declaration of the same string
	// is what lets a codec and a condition drift apart.
	skRolePrefix = "ROLE" + keySep

	// tenantsPK is the tenant directory partition (§2.2). Its entries' sort key
	// is tenantPK(id) — the same TENANT#<t> string the membership item already
	// carries as its GSI1SK, which is what makes GetTenantsForUser a Query
	// followed by a BatchGet with no key rewriting in between.
	tenantsPK = "TENANTS"

	// pkUserMetaPrefix is the partition of one user's metadata.
	//
	// Not USER#<t>#<u>, which is where data-model.md §1.4 #26-#28 put it, and the
	// correction is forced rather than chosen: UserMetadataStore's three methods
	// take (ctx, userID) and no tenant (core store.go), so no implementation can
	// name the tenant segment of that key. §8.1 recorded this as an open question
	// with "read the tenant off the request-scoped principal" as the interim and
	// an upstream signature widening as the fix. Neither is needed. The
	// linked-account item already solves the same problem the same way — it is
	// keyed globally and carries no tenantId, "deliberately absent", because
	// FindByProvider, ListForUser and Delete all lack a tenant too (§5) — and a
	// user id is unique across tenants by construction, so a partition keyed by
	// it alone is exactly as isolating as one keyed by both. §8.1 is closed by
	// this, not deferred.
	pkUserMetaPrefix = "USERMETA" + keySep

	// skMetaPrefix is the sort key of one metadata entry. Per key, not one item
	// holding a map: that is what makes UpdateMetadata's merge a write with no
	// read (§2.3).
	skMetaPrefix = "META" + keySep

	// pkAPIKeyPrefix keys the canonical API-key record by its prefix, because
	// FindByPrefix is the hot path and must be one GetItem; pkKeyIDPrefix is the
	// by-id pointer the four cold methods need, since Revoke, UpdateLastUsed,
	// FindByID and Delete all carry an id and nothing else (§2.3).
	pkAPIKeyPrefix = "APIKEY" + keySep
	pkKeyIDPrefix  = "KEYID" + keySep

	// webhooksPK is the webhook directory partition. One partition, like
	// TEMPLATES, and for the same reasons: the set is bounded and
	// administrator-authored, every read of it is a whole-partition Query, and a
	// strongly-consistent one means the admin who just saved a subscription sees
	// it in the next listing.
	webhooksPK = "WEBHOOKS"

	// skWebhookPrefix is the sort key namespace under it. The tail is the store's
	// own id, so a configuration is addressable by the id UpdateWebhook and
	// RemoveWebhook carry without a second pointer item.
	skWebhookPrefix = "WHK" + keySep

	// pkTelemetryPrefix keys one day of one tenant's events (§1.5 #59). Day
	// buckets rather than one partition per tenant, because the filter's only
	// mandatory-shaped dimension is a time range and an unbucketed tenant
	// partition would grow without bound.
	pkTelemetryPrefix = "TEL" + keySep

	// pkUIDPrefix keys the by-id user pointer, UID#<u>, which is what makes
	// auth.UserLookupStore one GetItem: the method carries an id and no tenant,
	// and every other user item has the tenant in its key (user_lookup.go,
	// FindUserByID).
	//
	// Why it cannot collide with anything. Every prefixed partition key in this
	// table is a word followed by keySep, and no other word is "UID": two keys
	// with different words differ before their first '#', and the tail cannot
	// smuggle one in because the user id is idPattern-checked and '#'-free. The
	// constant partitions (TENANTS, ROLES, TEMPLATES, SETTINGS, WEBHOOKS) carry
	// no '#' at all. Not "USERID#", although that is the word that reads best:
	// it is already gsi1UserIDPrefix, the by-owner fan-out's GSI1 partition
	// key. That would not be a collision either — a main-table key and an index
	// key never meet — but one string meaning two things in one table is the
	// confusion this catalogue exists to prevent, and "USERBYID#" would sort
	// among the USER# partitions in a console listing without being one.
	pkUIDPrefix = "UID" + keySep

	skProfile = "PROFILE"
	skEmail   = "EMAIL"

	// skSessionIndex is the sort key of the session's directory entry, in the
	// session's own partition. Chosen to sort *after* skSession ("SIDX" >
	// "SESSION") so that a future unconditioned Query of a session partition
	// returns the session first.
	skSessionIndex = "SIDX"

	skAPIKey       = "APIKEY"
	skKeyID        = "KEYID"
	skSession      = "SESSION"
	skRefresh      = "REFRESH"
	skToken        = "TOKEN"
	skOAuth        = "OAUTH"
	skLinkID       = "LINKID"
	skPendingLink  = "PLINK"
	skMemberPrefix = "MEMBER" + keySep

	// skUID is the single sort key of the by-id user pointer's partition, a
	// constant as LINKID's and KEYID's are: the partition holds exactly one
	// item.
	skUID = "UID"
)

// idPattern is the accepted shape of a tenant, user or session identifier. It
// admits everything awesome-go-auth generates ("usr_"/"ses_" + 32 hex chars,
// security.go:18-26) and excludes '#', which is what makes the composite keys
// unambiguous. An empty tenant id is handled separately, in checkTenant.
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// maxEmailKeyLen bounds the email segment of EMAIL#<t>#<email>. DynamoDB's own
// limit is 2048 bytes for a partition key; 320 is the longest address RFC 5321
// permits, and rejecting longer input here turns a mysterious
// ValidationException into a typed error at the boundary.
const maxEmailKeyLen = 320

// Sentinel errors for input the store refuses to turn into a key. They are
// separate from the auth core's errors because they signal a caller bug, not an
// authentication outcome.
var (
	// ErrInvalidIdentifier means a caller-supplied key segment — a tenant, user
	// or session id, an OAuth provider or provider account id, a pending-link
	// state — would produce an ambiguous or malformed key.
	ErrInvalidIdentifier = errors.New("dynamodb: invalid identifier")

	// ErrTenantRequired means multi-tenancy is on and the caller passed the
	// empty tenant. It is a typed error rather than a silent default: both
	// substituting a configured tenant and treating "" as a wildcard would
	// merge or leak tenants (data-model.md §3).
	ErrTenantRequired = errors.New("dynamodb: tenant id is required in multi-tenant mode")

	// ErrInvalidEmail means an email address cannot be used as a key segment.
	ErrInvalidEmail = errors.New("dynamodb: invalid email address")
)

// checkTenant validates a tenant id. "" is a real, distinct tenant — the
// single-tenant deployment's tenant — and maps to the literal partition
// USER##<u>. It is only rejected when multi-tenancy is enabled, where an
// unkeyed write is a bug worth failing loudly (data-model.md §3).
func (s *Store) checkTenant(tenantID string) error {
	if tenantID == "" {
		if s.multiTenant {
			return ErrTenantRequired
		}
		return nil
	}
	if !idPattern.MatchString(tenantID) {
		return fmt.Errorf("%w: tenant %q", ErrInvalidIdentifier, tenantID)
	}
	return nil
}

func checkID(kind, id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("%w: %s %q", ErrInvalidIdentifier, kind, id)
	}
	return nil
}

// checkHash guards the hash-keyed capability items. The value occupies the only
// variable segment of its partition key, so '#' inside it is unambiguous and
// need not be rejected; an empty hash, however, would build a key that any
// other empty-hash caller also builds, so it is refused.
func checkHash(kind, hash string) error {
	if hash == "" {
		return fmt.Errorf("%w: empty %s", ErrInvalidIdentifier, kind)
	}
	return nil
}

// Bounds on the caller-supplied values that occupy the only variable segment of
// a key. DynamoDB's own limits are 2048 bytes for a partition key and 1024 for a
// sort key; these are far below both, and are here so a value that cannot work
// is refused at the boundary with a typed error rather than deep inside the SDK.
//
// They are generous because none of these three is this package's to define: a
// role name, a metadata key and an API key's service id are all whatever the
// deployment says they are.
const (
	maxRoleNameLen  = 256
	maxMetaKeyLen   = 256
	maxServiceIDLen = 256

	// maxAPIKeyPrefixLen is generous for the same reason and tighter for one
	// more: the core mints an 11-character prefix (`ak_` plus 8 hex, api_keys.go)
	// and nothing longer is reachable through it, so this bound exists only to
	// stop a hand-built record from producing a key DynamoDB refuses.
	maxAPIKeyPrefixLen = 128
)

// checkOpaque validates a caller-supplied value that occupies the *only*
// variable segment of its key. '#' inside such a value is unambiguous and is
// therefore allowed — the rule checkProviderAccountID and checkStateKey already
// apply — so exactly three shapes are refused: the empty string, because every
// other empty-valued caller would build the same key; a value long enough to
// risk DynamoDB's key limit; and a control character, which would otherwise
// surface as an opaque ValidationException.
func checkOpaque(kind, v string, max int) error {
	switch {
	case v == "":
		return fmt.Errorf("%w: empty %s", ErrInvalidIdentifier, kind)
	case len(v) > max:
		return fmt.Errorf("%w: %s longer than %d bytes", ErrInvalidIdentifier, kind, max)
	case strings.ContainsAny(v, "\x00\n\r"):
		return fmt.Errorf("%w: %s contains a control character", ErrInvalidIdentifier, kind)
	}
	return nil
}

// checkServiceID is checkOpaque with the empty string allowed, because
// APIKeyRecord.ServiceID is optional: the reference's listByServiceId("") is a
// query for exactly the keys that left it unset, and refusing "" here would make
// those keys unreachable through the interface that exists to reach them.
func checkServiceID(serviceID string) error {
	if serviceID == "" {
		return nil
	}
	return checkOpaque("service id", serviceID, maxServiceIDLen)
}

// normalizeEmail mirrors the core's normalization (service.go:58) so the key
// this store computes is the key the core expects. It is duplicated rather than
// imported because it is unexported there.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func checkEmail(email string) error {
	switch {
	case email == "":
		return fmt.Errorf("%w: empty", ErrInvalidEmail)
	case len(email) > maxEmailKeyLen:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidEmail, maxEmailKeyLen)
	case strings.ContainsAny(email, "\x00\n\r"):
		return fmt.Errorf("%w: contains a control character", ErrInvalidEmail)
	}
	return nil
}

// userPK is USER#<t>#<u>: the tenant is inside the partition key, which is what
// makes cross-tenant reads unwritable rather than merely wrong.
func userPK(tenantID, userID string) string {
	return pkUserPrefix + tenantID + keySep + userID
}

// emailPK is the uniqueness item. Because the tenant segment is '#'-free the
// split is unambiguous however odd the address is.
func emailPK(tenantID, email string) string {
	return pkEmailPrefix + tenantID + keySep + email
}

func sessionPK(sessionID string) string { return pkSessionPrefix + sessionID }

func refreshPK(hash string) string { return pkRefreshPrefix + hash }

func tenantPK(tenantID string) string { return pkTenantPrefix + tenantID }

func memberSK(userID string) string { return skMemberPrefix + userID }

// uidPK is the by-id user pointer's partition, UID#<u>; see pkUIDPrefix.
func uidPK(userID string) string { return pkUIDPrefix + userID }

// userGSI1SK is the admin user directory's sort key: <tenantID>#<id>.
//
// It is the shape the upstream author designed AdminUserStore.ListUsers against
// (core store.go), and both forms of the method fall out of it — the unscoped
// one as a Query with no sort-key condition, the scoped one as a begins_with on
// tenantID+"#". Deliberately not partitioned by tenant: that would serve the
// scoped form and force a cross-partition Scan for the unscoped one, which is
// the form both of the reference's own consumers use.
//
// The tenant segment is '#'-free (idPattern), so begins_with("acme#") cannot
// reach tenant "acmecorp", and the split is unambiguous however odd the user id
// is.
//
// The order this produces for the unscoped listing is (TenantID, ID) rather than
// ID alone. That is a deviation from the core's normative order, the upstream
// author predicted it — "and that is the downstream store's to register" — and
// CompatibilityNotes registers it.
func userGSI1SK(tenantID, userID string) string {
	return tenantID + keySep + userID
}

// roleSK is the sort key of a role definition under rolesPK and of a role
// assignment under a user partition.
func roleSK(role string) string { return skRolePrefix + role }

// roleFromSK is the inverse. The role name is not duplicated into an attribute
// of its own on the assignment item, so the sort key is the one place it lives.
func roleFromSK(sk string) (string, bool) { return strings.CutPrefix(sk, skRolePrefix) }

// gsi1Role keys a role's assignments for the DeleteRole sweep.
func gsi1Role(role string) string { return gsi1RolePrefix + role }

// userMetaPK is the partition of one user's metadata; see pkUserMetaPrefix for
// why the tenant is not in it.
func userMetaPK(userID string) string { return pkUserMetaPrefix + userID }

func metaSK(key string) string { return skMetaPrefix + key }

func metaKeyFromSK(sk string) (string, bool) { return strings.CutPrefix(sk, skMetaPrefix) }

// tenantDirSK is the sort key of a tenant directory entry. It is tenantPK's
// string by construction rather than by coincidence: the membership item's
// GSI1SK already carries it, and GetTenantsForUser reads that value straight out
// of the index and uses it as this key.
func tenantDirSK(tenantID string) string { return tenantPK(tenantID) }

func apiKeyPK(prefix string) string { return pkAPIKeyPrefix + prefix }

func keyIDPK(keyID string) string { return pkKeyIDPrefix + keyID }

// gsi1APIKeyService keys one service identity's API keys. The service id is the
// trailing segment of a partition key, so '#' inside it is unambiguous; an empty
// one is a real value here, because APIKeyRecord.ServiceID is optional and the
// reference's listByServiceId("") would return exactly the keys that left it
// unset.
func gsi1APIKeyService(serviceID string) string { return gsi1APIKeyServicePrefix + serviceID }

func webhookSK(id string) string { return skWebhookPrefix + id }

func webhookIDFromSK(sk string) (string, bool) { return strings.CutPrefix(sk, skWebhookPrefix) }

// telemetryPK buckets one tenant's events by UTC day. The day is derived from
// the event's own timestamp, so a Query has to visit one partition per day of
// the requested range — which is what bounds TelemetryStore.Query and why the
// filter's time range is the one dimension this store insists on.
func telemetryPK(tenantID string, day time.Time) string {
	return pkTelemetryPrefix + tenantID + keySep + day.UTC().Format(telemetryDayLayout)
}

// telemetryDayLayout is the bucket granularity. A day rather than an hour or a
// month: an hour multiplies the per-query fan-out by 24 for no gain on a range
// anyone actually asks for, and a month makes one partition hold a month of a
// busy tenant's events, which is the hot-partition shape §6.2 warns about.
const telemetryDayLayout = "2006-01-02"

// telemetrySK orders one day's events by instant, then by id so the order is
// total. The timestamp is the same padded layout every other sort key in this
// table uses, for the reason tsLayout gives: DynamoDB compares bytewise.
func telemetrySK(at time.Time, eventID string) string {
	return formatTime(at) + keySep + eventID
}

func gsi1UserID(userID string) string { return gsi1UserIDPrefix + userID }

// sessionGSI1SK sorts a user's sessions by creation time. It relies on tsLayout
// being fixed-width: DynamoDB compares sort keys bytewise.
func sessionGSI1SK(createdAt, sessionID string) string {
	return skSession + keySep + createdAt + keySep + sessionID
}

// Bounds on the caller-supplied segments of the OAuth key space. DynamoDB's own
// limit is 2048 bytes for a partition key; rejecting longer input here turns a
// mysterious ValidationException into a typed error at the boundary, the same
// reason maxEmailKeyLen exists.
//
// maxProviderAccountIDLen is generous because a provider account id is whatever
// the provider says it is — a Google `sub`, a GitHub numeric id, or (on the
// account-link path, oauth_wire.go:776-779) an email address.
const (
	maxProviderAccountIDLen = 512
	maxStateKeyLen          = 1024
)

// checkProvider validates the provider name. It occupies a *middle* segment of
// OAUTH#<provider>#<providerId>, so a '#' inside it would make the split
// ambiguous and let one provider forge another's key — the same argument as for
// tenant ids, and idPattern is the same answer.
func checkProvider(provider string) error {
	if !idPattern.MatchString(provider) {
		return fmt.Errorf("%w: provider %q", ErrInvalidIdentifier, provider)
	}
	return nil
}

// checkProviderAccountID validates the provider's own account identifier. It is
// the trailing segment of its partition key, so '#' inside it is unambiguous and
// need not be rejected; empty is refused because OAUTH#google# is a key every
// other empty-id caller also builds, and a binding to "no account" is not a
// binding.
//
// MemoryLinkedAccounts would store one (oauth.go:380-399). This refuses instead:
// the only way to reach it is a provider that returned no account id, which
// HandleCallback should never have got past its profile check, and persisting it
// would make FindByProvider(provider, "") resolve to a real user.
func checkProviderAccountID(providerID string) error {
	switch {
	case providerID == "":
		return fmt.Errorf("%w: empty provider account id", ErrInvalidIdentifier)
	case len(providerID) > maxProviderAccountIDLen:
		return fmt.Errorf("%w: provider account id longer than %d bytes", ErrInvalidIdentifier, maxProviderAccountIDLen)
	case strings.ContainsAny(providerID, "\x00\n\r"):
		return fmt.Errorf("%w: provider account id contains a control character", ErrInvalidIdentifier)
	}
	return nil
}

// checkStateKey validates a PendingLinkStore key. The core composes it from a
// namespace and a nonce, a token hash or an (email, provider) pair
// (oauth_wire.go:417-426), so it is opaque here: it is the only variable segment
// of its partition key and may contain anything except the empty string, which
// every other empty-state caller would also build.
func checkStateKey(state string) error {
	switch {
	case state == "":
		return fmt.Errorf("%w: empty pending-link state", ErrInvalidIdentifier)
	case len(state) > maxStateKeyLen:
		return fmt.Errorf("%w: pending-link state longer than %d bytes", ErrInvalidIdentifier, maxStateKeyLen)
	case strings.ContainsAny(state, "\x00\n\r"):
		return fmt.Errorf("%w: pending-link state contains a control character", ErrInvalidIdentifier)
	}
	return nil
}

// oauthPK is the linked account's canonical key. The provider is '#'-free, so
// the split is unambiguous however odd the account id is.
func oauthPK(provider, providerID string) string {
	return pkOAuthPrefix + provider + keySep + providerID
}

// oauthGSI1SK sorts a user's links by provider then account, and carries both
// values in the index key so the by-owner query needs no extra projection.
func oauthGSI1SK(provider, providerID string) string {
	return skOAuth + keySep + provider + keySep + providerID
}

func linkIDPK(linkID string) string { return pkLinkIDPrefix + linkID }

func pendingLinkPK(state string) string { return pkPendingLinkPrefix + state }

// authCodePK keys an authorization code by its hash. The hash is the only
// variable segment of the partition key, so '#' inside it is unambiguous and
// need not be rejected; an empty one is refused by checkHash, because OIDC# is a
// key every other empty-hash caller would also build.
func authCodePK(codeHash string) string { return pkOIDCPrefix + codeHash }

// mailTemplateSK and uiTranslationSK key the two entries of the template
// directory under templatesPK. The id and the page are validated with checkID
// before either is called: the template ids the core defines (mailer.go:240-245,
// "password-reset" and its siblings) all satisfy idPattern, and '#' is excluded
// so MAIL#<id> cannot be made to read as anything else.
func mailTemplateSK(id string) string { return skMailTemplatePrefix + id }

func uiTranslationSK(page string) string { return skUITranslationPrefix + page }

// mailTemplateIDFromSK and uiTranslationPageFromSK are the inverses. Neither
// value is duplicated into an attribute of its own (data-model.md §5, "Mail
// template"), so the sort key is the one place it lives and these are the only
// decoders.
func mailTemplateIDFromSK(sk string) (string, bool) {
	return strings.CutPrefix(sk, skMailTemplatePrefix)
}

func uiTranslationPageFromSK(sk string) (string, bool) {
	return strings.CutPrefix(sk, skUITranslationPrefix)
}

// pendingLinkSingleUsePrefixes are the two PendingLinkStore namespaces whose
// entries are credentials spent exactly once, and are therefore consumed by the
// read that resolves them (see PendingLinks.Get).
//
// The core's own doc for the field says so — "It carries two kinds of entry,
// both keyed by an opaque string and both single-use: the in-flight OAuth state
// (so a nonce cannot be replayed) and the account-link token issued by
// /link-request" (oauth_wire.go:170-174) — and both are written by the core
// (oauth_wire.go:485, :710) and read exactly once (:530, :765).
//
// The third namespace the core knows about, "pending-link:", is deliberately not
// here. It is the host-written account-conflict stash, and LinkRequest *reads* it
// to resolve an identity (oauth_wire.go:689) while LinkVerify deletes it only
// after the link has been written (:804). Consuming it on read would make an
// ordinary retry of POST /link-request — a user whose mail never arrived, or a
// first attempt that failed its own GetUserByEmail — answer 401 UNAUTHORIZED
// instead of issuing a second token.
//
// Anything else is treated as re-readable, which is exactly MemoryPendingLinks'
// behaviour (oauth_wire.go:871-884). That is the safe default for an unknown
// namespace in one direction and the unsafe one in the other: failing to consume a
// new single-use kind loses an atomicity guarantee the reference never had, where
// consuming a new re-readable kind would silently break a working flow. The
// tie-breaker is that a broken flow is loud and a replayable credential is not — so
// the default stays "re-readable" and the silence is removed instead, by
// warnUnknownPendingLinkNamespace.
var pendingLinkSingleUsePrefixes = []string{"oauth-state:", "link-token:"}

// pendingLinkReReadablePrefixes are the namespaces this build positively knows are
// not credentials. Listing them is what makes an unrecognised namespace
// distinguishable from a deliberately re-readable one, and therefore reportable:
// this store's classification is a coupling to key builders the core does not
// export (oauth_wire.go:417-426), so a core upgrade that renames or adds one cannot
// be caught at compile time and must at least not pass in silence.
var pendingLinkReReadablePrefixes = []string{"pending-link:"}

// pendingLinkIsSingleUse reports whether a key names a credential rather than a
// stash entry.
func pendingLinkIsSingleUse(state string) bool {
	return hasAnyPrefix(state, pendingLinkSingleUsePrefixes)
}

// pendingLinkIsKnown reports whether this build recognises the key's namespace at
// all, either as a credential or as a stash entry.
func pendingLinkIsKnown(state string) bool {
	return pendingLinkIsSingleUse(state) || hasAnyPrefix(state, pendingLinkReReadablePrefixes)
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// pendingLinkNamespace is the part of a key that is safe to log: everything up to
// and including the first ':'.
//
// The remainder must never be logged. For "oauth-state:" it is the CSRF nonce
// itself, and for "link-token:" it is the sha256 of a live account-link token —
// both are the credential, not an identifier for it.
func pendingLinkNamespace(state string) string {
	if i := strings.Index(state, ":"); i >= 0 {
		return state[:i+1]
	}
	return "(no namespace)"
}

// tokenFamily is the parameterisation of the single-use token families
// (data-model.md §1.3). They differ only in a key prefix, two profile attribute
// names and — for email change — one extra attribute, so the flow is written
// once and each family is a value rather than a copy.
//
// That is deliberate beyond mere brevity: these five are the whole "issue a
// secret, consume it exactly once" surface, and a reviewer who has checked one
// conditional write has checked all of them. A fifth variant with its own
// hand-rolled condition would be the thing that quietly gets it wrong.
type tokenFamily struct {
	// name appears in error messages and in the pointer item's `family`
	// attribute, which is what makes a migration sweep over one family possible.
	name string

	// pkPrefix is the pointer item's partition-key prefix. Empty means the
	// family has no pointer item at all: GetUserBySMSCodeHash already carries
	// (userID, tenantID) (store.go:51), so the profile is directly addressable
	// and a pointer would cost a write per send and a read per verify to
	// resolve something the caller already knows (§2.3, "OTP# ephemeral item").
	pkPrefix string

	// hashAttr and expAttr are the two profile attributes that constrain each
	// other. They share one item because a DynamoDB condition is per-item: split
	// them and "the hash matches AND it has not expired" stops being expressible
	// as a single atomic check, which is the entire point of these stores.
	hashAttr string
	expAttr  string

	// extraIssueAttrs names the attributes issue writes beyond the hash and
	// expiry, for validation and documentation; the values come from the caller.
	extraIssueAttrs []string

	// extraClearAttrs are removed by Clear*Token alongside the hash and expiry,
	// and deliberately *not* by the consuming read. Email change is the reason:
	// ApplyEmailChange reads pendingEmail off the profile *after* the token has
	// been consumed (service.go:472-479), so consuming must leave it in place
	// while clearing must take it away, exactly as MemoryUserStore does
	// (memory_store.go:395).
	extraClearAttrs []string

	// invalidErr is what an unknown, already-consumed or expired value maps to.
	// SMS answers ErrInvalidCode where the token families answer ErrInvalidToken
	// (memory_store.go:238 versus :195), and the wire mapping is built on that
	// distinction, so it is a per-family property rather than a constant.
	invalidErr error
}

func (f tokenFamily) pk(hash string) string { return f.pkPrefix + hash }

// hasPointer reports whether a hash is resolved through a pointer item, i.e.
// whether the lookup method carries a tenant and user id of its own.
func (f tokenFamily) hasPointer() bool { return f.pkPrefix != "" }

// The five families. Four are pointer-backed because their lookup methods carry
// no tenant id and the profile lives under USER#<t>#<u>; SMS is not, because its
// lookup carries both.
var (
	familyReset = tokenFamily{
		name:       "reset",
		pkPrefix:   "RESET" + keySep,
		hashAttr:   "resetHash",
		expAttr:    "resetExp",
		invalidErr: auth.ErrInvalidToken,
	}

	familyMagic = tokenFamily{
		name:       "magic",
		pkPrefix:   "MAGIC" + keySep,
		hashAttr:   attrMagicHash,
		expAttr:    attrMagicExp,
		invalidErr: auth.ErrInvalidToken,
	}

	familyVerify = tokenFamily{
		name:       "verify",
		pkPrefix:   "VERIFY" + keySep,
		hashAttr:   attrVerifyHash,
		expAttr:    attrVerifyExp,
		invalidErr: auth.ErrInvalidToken,
	}

	// familyEchg carries the address the change is *to*. It is written with the
	// token and cleared with the token, so a stale token can never be the reason
	// a pending address survives.
	familyEchg = tokenFamily{
		name:            "echg",
		pkPrefix:        "ECHG" + keySep,
		hashAttr:        attrEchgHash,
		expAttr:         attrEchgExp,
		extraIssueAttrs: []string{attrPendingEmail},
		extraClearAttrs: []string{attrPendingEmail},
		invalidErr:      auth.ErrInvalidToken,
	}

	familySMS = tokenFamily{
		name:       "sms",
		hashAttr:   attrSMSHash,
		expAttr:    attrSMSExp,
		invalidErr: auth.ErrInvalidCode,
	}
)

// pointerFamilies is the set that writes a pointer item. DeleteUser sweeps them
// off the profile, and the family tests iterate it so a new family cannot be
// added without being covered.
var pointerFamilies = []tokenFamily{familyReset, familyMagic, familyVerify, familyEchg}

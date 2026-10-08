package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// Profile attributes. The four single-use families are all listed even though
// only "reset" has methods in the P1 subset: the profile item must round-trip a
// whole auth.User, so leaving the others out of the codec would silently drop
// them the first time a P2 store wrote one.
const (
	attrUserID        = "userId"
	attrTenantID      = "tenantId"
	attrEmail         = "email"
	attrPasswordHash  = "passwordHash"
	attrPhoneNumber   = "phoneNumber"
	attrFirstName     = "firstName"
	attrLastName      = "lastName"
	attrRole          = "role"
	attrEmailVerified = "isEmailVerified"

	// attrIsAdmin is auth.User.IsAdmin (models.go, new in core v0.8.0): the
	// stored flag the admin router's 'is-admin-flag' access policy reads as
	// `granted = user.isAdmin === true`. It is a persisted column with no
	// derivation behind it — the core's field doc is explicit that role-shaped
	// admin-ness belongs in RBAC and a custom predicate instead — so a store that
	// does not round-trip it is a store where nobody can ever be an
	// administrator, whatever the record says.
	attrIsAdmin = "isAdmin"

	// attrLoginProvider is auth.User.LoginProvider: the provider that created
	// the account, empty for a password registration. Dropping it made every
	// OAuth-provisioned user report loginProvider "local" on /me and on every
	// token, because the core reads an empty field as LoginProviderLocal.
	attrLoginProvider = "loginProvider"
	attrRequire2FA    = "require2FA"
	attrTOTPEnabled   = "isTotpEnabled"
	attrTOTPSecret    = "totpSecret"
	attrPendingEmail  = "pendingEmail"
	attrCreatedAt     = "createdAt"
	attrUpdatedAt     = "updatedAt"

	// attrImported carries the attributes an import brought across that no
	// auth.User field has a home for. See ImportedAttributesKey. The migration
	// marker is a separate attribute that deliberately never reaches auth.User
	// at all; it lives in migration.go.
	attrImported = "imported"

	// OAuth linked-account and pending-link attributes. They live on their own
	// item types, not on the profile, but the names belong in one place with the
	// rest so a codec and a condition cannot disagree about one.
	attrLinkID        = "linkId"
	attrProvider      = "provider"
	attrProviderID    = "providerId"
	attrName          = "name"
	attrPicture       = "picture"
	attrRedirectURL   = "redirectUrl"
	attrMetaExpiresAt = "metaExpiresAt"

	attrMagicHash  = "magicHash"
	attrMagicExp   = "magicExp"
	attrVerifyHash = "verifyHash"
	attrVerifyExp  = "verifyExp"
	attrEchgHash   = "echgHash"
	attrEchgExp    = "echgExp"
	attrSMSHash    = "smsHash"
	attrSMSExp     = "smsExp"
)

// Why the marker is on the PROFILE item, and why it is the only thing about a
// user this store reads without putting it on auth.User.
//
// The upstream password-verifier seam is handed the user record as the store
// holds it and requires the verifier to key on a marker in that record before it
// does anything at all — because the hook is reached for every account whose
// stored hash failed to verify, including OAuth-only and magic-link-only
// accounts that never had a password, from an unauthenticated route
// (awesome-go-auth/password_verifier.go). So the marker has to be readable from
// the single item the login path reads, and GetUserByEmail reads exactly one:
// the profile. A marker on the META# item would cost a second
// strongly-consistent GetItem on every single login to find out that almost
// every login does not need it.
//
// Where it does NOT go is auth.User. The seam's own example reads
// `u.Metadata["legacyIdP"]`, and that is the obvious place, but auth.User is
// what auth.NewPublicUser serialises: a marker there is a marker GET /me hands
// to the account holder, naming the source directory and the user pool id. So
// the profile read files it on the request context instead and the verifier
// takes it from there — see migration.go, which argues the carrier and cites the
// core line that makes it correct.
//
// Why not a magic placeholder in passwordHash, which the upstream doc also
// offers. It would be tidier — a placeholder can never verify, so the hook is
// reached, and adoption overwrites it, so the marker clears itself with no
// second write. It is refused because an imported Cognito user has no password
// hash at all, and an EMPTY PasswordHash is load-bearing upstream: it is what
// opens the passwordless initial-password path (wire_password_email.go:347). A
// placeholder would close that path for exactly the population that most needs
// it — a migrated person who has forgotten the password the old system held and
// wants to set one here.

// ImportedAttributesKey is the auth.User.Metadata key carrying the attributes an
// import brought across that no auth.User field has a home for — in practice a
// Cognito pool's `custom:*` schema.
//
// This is NOT this driver's implementation of UserMetadataStore, and the
// distinction is the whole reason it is a second reserved key rather than a
// general metadata round-trip. That interface is deliberately absent
// (interfaces.go) because its item type is designed and unbuilt, and half of it
// — persistence with no GetMetadata, no UpdateMetadata and no ClearMetadata —
// would make the core's type assertion advertise a feature that fails on the
// wire, which is the exact failure interfaces.go refuses. What this key is
// instead is a one-way record: written once by an import, read back with the
// user so a claims mapping or a support tool can see what the old directory
// held, and modified by nothing here.
//
// Only string values survive the round trip, because that is what a Cognito
// attribute is. A pool with a JSON blob in a custom attribute keeps the blob as
// the string it already was.
const ImportedAttributesKey = "imported"

// reservedMetadataKeys are the auth.User.Metadata keys this driver persists on
// the profile item, each under a profile attribute of the same name. Everything
// else in Metadata is dropped on write and absent on read.
//
// One table rather than two code paths, so that the encoder and the decoder
// cannot disagree about which keys are persisted, and so that the answer to
// "what of Metadata survives here" is a list somebody can read. That the list
// has one entry is the point: the migration marker is NOT on it, and cannot be
// added to it without putting the marker back on the wire.
var reservedMetadataKeys = []struct{ key, attr string }{
	{ImportedAttributesKey, attrImported},
}

// maxUserCollectionItems caps the unconditioned Query over USER#<t>#<u>. The
// collection is bounded by design — only PROFILE and ROLE# live there, metadata
// having moved to its own partition because UserMetadataStore carries no tenant
// (§1.4, corrected) — so this is a tripwire for a future child type that broke
// that rule, not a paging limit anyone should hit.
const maxUserCollectionItems = 2000

// profileItem encodes a whole auth.User. Optional values are omitted rather than
// written as NULL, which is what keeps attribute_not_exists usable as a
// condition (§5).
func profileItem(u auth.User) item {
	it := item{}.
		sAlways(attrPK, userPK(u.TenantID, u.ID)).
		sAlways(attrSK, skProfile).
		stamp(typeUser).
		sAlways(attrUserID, u.ID).
		sAlways(attrTenantID, u.TenantID).
		sAlways(attrEmail, u.Email).
		// The admin user directory (data-model.md §1.4 #47). A constant GSI1
		// partition key and a <tenantID>#<id> sort key are what make
		// AdminUserStore.ListUsers a Query in both of its forms; see ListUsers
		// and userGSI1SK.
		//
		// Written here and nowhere else, which is the whole reason this costs
		// nothing after registration: profileItem is only ever used by
		// CreateUser — every other write to a profile is an UpdateItem with an
		// explicit attribute list — and DynamoDB writes to a GSI only when an
		// indexed or projected attribute changes. Neither of these two ever
		// changes for a given user (a user's tenant and id are its main-table
		// partition key and no method moves either), and nothing else on the
		// profile is projected, so the busiest item in the table pays one index
		// write in its life.
		sAlways(attrGSI1PK, gsi1AllUsersPK).
		sAlways(attrGSI1SK, userGSI1SK(u.TenantID, u.ID)).
		s(attrPasswordHash, u.PasswordHash).
		s(attrPhoneNumber, u.PhoneNumber).
		s(attrFirstName, u.FirstName).
		s(attrLastName, u.LastName).
		s(attrRole, u.Role).
		b(attrIsAdmin, u.IsAdmin).
		s(attrLoginProvider, u.LoginProvider).
		b(attrEmailVerified, u.IsEmailVerified).
		b(attrRequire2FA, u.Require2FA).
		b(attrTOTPEnabled, u.IsTOTPEnabled).
		s(attrTOTPSecret, u.TOTPSecret).
		s(attrPendingEmail, u.PendingEmail).
		t(attrCreatedAt, u.CreatedAt).
		t(attrUpdatedAt, u.UpdatedAt).
		// The by-id pointer stamp (user_lookup.go). True on every profile this
		// codec writes, because createUser writes the pointer in the same
		// transaction; it is how the backfill tells a profile that has one from
		// a profile written before pointers existed.
		b(attrUIDPointer, true)

	// Addressed through the families rather than the bare constants, so the codec
	// and the conditional writes can never disagree about an attribute name.
	it.s(familyReset.hashAttr, u.ResetTokenHash).tp(familyReset.expAttr, u.ResetTokenExpiresAt)
	it.s(familyMagic.hashAttr, u.MagicLinkTokenHash).tp(familyMagic.expAttr, u.MagicLinkTokenExpiresAt)
	it.s(familyVerify.hashAttr, u.EmailVerificationTokenHash).tp(familyVerify.expAttr, u.EmailVerificationTokenExpiry)
	it.s(familyEchg.hashAttr, u.EmailChangeTokenHash).tp(familyEchg.expAttr, u.EmailChangeTokenExpiry)
	it.s(familySMS.hashAttr, u.SMSCodeHash).tp(familySMS.expAttr, u.SMSCodeExpiresAt)

	// The reserved metadata keys, and nothing else out of Metadata.
	// Round-tripping the whole map would put an unbounded, caller-supplied
	// document on the item every login reads, and would silently become this
	// driver's implementation of UserMetadataStore without any of that
	// interface's semantics.
	for _, r := range reservedMetadataKeys {
		if mv := stringMapAV(u.Metadata[r.key]); mv != nil {
			it.av(r.attr, mv)
		}
	}
	return it
}

// stringMapAV encodes one reserved metadata value as a DynamoDB map of strings,
// or nil when there is nothing to write.
//
// Only string-valued entries survive, and a map with none is dropped rather than
// written empty: the omission rule in §5 is what lets the REMOVE in
// UpdatePassword and an attribute_not_exists condition mean what they say, and a
// present-but-empty marker in particular would be a row that reads as
// mid-migration forever while naming no directory to ask.
func stringMapAV(v any) types.AttributeValue {
	raw, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	fields := make(map[string]types.AttributeValue, len(raw))
	for k, val := range raw {
		s, ok := val.(string)
		if !ok || s == "" {
			continue
		}
		fields[k] = avS(s)
	}
	if len(fields) == 0 {
		return nil
	}
	return &types.AttributeValueMemberM{Value: fields}
}

// stringMapFrom is the inverse: one reserved attribute as the map[string]any the
// core hands a PasswordVerifier, or nil when the attribute is absent, is not a
// map, or holds nothing this codec wrote.
func stringMapFrom(m map[string]types.AttributeValue, attr string) map[string]any {
	av, ok := m[attr].(*types.AttributeValueMemberM)
	if !ok || len(av.Value) == 0 {
		return nil
	}
	out := make(map[string]any, len(av.Value))
	for k, v := range av.Value {
		s, ok := v.(*types.AttributeValueMemberS)
		if !ok {
			continue
		}
		out[k] = s.Value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// userFromItem is the inverse. Roles, Permissions and Tenants stay nil: they
// live in other item types and the core fills them in through the optional
// stores, so inventing empty values here would hide a missing store.
//
// Metadata is the one that is no longer unconditionally nil: an imported user
// carries ImportedAttributesKey, and nothing else ever does. It does NOT carry
// the migration marker, which is read off the same item by GetUserByID and filed
// on the request context instead — see migration.go for why the one thing this
// codec reads without returning it is the one thing that must not reach a
// response body.
func userFromItem(m map[string]types.AttributeValue) (auth.User, error) {
	if err := checkVersion(m, typeUser); err != nil {
		return auth.User{}, err
	}
	u := auth.User{
		ID:              getS(m, attrUserID),
		Email:           getS(m, attrEmail),
		PasswordHash:    getS(m, attrPasswordHash),
		TenantID:        getS(m, attrTenantID),
		PhoneNumber:     getS(m, attrPhoneNumber),
		FirstName:       getS(m, attrFirstName),
		LastName:        getS(m, attrLastName),
		Role:            getS(m, attrRole),
		IsAdmin:         getBool(m, attrIsAdmin),
		LoginProvider:   getS(m, attrLoginProvider),
		IsEmailVerified: getBool(m, attrEmailVerified),
		Require2FA:      getBool(m, attrRequire2FA),
		IsTOTPEnabled:   getBool(m, attrTOTPEnabled),
		TOTPSecret:      getS(m, attrTOTPSecret),
		PendingEmail:    getS(m, attrPendingEmail),

		ResetTokenHash:             getS(m, familyReset.hashAttr),
		MagicLinkTokenHash:         getS(m, familyMagic.hashAttr),
		EmailVerificationTokenHash: getS(m, familyVerify.hashAttr),
		EmailChangeTokenHash:       getS(m, familyEchg.hashAttr),
		SMSCodeHash:                getS(m, familySMS.hashAttr),
	}
	for _, r := range reservedMetadataKeys {
		got := stringMapFrom(m, r.attr)
		if got == nil {
			continue
		}
		if u.Metadata == nil {
			u.Metadata = make(map[string]any, len(reservedMetadataKeys))
		}
		u.Metadata[r.key] = got
	}

	var err error
	if u.CreatedAt, err = getTime(m, attrCreatedAt); err != nil {
		return auth.User{}, err
	}
	if u.UpdatedAt, err = getTime(m, attrUpdatedAt); err != nil {
		return auth.User{}, err
	}
	for _, f := range []struct {
		attr string
		dst  **time.Time
	}{
		{familyReset.expAttr, &u.ResetTokenExpiresAt},
		{familyMagic.expAttr, &u.MagicLinkTokenExpiresAt},
		{familyVerify.expAttr, &u.EmailVerificationTokenExpiry},
		{familyEchg.expAttr, &u.EmailChangeTokenExpiry},
		{familySMS.expAttr, &u.SMSCodeExpiresAt},
	} {
		if *f.dst, err = getTimePtr(m, f.attr); err != nil {
			return auth.User{}, err
		}
	}
	return u, nil
}

// The two mandatory user interfaces (store.go:9-20). Unlike almost everything
// else this package pins, UserStore is not discovered by type assertion — it is
// the one store auth.WithUserStore takes by name — so a drift in *its* three
// signatures does fail the composition root's build. UserAccountStore is
// asserted, and is the pair that would go quiet: DELETE /account and
// PUT /profile would answer ErrFeatureNotSupported from a binary that built.
//
// See interfaces.go for why every interface in this package carries one of
// these, and for the convention this follows.
var (
	_ auth.UserStore        = (*Store)(nil)
	_ auth.UserAccountStore = (*Store)(nil)
)

// CreateUser writes the profile, the email-uniqueness item, the tenant
// membership and the by-id pointer in one transaction (data-model.md #1).
//
// The uniqueness constraint is the reason this is a transaction and not three
// writes: a GSI cannot enforce uniqueness and is eventually consistent, so the
// only way two concurrent registrations of one address can be made to produce
// exactly one winner is a separate item guarded by attribute_not_exists inside a
// transaction. The loser gets ErrUserExists, matching memory_store.go:39-45.
func (s *Store) CreateUser(ctx context.Context, user auth.User) (auth.User, error) {
	return s.createUser(ctx, user, MigrationMarker{})
}

// CreateMigratedUser is CreateUser plus the migration marker, written into the
// same profile item in the same transaction.
//
// It is a second method rather than a field on auth.User for the reason
// migration.go gives at length: auth.NewPublicUser serialises everything on
// auth.User, so a marker that could be *passed* on one would be a marker that
// could be *returned* on one, and the separation this design depends on would
// hold only by convention. Here it holds by signature — there is no way to write
// a marker except by naming it, and no way to read one back except through the
// request-scoped carrier.
//
// It also records the marker into that carrier, because the dual-read path
// creates a row and then hands it straight to the verifier in the same request,
// with no intervening profile read to do the recording.
func (s *Store) CreateMigratedUser(ctx context.Context, user auth.User, marker MigrationMarker) (auth.User, error) {
	created, err := s.createUser(ctx, user, marker)
	if err != nil {
		return auth.User{}, err
	}
	recordMigrationMarker(ctx, created.ID, marker)
	return created, nil
}

func (s *Store) createUser(ctx context.Context, user auth.User, marker MigrationMarker) (auth.User, error) {
	if err := s.checkTenant(user.TenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", user.ID); err != nil {
		return auth.User{}, err
	}
	user.Email = normalizeEmail(user.Email)
	if err := checkEmail(user.Email); err != nil {
		return auth.User{}, err
	}

	notExists := "attribute_not_exists(#PK)"
	names := exprNames(attrPK)

	emailIt := item{}.
		sAlways(attrPK, emailPK(user.TenantID, user.Email)).
		sAlways(attrSK, skEmail).
		stamp(typeEmail).
		sAlways(attrUserID, user.ID).
		sAlways(attrTenantID, user.TenantID)

	// The membership item is what makes GetTenantsForUser and GetUsersForTenant
	// possible without a scan. It is written here, in the same transaction, so a
	// user can never exist without one.
	//
	// Built by tenants.go's membershipItem rather than inline, now that
	// AssociateUserWithTenant writes the same item: two builders for one item
	// shape is how a codec and a condition drift apart, and here they would drift
	// into a membership that one of the two readers cannot see.
	memberIt := s.membershipItem(user.ID, user.TenantID)

	profile := profileItem(user)
	if mv := markerItem(marker); mv != nil {
		profile.av(attrMigration, mv)
	}

	err := s.transactWrite(ctx, &awsddb.TransactWriteItemsInput{
		TransactItems: []types.TransactWriteItem{
			{Put: &types.Put{
				TableName:                aws.String(s.table),
				Item:                     profile,
				ConditionExpression:      aws.String(notExists),
				ExpressionAttributeNames: names,
			}},
			{Put: &types.Put{
				TableName:                aws.String(s.table),
				Item:                     emailIt,
				ConditionExpression:      aws.String(notExists),
				ExpressionAttributeNames: names,
			}},
			// Unconditional: re-registering the same membership is a no-op, and
			// a stale membership must not fail a registration.
			{Put: &types.Put{TableName: aws.String(s.table), Item: memberIt}},
			// The by-id pointer (user_lookup.go). Its condition is the one thing
			// in this transaction that looks across tenants: the profile's own
			// attribute_not_exists covers USER#<t>#<u> and nothing else, so
			// without it an id another tenant holds would register here too, and
			// FindUserByID would have two records to choose between.
			// MemoryUserStore refuses that id at CreateUser as well.
			{Put: &types.Put{
				TableName:                 aws.String(s.table),
				Item:                      uidItem(user.ID, user.TenantID),
				ConditionExpression:       aws.String(uidClaimCondition),
				ExpressionAttributeNames:  uidClaimNames(),
				ExpressionAttributeValues: map[string]types.AttributeValue{":tenant": avS(user.TenantID)},
			}},
		},
	})
	if err != nil {
		if reasons, ok := txConditionFailures(err); ok {
			// The id, the address, or the id under another tenant was taken.
			// The reference returns the same error for all three
			// (memory_store.go:39-45), so no distinction is invented here.
			for _, i := range []int{0, 1, 3} {
				if _, failed := txFailedAt(reasons, i); failed {
					return auth.User{}, auth.ErrUserExists
				}
			}
		}
		return auth.User{}, wrap("create user", err)
	}
	return user, nil
}

// GetUserByEmail resolves the uniqueness item and then the profile. Two
// strongly-consistent GetItems, not one eventually-consistent index query: this
// is the login path, and a stale read here is a failed login (§2.3).
func (s *Store) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	email = normalizeEmail(email)
	if err := checkEmail(email); err != nil {
		return auth.User{}, err
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(emailPK(tenantID, email), skEmail),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get email pointer", err)
	}
	if len(out.Item) == 0 {
		return auth.User{}, ErrUserNotFound
	}
	if err := checkVersion(out.Item, typeEmail); err != nil {
		return auth.User{}, err
	}
	return s.GetUserByID(ctx, getS(out.Item, attrUserID), tenantID)
}

// GetUserByID reads the profile straight out of USER#<t>#<u>. There is no
// tenant comparison after the read because there cannot be one: a mismatched
// tenant addresses a different partition and simply finds nothing.
func (s *Store) GetUserByID(ctx context.Context, id, tenantID string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", id); err != nil {
		return auth.User{}, err
	}
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(userPK(tenantID, id), skProfile),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return auth.User{}, wrap("get user", err)
	}
	if len(out.Item) == 0 {
		return auth.User{}, ErrUserNotFound
	}
	// The migration marker is filed on the request context here and nowhere
	// else, because this is the read the login path makes: GetUserByEmail
	// resolves the uniqueness item and then comes straight here, so one profile
	// GetItem serves both the user and the marker. It is recorded whether or not
	// the profile carries one — "read, and there is none" is a different answer
	// from "never read", and only the second is a wiring fault worth a log line.
	// See migration.go.
	recordMigrationMarker(ctx, id, markerFromItem(out.Item))
	return userFromItem(out.Item)
}

// UpdateProfile sets the two name fields and returns the updated user.
//
// An empty name REMOVEs the attribute instead of writing "": the omission rule
// in §5 is what lets other conditions rely on attribute_not_exists, and it
// round-trips identically because a missing string decodes to "".
func (s *Store) UpdateProfile(ctx context.Context, userID, tenantID, firstName, lastName string) (auth.User, error) {
	if err := s.checkTenant(tenantID); err != nil {
		return auth.User{}, err
	}
	if err := checkID("user id", userID); err != nil {
		return auth.User{}, err
	}

	set := []string{"#updatedAt = :now"}
	remove := []string{}
	values := map[string]types.AttributeValue{":now": avS(formatTime(s.nowUTC()))}
	for _, f := range []struct {
		attr, alias, value string
	}{
		{attrFirstName, ":first", firstName},
		{attrLastName, ":last", lastName},
	} {
		if f.value == "" {
			remove = append(remove, "#"+f.attr)
			continue
		}
		set = append(set, "#"+f.attr+" = "+f.alias)
		values[f.alias] = avS(f.value)
	}

	out, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                 aws.String(s.table),
		Key:                       key(userPK(tenantID, userID), skProfile),
		UpdateExpression:          aws.String(updateExpression(set, remove)),
		ConditionExpression:       aws.String("attribute_exists(#PK)"),
		ExpressionAttributeNames:  exprNames(attrPK, attrFirstName, attrLastName, attrUpdatedAt),
		ExpressionAttributeValues: values,
		ReturnValues:              types.ReturnValueAllNew,
	})
	if err != nil {
		if isConditionFailed(err) {
			return auth.User{}, ErrUserNotFound
		}
		return auth.User{}, wrap("update profile", err)
	}
	return userFromItem(out.Attributes)
}

// DeleteUser removes the user's whole item collection plus the items outside it
// that this store wrote: the email-uniqueness item, the tenant membership and,
// when it names this tenant, the by-id pointer.
//
// Sessions are swept through GSI1, which is eventually consistent — a session
// created microseconds earlier can be missed. That is acceptable and not papered
// over: the profile is gone by then, so Service.Refresh's GetUserByID fails and
// the surviving session cannot mint a token. Refresh pointers are left to TTL for
// the same reason; a pointer to a deleted session resolves to nothing.
func (s *Store) DeleteUser(ctx context.Context, userID, tenantID string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}

	// The user collection holds only META#, PROFILE and ROLE# — all bounded —
	// so an unconditioned Query on the partition is safe (§2.2).
	collection, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                 aws.String(s.table),
		KeyConditionExpression:    aws.String("#PK = :pk"),
		ExpressionAttributeNames:  exprNames(attrPK),
		ExpressionAttributeValues: map[string]types.AttributeValue{":pk": avS(userPK(tenantID, userID))},
		ConsistentRead:            aws.Bool(true),
	}, maxUserCollectionItems)
	if err != nil {
		return wrap("query user collection", err)
	}

	var profile map[string]types.AttributeValue
	keys := make([]map[string]types.AttributeValue, 0, len(collection)+8)
	for _, it := range collection {
		if getS(it, attrSK) == skProfile {
			// Not into the batch: the profile goes last, in one transaction
			// with the by-id pointer (deleteProfileAndPointer).
			profile = it
			continue
		}
		keys = append(keys, key(getS(it, attrPK), getS(it, attrSK)))
	}
	if profile == nil {
		return ErrUserNotFound
	}

	keys = append(keys,
		key(emailPK(tenantID, getS(profile, attrEmail)), skEmail),
		key(tenantPK(tenantID), memberSK(userID)),
	)

	// Drop the single-use pointers the profile still names. They would expire on
	// their own, but the reference deletes them (memory_store.go:99-110) and a
	// pointer outliving its user is needless garbage.
	// Driven off pointerFamilies rather than a hand-written list, so a family
	// added later cannot leave its pointers behind.
	for _, f := range pointerFamilies {
		if hash := getS(profile, f.hashAttr); hash != "" {
			keys = append(keys, key(f.pk(hash), skToken))
		}
	}

	sessionKeys, err := s.sessionKeysForUser(ctx, userID, tenantID)
	if err != nil {
		return err
	}
	keys = append(keys, sessionKeys...)
	// Each session's directory entry (sessionIndexItem) lives beside it in the
	// same partition, so it needs no query of its own — but it does need
	// deleting, or GetAllSessions would go on offering an entry that resolves to
	// nothing for as long as its TTL takes to fire. pagedIndexQuery is written to
	// survive exactly that, which is why this is tidiness rather than
	// correctness; it is still not garbage worth leaving behind.
	for _, k := range sessionKeys {
		keys = append(keys, key(getS(k, attrPK), skSessionIndex))
	}

	// The OAuth bindings and their by-id pointers (data-model.md #6, "links").
	// Swept whether or not this deployment wired the LinkedAccountStore: the items
	// outlive the interface that wrote them, and a binding left behind would keep
	// resolving FindByProvider to a user who no longer exists — which
	// HandleCallback answers with ErrInvalidCredentials rather than by creating a
	// fresh account, so the provider identity would be stranded. Like the session
	// sweep this goes through GSI1 and is therefore eventually consistent; a link
	// written microseconds earlier can be missed, and is harmless for the same
	// reason.
	linkKeys, err := s.linkKeysForUser(ctx, userID)
	if err != nil {
		return err
	}
	keys = append(keys, linkKeys...)

	// The user's metadata, which lives in its own partition rather than in this
	// collection because UserMetadataStore carries no tenant (metadata.go). It is
	// swept whether or not the deployment wired the store, for the reason the
	// OAuth sweep is: the items outlive the interface that wrote them, and a
	// user id is reused by nothing, so what is left behind is unreachable garbage
	// rather than a hazard. Strongly consistent, unlike the two GSI1 sweeps
	// above, because it is a Query on the user's own partition.
	metaKeys, err := s.metadataKeys(ctx, userID)
	if err != nil {
		return err
	}
	keys = append(keys, metaKeys...)

	if err := s.deleteKeys(ctx, keys); err != nil {
		return wrap("delete user", err)
	}
	// The profile, and the by-id pointer when it is this record's. After the
	// batch rather than inside it, because a batch carries no conditions and the
	// pointer's removal must be conditional on naming this tenant — and last,
	// so a delete that failed above still finds its profile on retry.
	if err := s.deleteProfileAndPointer(ctx, userID, tenantID); err != nil {
		return wrap("delete user", err)
	}
	return nil
}

// AdminUserStore is discovered by type assertion on the user store
// (Service.ListUsers), so a drifted signature here does not fail a build: M8's
// GET /admin/api/users simply starts answering the reference's 501, and the
// 'first-user' access policy — which is `listUsers(1, 0)[0]` — starts answering
// that nobody is an administrator. See interfaces.go for the convention.
var _ auth.AdminUserStore = (*Store)(nil)

// ListUsers implements auth.AdminUserStore: one page of users, ID-ordered
// within a tenant, optionally scoped to one (data-model.md §1.4 #47).
//
// # The index, and why it is not partitioned by tenant
//
// Every profile carries GSI1PK = "USER" — a constant — and
// GSI1SK = "<tenantID>#<id>". The unscoped form is then a Query with no
// sort-key condition and the scoped form the same Query with
// begins_with(GSI1SK, tenantID+"#"). A tenant-partitioned index would serve the
// scoped form better and force a cross-partition Scan for the unscoped one,
// which is the form both of the reference's consumers use: GET /admin/api/users
// takes no tenant parameter at all (admin.router.ts:748), and the 'first-user'
// policy asks for `listUsers(1, 0)`.
//
// This replaces what §1.4 #47 originally specified — a page of
// GetUsersForTenant plus a BatchGet of profiles. That design cannot answer the
// unscoped form, and for the scoped one it answers out of the membership table,
// which is precisely the reachability dead end this interface exists to route
// around: a single-tenant deployment whose tenant has no membership rows had
// nothing to page through at all. §1.4 is corrected to this.
//
// Two costs, neither of them papered over:
//
//   - The constant partition key is a hot key under write load. Here that means
//     one GSI write per *registration* and none per login, token issue or
//     profile edit (see profileItem), so the ceiling is a registration rate, not
//     a request rate. Sharding it across USER#0..USER#n is the usual answer and
//     costs an n-way merge on every read to keep the order; §6.2 carries the
//     numbers and the escape hatch.
//   - offset is positional, and no key-value store can seek to the Nth item:
//     offset N costs reading and discarding N index entries (not N users —
//     pagedIndexQuery never resolves what it skips). Bounded, since the route
//     clamps limit to 100 and Options.MaxPageWindow clamps limit+offset, but
//     real. The only signature that removes it is a cursor, which cannot express
//     the reference's `total` arithmetic and would change the wire.
//
// # Ordering
//
// The core's normative order is ID ascending. A <tenantID>#<id> sort key gives
// (TenantID, ID) for the unscoped listing, which the upstream author predicted
// and left to "the downstream store's register"; CompatibilityNotes carries it.
// The **scoped** form is unaffected — inside one tenant the order is exactly ID
// ascending — and so is every single-tenant deployment, where all users share
// one tenant value and the two orders are the same order.
//
// # The empty tenant
//
// An empty tenantID means *no filter*: every user, in every tenant, including
// users whose own tenant is empty. That is the one place in this package where
// an empty tenant is a wildcard rather than a literal, and it is the core's
// reading rather than this store's invention — the reference's signature carries
// no tenant at all, so "every user" has to be expressible. It is also why this
// method does not go through checkTenant: refusing an empty tenant in
// multi-tenant mode, which is what that helper does everywhere else, would make
// the admin user list unusable in exactly the deployment that has more than one
// tenant. A non-empty tenant is still validated, so it cannot forge a key.
func (s *Store) ListUsers(ctx context.Context, tenantID string, limit, offset int) ([]auth.User, error) {
	in := &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		IndexName:                aws.String(s.index),
		KeyConditionExpression:   aws.String("#GSI1PK = :pk"),
		ExpressionAttributeNames: exprNames(attrGSI1PK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(gsi1AllUsersPK),
		},
	}
	if tenantID != "" {
		if !idPattern.MatchString(tenantID) {
			return nil, fmt.Errorf("%w: tenant %q", ErrInvalidIdentifier, tenantID)
		}
		in.KeyConditionExpression = aws.String("#GSI1PK = :pk AND begins_with(#GSI1SK, :prefix)")
		in.ExpressionAttributeNames = exprNames(attrGSI1PK, attrGSI1SK)
		in.ExpressionAttributeValues[":prefix"] = avS(tenantID + keySep)
	}

	// The profile indexes itself, so an index entry names its own item.
	items, err := s.pagedIndexQuery(ctx, in, limit, offset, canonicalKeyOfEntry)
	if err != nil {
		if errors.Is(err, ErrPageWindowTooLarge) {
			return nil, err
		}
		return nil, wrap("list users", err)
	}
	out := make([]auth.User, 0, len(items))
	for _, m := range items {
		u, err := userFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, nil
}

// updateExpression joins the SET and REMOVE clauses, omitting an empty one:
// DynamoDB rejects "SET" or "REMOVE" with nothing after it.
func updateExpression(set, remove []string) string {
	expr := ""
	if len(set) > 0 {
		expr = "SET " + strings.Join(set, ", ")
	}
	if len(remove) > 0 {
		if expr != "" {
			expr += " "
		}
		expr += "REMOVE " + strings.Join(remove, ", ")
	}
	return expr
}

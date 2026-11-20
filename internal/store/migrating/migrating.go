// Package migrating wraps the DynamoDB user store with the two halves of a
// migration off another identity provider: a lookup that can fall through to the
// old directory, and the marker that decides which accounts the login path is
// still allowed to ask about.
//
// # What a migration is here
//
// Two things have to cross, and they cross by different routes because one of
// them cannot be copied.
//
// The records cross in bulk, through cmd/migrate, which pages the source
// directory and writes each user with CreateUser. The passwords do not cross at
// all: a user pool hands out no password hash, by design, so there is nothing to
// import. They are collected one at a time instead, on the next login each
// person performs, through the core's password-verifier seam — the old directory
// is asked whether the password is right, and if it is, the core hashes it
// locally and never asks again (awesome-go-auth/password_verifier.go). A
// migration is finished when the last person has logged in once, and the
// operator can watch that happen by counting the rows that still carry a marker.
//
// # The marker, and why everything keys on it
//
// Every imported row carries `migration = {source, pool}` — a profile attribute
// on the DynamoDB item. It is the answer to "may this account's password be sent
// to Cognito", and the upstream seam requires a verifier to ask that question
// before it does anything else, for two reasons that both bind this package:
//
//   - The hook is reached by every login whose stored hash failed to verify,
//     which is wider than the imported rows. An account that never had a
//     password — OAuth-only, magic-link-only — carries an empty hash, so its
//     failed logins arrive too, carrying whatever plaintext the request held.
//   - The hook sits on an unauthenticated route. A verifier that calls the
//     source for any address it is handed turns POST /login into an amplifier
//     aimed at that source, and at its lockout counters, for every address an
//     attacker cares to name.
//
// The marker is also checked against the *configured* pool, not merely for
// presence. A stack repointed at a second pool must not start asking the new
// pool about accounts imported from the first: the answer would be "no such
// user" for all of them, which is harmless, and the traffic would not be.
//
// It never travels on auth.User. The profile read files it on the request
// context and the verifier takes it from there, because auth.NewPublicUser
// serialises everything on auth.User and GET <prefix>/me is that projection
// unwrapped — a marker on the record would name the source directory and the
// user pool id to whoever holds a session on a not-yet-migrated account.
// internal/store/dynamodb/migration.go argues the carrier and cites the core
// line that makes it correct; this package is its only consumer. The
// consequence here is one rule with no exception: a verifier that cannot find a
// marker for the user it was handed answers no. There is no fallback to reading
// Metadata, because a fallback is how the disclosure would come back.
//
// # What dual-read costs
//
// In dual-read mode a GetUserByEmail miss falls through to AdminGetUser and
// lazily creates the local row. That is one call to Cognito per miss, and
// GetUserByEmail is reached from POST /login, /register, /forgot-password,
// /magic-link/send and /sms-code/send — all unauthenticated, all taking an
// address straight from the request body. So the cost is exactly the cost the
// verifier's marker gate exists to prevent, arriving through the other door,
// and the same reasoning applies to it:
//
//   - It is off by default. import-only is the default mode, and the runbook
//     says to turn dual-read off once the bulk import has been verified. The
//     mode exists for the window in which the import is incomplete, not for the
//     life of the deployment.
//   - It is rate-limited, per address and globally, by the same limiter the
//     verifier uses (limiter.go). Over budget, the miss stays a miss.
//   - It never changes what the route answers. A fall-through that fails — the
//     limiter refused, the pool does not know the address, the call errored —
//     returns the original ErrUserNotFound, never a new error, so a client
//     cannot tell a dual-read deployment from an import-only one by anything on
//     the wire. There is a timing difference and it is not equalised; see
//     GetUserByEmail.
//
// A negative cache was considered and refused. Remembering "this address is not
// in the pool" would collapse repeated misses for one address to a single call,
// but the per-address bucket already does that, and a cache with a lifetime is a
// user-enumeration oracle with a lifetime: the second lookup of an address is
// fast or slow depending on what the first one found. The global bucket is the
// bound that matters for distinct addresses, and a cache does nothing for those.
//
// # What this package does not do
//
// It does not fork or replace anything the core owns. The password is adopted by
// the core, hashed at Config.BcryptCost and written through
// UserPasswordStore.UpdatePassword; the marker is dropped by that same write
// (internal/store/dynamodb/tokens.go). Nothing here mints a token, answers a
// route or adds a status code, and with the block unconfigured none of it is
// constructed at all.
package migrating

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// Options configures New.
type Options struct {
	// Inner is the store being wrapped. It is the concrete *dynamodb.Store and
	// not auth.UserStore, and that is load-bearing rather than lazy: the core
	// discovers MagicLinkStore, SMSStore, TOTPStore, UserPasswordStore and five
	// more by TYPE ASSERTION on whatever was handed to auth.WithUserStore, and
	// cmd/auth resolves the template, OAuth and authorization-code stores the
	// same way. A wrapper holding an interface would promote three methods and
	// silently take every one of those features away — the trap cmd/auth's
	// memoryStoreBundle documents. Embedding the concrete type promotes all of
	// them.
	//
	// Narrowing to one driver costs nothing today: the marker is a DynamoDB
	// profile attribute and RS-13 refuses the migration block on any other
	// driver.
	Inner *ddbstore.Store

	// Directory is the source being migrated away from. Required.
	Directory awsintegration.CognitoDirectory

	// Source and UserPoolID are written into the marker of every row this
	// package creates, and are what a stored marker is checked against.
	Source     string
	UserPoolID string

	// DualRead turns the lookup fall-through on. False is import-only.
	DualRead bool

	// Attributes maps source attribute names onto the fields they fill. Nil is
	// DefaultAttributeMap.
	Attributes AttributeMap

	// Logger receives the one line a failed fall-through writes. Defaults to
	// slog.Default().
	Logger *slog.Logger

	// Now is the clock the limiters refill against. Defaults to time.Now.
	Now func() time.Time

	// The limiter bounds. Zero takes the package default; see limiter.go for
	// what each one is protecting against.
	SubjectBurst     float64
	SubjectPerMinute float64
	GlobalBurst      float64
	GlobalPerSecond  float64
	MaxSubjects      int
}

// MigratingUserStore is the user store cmd/auth hands the core while a migration
// is in progress.
//
// Everything except GetUserByEmail is the embedded store's, unchanged and
// unwrapped. GetUserByEmail is overridden for dual-read, and even then the
// override is a fall-through on a miss rather than a different lookup: a
// deployment that has finished importing pays one map lookup of a boolean per
// call and nothing else.
type MigratingUserStore struct {
	*ddbstore.Store

	directory  awsintegration.CognitoDirectory
	source     string
	pool       string
	dualRead   bool
	attributes AttributeMap

	log *slog.Logger
	now func() time.Time

	// Two limiters, not one. The two paths call different Cognito APIs with
	// different service quotas — AdminGetUser is a read, AdminInitiateAuth is a
	// sign-in attempt that touches the pool's own lockout counters — and a
	// shared budget would let a flood of lookups starve the verifier, or the
	// reverse, for no reason beyond the convenience of one field.
	lookupLimit *limiter
	verifyLimit *limiter
}

// ref is what this deployment's markers name, and what a stored one is checked
// against.
func (m *MigratingUserStore) ref() SourceRef {
	return SourceRef{Source: m.source, Pool: m.pool}
}

// Compile-time proof that the wrapper is still every store the embedded one was.
// The core finds all of these by type assertion, so a promotion that stopped
// working would not fail to build at the call site — it would turn into a 501 or
// a 500 on the wire, which is exactly what internal/store/dynamodb/interfaces.go
// exists to prevent one level down.
var (
	_ auth.UserStore              = (*MigratingUserStore)(nil)
	_ auth.UserAccountStore       = (*MigratingUserStore)(nil)
	_ auth.UserPasswordStore      = (*MigratingUserStore)(nil)
	_ auth.MagicLinkStore         = (*MigratingUserStore)(nil)
	_ auth.SMSStore               = (*MigratingUserStore)(nil)
	_ auth.EmailVerificationStore = (*MigratingUserStore)(nil)
	_ auth.EmailChangeStore       = (*MigratingUserStore)(nil)
	_ auth.TOTPStore              = (*MigratingUserStore)(nil)
	_ auth.UserPhoneStore         = (*MigratingUserStore)(nil)
	_ auth.TemplateStore          = (*MigratingUserStore)(nil)
	_ auth.AuthCodeStore          = (*MigratingUserStore)(nil)
	_ auth.UserLookupStore        = (*MigratingUserStore)(nil)
)

// New validates opts and returns the wrapper. It performs no I/O: the directory
// builds its own client on first use (internal/integration/aws/cognito.go), and
// a cold start must not pay a credential-chain walk for a capability most
// invocations never reach.
func New(opts Options) (*MigratingUserStore, error) {
	if opts.Inner == nil {
		return nil, errors.New("migrating: the wrapped store is required")
	}
	if opts.Directory == nil {
		return nil, errors.New("migrating: a source directory is required")
	}
	if strings.TrimSpace(opts.Source) == "" {
		return nil, errors.New("migrating: a source name is required; it is written into every marker and compared against every stored one")
	}
	if strings.TrimSpace(opts.UserPoolID) == "" {
		return nil, errors.New("migrating: a user pool id is required; it is written into every marker and compared against every stored one")
	}

	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	attrs := opts.Attributes
	if attrs == nil {
		attrs = DefaultAttributeMap()
	}

	return &MigratingUserStore{
		Store:      opts.Inner,
		directory:  opts.Directory,
		source:     strings.TrimSpace(opts.Source),
		pool:       strings.TrimSpace(opts.UserPoolID),
		dualRead:   opts.DualRead,
		attributes: attrs,
		log:        log,
		now:        now,
		lookupLimit: newLimiter(opts.SubjectBurst, opts.SubjectPerMinute,
			opts.GlobalBurst, opts.GlobalPerSecond, opts.MaxSubjects, now),
		verifyLimit: newLimiter(opts.SubjectBurst, opts.SubjectPerMinute,
			opts.GlobalBurst, opts.GlobalPerSecond, opts.MaxSubjects, now),
	}, nil
}

// GetUserByEmail resolves locally first and, in dual-read mode only, falls a
// miss through to the source.
//
// Three properties, each pinned by a test:
//
//   - A hit never reaches the source. The migration is invisible to every
//     account already imported, which after the bulk import is all of them.
//   - A store failure that is not a miss is returned as itself. Falling through
//     on a timeout or a throttle would turn a transient DynamoDB problem into a
//     provisioning run against Cognito, and could create a duplicate row for a
//     user the table already holds and merely failed to return.
//   - A failed fall-through returns the ORIGINAL miss. Not the limiter's
//     refusal, not the directory's error, not a wrapped anything: the core maps
//     a GetUserByEmail error to ErrInvalidCredentials without reading it
//     (login_2fa.go), so any error works on the login path — but /register
//     branches on ErrUserExists versus a miss, and a novel error there would be
//     a 500 where the route used to answer a 201. The original error is the only
//     value that is right on every route that calls this.
//
// What is not equalised is time. A miss that falls through costs a network round
// trip that a local hit does not, on an unauthenticated route, so a client that
// measures can tell "this address is in neither place" from "this address is
// local" — and, more sharply, can tell "in the pool" from "in neither". That
// signal is not created here: the login path never equalised, an unknown address
// returns before any bcrypt work while a known one pays a compare
// (awesome-go-auth/login_2fa.go), and the upstream seam says in as many words
// that equalising what a host adds is the host's job and not the library's. What
// this package does about it is bound it — the limiter caps how many
// measurements an attacker gets — and turn it off by default. It is a statement
// of posture, not a pinned property, and the runbook says so.
func (m *MigratingUserStore) GetUserByEmail(ctx context.Context, email, tenantID string) (auth.User, error) {
	user, err := m.Store.GetUserByEmail(ctx, email, tenantID)
	if err == nil || !m.dualRead {
		return user, err
	}
	if !errors.Is(err, ddbstore.ErrUserNotFound) {
		return user, err
	}

	provisioned, perr := m.provisionFromSource(ctx, email, tenantID)
	if perr != nil {
		if !errors.Is(perr, errNotInSource) && !errors.Is(perr, errOverBudget) {
			// A miss that the source could not answer is worth one line, because
			// it is the difference between "the import is incomplete" and "the
			// migration is broken" and nothing on the wire distinguishes them.
			// The address is not quoted: this is an unauthenticated route and the
			// value came out of a request body.
			m.log.Warn("migration dual-read could not reach the source directory; the lookup stays a miss",
				slog.String("source", m.source),
				slog.String("error", perr.Error()))
		}
		return auth.User{}, err
	}
	return provisioned, nil
}

// The two outcomes of a fall-through that are ordinary rather than notable, kept
// as sentinels so the caller can decide not to log them. Neither ever leaves
// this package.
var (
	errNotInSource = errors.New("migrating: the source directory holds no such user")
	errOverBudget  = errors.New("migrating: the source directory was not consulted; the rate limit is spent")
)

// provisionFromSource reads one user out of the source and writes the local row.
func (m *MigratingUserStore) provisionFromSource(ctx context.Context, email, tenantID string) (auth.User, error) {
	subject := normalizeEmail(email)
	if subject == "" {
		return auth.User{}, errNotInSource
	}
	if !m.lookupLimit.allow(subject) {
		return auth.User{}, errOverBudget
	}

	rec, err := m.directory.GetUser(ctx, subject)
	if err != nil {
		if errors.Is(err, awsintegration.ErrCognitoUserNotFound) {
			return auth.User{}, errNotInSource
		}
		return auth.User{}, err
	}

	user, err := UserFromSource(rec, m.attributes)
	if err != nil {
		return auth.User{}, err
	}
	user.TenantID = tenantID

	// CreateMigratedUser, not CreateUser: the marker is a separate argument
	// precisely so that it cannot ride in on auth.User, and this call is also
	// what files it on the request context — there is no intervening profile
	// read to do that, because the row did not exist a moment ago and the
	// verifier runs next.
	created, err := m.Store.CreateMigratedUser(ctx, user, m.ref().Marker())
	if err == nil {
		return created, nil
	}
	if errors.Is(err, auth.ErrUserExists) {
		// Another execution environment provisioned the same person between our
		// miss and our write, which under Lambda is ordinary rather than
		// exceptional: two requests for one address can land in two environments
		// at once. The uniqueness item made exactly one of them the winner
		// (internal/store/dynamodb/users.go CreateUser), and reading the winner's
		// row back is both correct and the only way to return the id that
		// actually exists.
		return m.Store.GetUserByEmail(ctx, email, tenantID)
	}
	return auth.User{}, err
}

// SourceRef is what a marker names: which directory family, and which instance
// of it.
type SourceRef struct {
	Source string
	Pool   string
}

// Marker renders the reference as the value the store writes onto an imported
// profile.
func (r SourceRef) Marker() ddbstore.MigrationMarker {
	return ddbstore.MigrationMarker{Source: r.Source, Pool: r.Pool}
}

// Matches reports whether a stored marker is this reference's.
//
// Both halves matter. Source alone would let one stack's marker answer for
// another pool of the same family; pool alone would do the same across
// families. A stack repointed at a second pool must not start sending it
// accounts imported from the first — that is traffic somebody else's directory
// receives for accounts it has never heard of.
func (r SourceRef) Matches(marker ddbstore.MigrationMarker) bool {
	return !marker.IsZero() && marker.Source == r.Source && marker.Pool == r.Pool
}

// The fields an attribute may be mapped onto. They are spelled as the schema and
// the wire spell them, not as the Go struct does, because an operator writing an
// attribute-map file is reading docs/config-reference.md and not models.go.
const (
	FieldEmail           = "email"
	FieldEmailVerified   = "isEmailVerified"
	FieldPhoneNumber     = "phoneNumber"
	FieldFirstName       = "firstName"
	FieldLastName        = "lastName"
	FieldRole            = "role"
	FieldMetadataPrefix  = "metadata:"
	FieldIgnore          = "-"
	fieldMetadataMinimum = len(FieldMetadataPrefix) + 1
)

// AttributeMap maps a source attribute name onto the field it fills. A value of
// FieldIgnore drops the attribute; a value beginning with FieldMetadataPrefix
// puts it under that key in the imported-attributes map; anything else must be
// one of the Field constants.
//
// An attribute the map does not mention is dropped, with one exception: a
// "custom:" attribute with no entry lands in the imported-attributes map under
// its name with the prefix stripped. That default is what makes the common case
// — a pool with a handful of custom attributes and no opinion about them —
// require no file at all, while an operator who wants one of them to become
// `role` writes a single line.
type AttributeMap map[string]string

// DefaultAttributeMap is the mapping applied when no file is supplied: the
// Cognito standard attribute names that have an auth.User field.
//
// `sub` is deliberately absent. It is the pool's own identifier and it is not
// this deployment's: the local row gets an id in this product's own shape, and
// recording the pool's would invite something downstream to treat it as a
// foreign key into a directory that is being deleted. A deployment that needs it
// can map it into metadata in one line.
func DefaultAttributeMap() AttributeMap {
	return AttributeMap{
		"email":          FieldEmail,
		"email_verified": FieldEmailVerified,
		"phone_number":   FieldPhoneNumber,
		"given_name":     FieldFirstName,
		"family_name":    FieldLastName,
	}
}

// Validate reports every entry whose target is not a field this build knows.
// Called by cmd/migrate before the first page is read, so a typo in a map file
// is a refusal rather than four thousand users imported without a phone number.
func (a AttributeMap) Validate() error {
	bad := make([]string, 0, 4)
	for name, target := range a {
		switch {
		case target == FieldIgnore,
			target == FieldEmail, target == FieldEmailVerified, target == FieldPhoneNumber,
			target == FieldFirstName, target == FieldLastName, target == FieldRole:
		case strings.HasPrefix(target, FieldMetadataPrefix) && len(target) >= fieldMetadataMinimum:
		default:
			bad = append(bad, fmt.Sprintf("%s -> %q", name, target))
		}
	}
	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("migrating: unknown attribute target(s): %s; use one of %s, %s, %s, %s, %s, %s, %s<key>, or %q to drop",
		strings.Join(bad, ", "),
		FieldEmail, FieldEmailVerified, FieldPhoneNumber, FieldFirstName, FieldLastName, FieldRole,
		FieldMetadataPrefix, FieldIgnore)
}

// ErrNoEmail is what UserFromSource reports for a source record with no usable
// address.
//
// Such a record is refused rather than invented around, and that is the whole
// decision: email is the account's identity everywhere in this product — the
// uniqueness item is keyed on it (data-model.md #1), every credential flow
// addresses it, and the core normalizes and requires it. A synthesised address
// would create a row nobody can log into, that occupies a uniqueness key, and
// that silently becomes a duplicate the day the person's real address is added.
// cmd/migrate reports these by username so an operator can fix the source.
var ErrNoEmail = errors.New("migrating: the source record has no email address")

// UserFromSource maps one source record onto the auth.User the store writes.
//
// It does NOT carry the marker, and that is the whole of why the marker cannot
// reach the wire: there is no field on the value this returns that could hold
// one, so writing it means naming it to CreateMigratedUser. What the returned
// user does carry out of the source is the attributes the map placed in
// Metadata[ImportedAttributesKey], which is the operator's own data about the
// person and is meant to be readable.
//
// PasswordHash is left empty and that is not an omission: a user pool yields no
// password hash, which is the entire reason the just-in-time half of this
// package exists. Empty is also the value the core reads as "this account has
// never had a password", which keeps the passwordless initial-password path open
// for a migrated person who never comes back to log in
// (awesome-go-auth/wire_password_email.go:347) — the reason the marker is a
// separate attribute rather than a placeholder written into the hash.
func UserFromSource(rec awsintegration.CognitoUser, attrs AttributeMap) (auth.User, error) {
	if attrs == nil {
		attrs = DefaultAttributeMap()
	}

	user := auth.User{
		// The created-at is the source's, so a migrated account keeps the age it
		// had. The store stamps updated-at itself.
		CreatedAt: rec.CreatedAt,
		UpdatedAt: rec.UpdatedAt,
	}
	imported := map[string]any{}

	for name, value := range rec.Attributes {
		target, mapped := attrs[name]
		if !mapped {
			if custom, ok := strings.CutPrefix(name, "custom:"); ok && custom != "" {
				imported[custom] = value
			}
			continue
		}
		switch {
		case target == FieldIgnore:
		case target == FieldEmail:
			user.Email = value
		case target == FieldEmailVerified:
			// Cognito writes the flag as the strings "true" and "false"; anything
			// else is read as not verified, which is the safe direction — a
			// migrated account that has to verify its address is an inconvenience,
			// one that skipped verification because an attribute did not parse is
			// a hole.
			user.IsEmailVerified = strings.EqualFold(strings.TrimSpace(value), "true")
		case target == FieldPhoneNumber:
			user.PhoneNumber = value
		case target == FieldFirstName:
			user.FirstName = value
		case target == FieldLastName:
			user.LastName = value
		case target == FieldRole:
			user.Role = value
		case strings.HasPrefix(target, FieldMetadataPrefix):
			if key := strings.TrimPrefix(target, FieldMetadataPrefix); key != "" && value != "" {
				imported[key] = value
			}
		}
	}

	user.Email = normalizeEmail(user.Email)
	if user.Email == "" {
		return auth.User{}, fmt.Errorf("%w: %s", ErrNoEmail, rec.Username)
	}

	id, err := NewUserID()
	if err != nil {
		return auth.User{}, err
	}
	user.ID = id

	if len(imported) > 0 {
		user.Metadata = map[string]any{ddbstore.ImportedAttributesKey: imported}
	}
	return user, nil
}

// userIDBytes and the "usr_" prefix reproduce the core's own identifier shape
// (awesome-go-auth/security.go newID). A migrated account must be
// indistinguishable from a registered one by its id: anything that could tell
// them apart eventually becomes something that treats them differently.
const userIDBytes = 16

// NewUserID mints an identifier in the core's shape. Exported because cmd/migrate
// mints them too and the two must not drift.
func NewUserID() (string, error) {
	b := make([]byte, userIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("migrating: random id: %w", err)
	}
	return "usr_" + hex.EncodeToString(b), nil
}

// normalizeEmail is the core's own normalisation — trim and lower-case — applied
// here so that the address a marker, a limiter bucket and a uniqueness item are
// keyed on is one value. The core normalizes on its way in
// (awesome-go-auth/login_2fa.go) and the DynamoDB store normalizes again on its
// way to a key; this is the same rule a third time, for the one caller that sits
// outside both.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

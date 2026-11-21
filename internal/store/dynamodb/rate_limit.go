package dynamodb

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// This file implements the shared counter behind the built-in rate limiter
// (data-model.md §1.5 row #61): one item per (scope, subject, window), advanced
// by a single conditional UpdateItem per request.
//
// It is the only store in this package that implements no awesome-go-auth
// interface. The reference has no rate limiting at all — RouterOptions.rateLimiter
// is an empty slot a host drops an Express handler into, and absent it the
// router collapses to rl = [] (auth.router.ts:46, :468) — so there is no
// upstream contract to satisfy and no type assertion to survive. cmd/auth
// discovers AllowRequest structurally, which is what rateLimitCounter below
// pins.
//
// ── why the counter cannot live in the process ───────────────────────────────
//
// A Lambda execution environment serves one request at a time and AWS runs as
// many of them as the arrival rate demands. An in-process counter therefore
// limits each environment separately: under any concurrency worth limiting, the
// effective ceiling is the configured max multiplied by a number nobody chose
// and nothing reports. That is not a loose limit, it is no limit — an attacker
// who can raise concurrency raises their own budget with it. So the limit is a
// row in the table every environment shares, and the in-process tier in cmd/auth
// is a pre-filter in front of this one, never the limit itself.
//
// ── the item, and why it is a fixed window ───────────────────────────────────
//
// PK=RL#<scope>#<subject>#<window>, SK=RL, with the window index — wall-clock
// seconds divided by the window length — inside the partition key. A window
// therefore has its own item, a past window is unreachable rather than stale,
// and nothing has to be reset between windows: the next window starts at zero
// because it starts at a key nothing has written yet. (ResetRateLimit, below,
// clears the current window's item early; only the second-factor cap uses it.)
//
// That is a fixed window and it has the property every fixed window has: the
// boundary is a seam. A subject may spend its whole budget in the last instant
// of one window and its whole budget again in the first instant of the next, so
// the true worst case over a sliding window of the same length is 2×max, not
// max. This is accepted rather than worked around, and the reasons are in that
// order:
//
//   - A sliding window or a token bucket needs the request history, or a
//     timestamp plus a fractional balance, which means a read-modify-write or a
//     much larger conditional expression. Both cost more than one write per
//     request, on the login path, forever.
//   - The bound this limiter exists for is "an attacker cannot make unlimited
//     guesses", and 2×max per window is as much a bound as max is. A factor of
//     two does not change what a 10-per-minute limit does to a credential
//     stuffing run.
//   - The seam is only reachable by an attacker who knows where the boundary is
//     and is willing to idle up to it. They can learn it — a refusal's
//     Retry-After names it — and it buys them one extra window's budget, once.
//
// docs/config-reference.md says the same thing to the operator, because the one
// thing a fixed window must not be is a surprise.
//
// ── what one request costs ───────────────────────────────────────────────────
//
// One UpdateItem against an item well under 1 KB: **1 WCU per limited request**,
// allowed or refused. A refused request costs the same write as an allowed one —
// DynamoDB bills a conditional write whose condition fails — and that is the
// cost the in-process pre-filter exists to remove: an environment that has
// already watched a subject exhaust its budget in this window refuses locally
// and writes nothing.
//
// The condition is attribute_not_exists(n) OR n < :max, so a refused request
// does not increment. The counter is bounded by max however long the flood
// lasts, which matters for a reason beyond tidiness: an unbounded counter would
// let an attacker push n arbitrarily high, and any later feature that compared
// against it — a progressive delay, a lockout — would inherit an
// attacker-controlled number.
//
// ── the hot partition, and why keyBy defaults to email ───────────────────────
//
// One (scope, subject, window) is one partition key, and a partition key is
// capped at 1 000 WCU. With keyBy: ip that is mostly a feature — a single
// abusive source throttles itself — but a large NAT or corporate egress shares
// one key with every legitimate user behind it, so the limiter becomes the
// outage for exactly the people it is not aimed at (data-model.md §2.3). It is
// why this product's keyBy defaults to email, where the partition is one account
// and the write rate is one person's login attempts, and it is how §2.3's own
// conclusion — "per-IP windows must therefore be short and the account-scoped
// limiter must be the primary control" — is honoured rather than merely quoted.

// Rate-limit key space. The window index is the trailing segment and is always a
// decimal integer, so the split at the last separator is unambiguous however odd
// the subject is — which is what lets the subject occupy a middle segment
// without the '#'-free rule checkProvider needs.
const (
	// pkRateLimitPrefix keys one counter (data-model.md §2.2). The subject is
	// written as it is — an address, or a client IP — for the same reason
	// EMAIL#<t>#<email> is: this table already keys items by address, so nothing
	// here is a new class of stored data, and an operator debugging "why is this
	// person being refused" can find the item. It is unreadable without table
	// access and gone within two windows of the last request.
	pkRateLimitPrefix = "RL" + keySep

	// skRateLimit is the single sort key of the partition. The partition holds
	// exactly one item, so the sort key is a constant, as SESSION's and PLINK's
	// are; there is nothing to name because there is nothing to distinguish.
	skRateLimit = "RL"
)

// typeRateLimit is the counter's _t (data-model.md §7). Its own type because a
// migration sweep over these has nothing in common with a sweep over anything
// else in the table: they are the only items here that are pure counters, owned
// by no user, referenced by no other item and read by nothing.
const typeRateLimit = "ratelimit"

// attrRateLimitCount is the counter itself. One letter deliberately: it is
// written on every limited request and DynamoDB bills an attribute name as part
// of the item on every one of them.
const attrRateLimitCount = "n"

// maxRateLimitSubjectLen bounds the subject segment, for the reason
// maxEmailKeyLen exists: DynamoDB's own limit is 2 048 bytes for a partition
// key, and an attacker who chooses the subject — which on an email-keyed limiter
// they do, by putting whatever they like in the request body — must not be able
// to turn that into an opaque ValidationException on the login path. 320 is the
// longest address RFC 5321 permits and is the cap EMAIL# already uses.
const maxRateLimitSubjectLen = 320

// rateLimitTTLGrace is how long past the end of its window a counter is kept
// before TTL may reap it.
//
// Nothing reads a counter after its window ends — the window index is inside the
// partition key, so a past item is not stale but unreachable — which means the
// grace is not protecting a read, as the session grace is. It covers clock skew
// between execution environments, so two Lambdas a few seconds apart agree on
// which item they are advancing rather than one of them writing into a window
// the other has already had reaped. Five minutes is far more skew than AWS's
// clocks show and costs nothing: TTL deletion is free and the item is ~100 bytes.
const rateLimitTTLGrace = 5 * time.Minute

// ErrInvalidRateLimitSubject means a caller handed the limiter a subject that
// cannot be turned into a key: empty, longer than maxRateLimitSubjectLen, or
// carrying a control character.
//
// It is a typed refusal rather than a silent substitution because both available
// substitutions are wrong. Putting a constant in place of a bad subject would
// place every such request in one partition under one budget, which is a
// self-inflicted denial of service an attacker triggers on purpose by sending
// nonsense. Skipping the limiter would let the same nonsense buy an unlimited
// route. cmd/auth answers it by falling back to the client address, which is a
// real subject it always has and never takes from the request body.
var ErrInvalidRateLimitSubject = errors.New("dynamodb: invalid rate-limit subject")

// ErrInvalidRateLimitScope means the scope segment is not a usable key segment.
// It occupies a middle segment of the partition key, exactly as an OAuth
// provider name does, so a '#' inside it would let one scope forge another's
// counter — and idPattern is the same answer here that it is there.
var ErrInvalidRateLimitScope = errors.New("dynamodb: invalid rate-limit scope")

// rateLimitCounter is the shape cmd/auth discovers structurally, pinned here so
// that a signature which drifts is a build failure in this package rather than a
// limiter that silently stops being found and a deployment that silently stops
// being limited — the same argument interfaces.go makes for the stores the core
// discovers by type assertion.
//
// It is deliberately in this file and not in interfaces.go. That file is one
// central block of assertions and is being broken up into one assertion per
// store file; putting this one where its method is is where that refactor is
// heading, and it keeps this block out of its way.
type rateLimitCounter interface {
	AllowRequest(ctx context.Context, scope, subject string, max int, window time.Duration) (bool, time.Duration, error)
}

var _ rateLimitCounter = (*Store)(nil)

// secondFactorCounter is the shape cmd/auth's per-account cap on failed
// second-factor checks discovers, pinned here for the same reason.
type secondFactorCounter interface {
	rateLimitCounter
	ResetRateLimit(ctx context.Context, scope, subject string, window time.Duration) error
}

var _ secondFactorCounter = (*Store)(nil)

// AllowRequest advances the counter for one request and reports whether it may
// proceed.
//
// scope is the endpoint group the limiter was pointed at, subject is whatever
// the deployment keys by — an address, or a client IP — max is the budget for
// one window and window is the window length. The returned duration is the time
// remaining in the current window, which is what a refusal's Retry-After is
// built from; it is meaningless when the request was allowed.
//
// It is one conditional UpdateItem and nothing else: no read, no transaction, no
// second call. Two invocations racing on the last unit of a budget cannot both
// win, because the comparison and the increment are one expression against one
// item — the property this whole package is written for, and the reason the
// limiter is not a read followed by a write over a counter it observed a moment
// earlier.
//
// The error is reserved for the store itself failing. A request that is over
// budget is (false, remaining, nil) and not an error: it is an outcome, and
// mapping it to an error would make every caller tell "the limit said no" apart
// from "DynamoDB said nothing" by inspecting a message — which is exactly the
// distinction the fail-open decision in cmd/auth turns on.
func (s *Store) AllowRequest(ctx context.Context, scope, subject string, max int, window time.Duration) (bool, time.Duration, error) {
	if err := checkRateLimitScope(scope); err != nil {
		return false, 0, err
	}
	if err := checkRateLimitSubject(subject); err != nil {
		return false, 0, err
	}
	if max <= 0 {
		return false, 0, fmt.Errorf("dynamodb: rate-limit max must be positive, got %d", max)
	}
	if window <= 0 {
		return false, 0, fmt.Errorf("dynamodb: rate-limit window must be positive, got %s", window)
	}

	now := s.now().UTC()
	index, ends := rateLimitWindow(now, window)
	remaining := ends.Sub(now)

	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName: aws.String(s.table),
		Key:       key(rateLimitPK(scope, subject, index), skRateLimit),
		// ADD creates the attribute at :one when it does not exist, so the first
		// request of a window needs no separate insert and no upsert race. The
		// SET clause stamps the item the way every other item in this table is
		// stamped and writes the expiry; both are rewritten on every request,
		// which costs nothing and means a half-written counter cannot exist.
		UpdateExpression: aws.String("SET #ttl = :exp, #etype = :type, #ever = :ver ADD #n :one"),
		// The whole decision. attribute_not_exists admits the first request of
		// the window; #n < :max admits every request up to the budget and
		// refuses the one after it without incrementing — see the file header on
		// why a refused request must not advance the counter.
		ConditionExpression: aws.String("attribute_not_exists(#n) OR #n < :max"),
		// Written out rather than built with exprNames, which is the convention
		// everywhere else in this package. exprNames aliases an attribute to
		// "#" + its own name, and two of the four names here are _t and _v: a
		// substitution token of "#_t" would depend on DynamoDB accepting a
		// leading underscore in an expression attribute name, which is a detail
		// of the expression grammar this store has no reason to bet the login
		// path on. The aliases are arbitrary, so they are chosen to be boring.
		ExpressionAttributeNames: map[string]string{
			"#n":     attrRateLimitCount,
			"#ttl":   attrTTL,
			"#etype": attrType,
			"#ever":  attrVer,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":one":  avN(1),
			":max":  avN(int64(max)),
			":exp":  avN(ends.Add(rateLimitTTLGrace).Unix()),
			":type": avS(typeRateLimit),
			":ver":  avN(schemaVersion),
		},
	})
	switch {
	case err == nil:
		return true, remaining, nil
	case isConditionFailed(err):
		return false, remaining, nil
	default:
		return false, remaining, wrap("rate limit", err)
	}
}

// ResetRateLimit clears the counter of (scope, subject) for the window now falls
// in, so the subject's next AllowRequest in that window starts at zero.
//
// It exists for one caller, cmd/auth's per-account cap on failed second-factor
// checks (secondfactor_cap.go), which reserves each check with AllowRequest
// before the check runs — the conditional increment is what keeps concurrent
// guesses from all slipping under the cap — and clears the count when a check
// succeeds. The rate limiter proper never resets anything: its local
// pre-filter is sound only while a window's count never goes down (see
// cmd/auth ratelimit.go), so a scope that is ever reset must not be counted
// through that pre-filter, and the cap does not.
//
// One DeleteItem on the current window's item, unconditional: deleting an item
// that does not exist is not an error, and a past window needs no reset
// because nothing reads it. The window is passed rather than remembered,
// because the item's key depends on it. The error is the store failing.
func (s *Store) ResetRateLimit(ctx context.Context, scope, subject string, window time.Duration) error {
	if err := checkRateLimitScope(scope); err != nil {
		return err
	}
	if err := checkRateLimitSubject(subject); err != nil {
		return err
	}
	if window <= 0 {
		return fmt.Errorf("dynamodb: rate-limit window must be positive, got %s", window)
	}
	index, _ := rateLimitWindow(s.now().UTC(), window)
	_, err := s.api.DeleteItem(ctx, &awsddb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key(rateLimitPK(scope, subject, index), skRateLimit),
	})
	if err != nil {
		return wrap("rate limit reset", err)
	}
	return nil
}

// rateLimitWindow returns the index of the fixed window now falls in, and the
// instant that window ends.
//
// The index is seconds-since-epoch divided by the window length, so every
// execution environment computes the same index from the same clock without
// coordinating, and windows are aligned to the epoch rather than to whenever a
// particular subject first appeared. That alignment is what makes the in-process
// pre-filter in cmd/auth sound: it computes the same index the same way, so a
// local refusal is always one the shared counter would have made too.
func rateLimitWindow(now time.Time, window time.Duration) (int64, time.Time) {
	secs := int64(window / time.Second)
	if secs < 1 {
		secs = 1
	}
	index := now.Unix() / secs
	return index, time.Unix((index+1)*secs, 0).UTC()
}

// rateLimitPK is RL#<scope>#<subject>#<window>. See the key-space comment above
// for why the trailing integer is what makes the middle segment safe.
func rateLimitPK(scope, subject string, window int64) string {
	return pkRateLimitPrefix + scope + keySep + subject + keySep + strconv.FormatInt(window, 10)
}

func checkRateLimitScope(scope string) error {
	if !idPattern.MatchString(scope) {
		return fmt.Errorf("%w: scope %q", ErrInvalidRateLimitScope, scope)
	}
	return nil
}

// checkRateLimitSubject validates the caller-supplied subject. It is the one
// segment an attacker chooses on an email-keyed limiter, so every bound here is
// load-bearing rather than defensive: see ErrInvalidRateLimitSubject.
func checkRateLimitSubject(subject string) error {
	switch {
	case subject == "":
		return fmt.Errorf("%w: empty", ErrInvalidRateLimitSubject)
	case len(subject) > maxRateLimitSubjectLen:
		return fmt.Errorf("%w: longer than %d bytes", ErrInvalidRateLimitSubject, maxRateLimitSubjectLen)
	case strings.ContainsAny(subject, "\x00\n\r"):
		return fmt.Errorf("%w: contains a control character", ErrInvalidRateLimitSubject)
	}
	return nil
}

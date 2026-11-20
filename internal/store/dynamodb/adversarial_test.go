package dynamodb

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// Adversarial review pass over the seven new stores. Everything here starts from
// the assumption that a single-use credential CAN be redeemed twice and tries to
// do it, rather than from the assumption that the conditional writes are right.
//
// Four things are deliberately not asserted the way the authors' own tests assert
// them:
//
//   - The TTL unit is read back as a raw attribute value and compared against an
//     independently computed epoch-seconds range, never against the helper that
//     wrote it. A test that asserts item.ttl() against at.Unix() agrees with the
//     code by construction; DynamoDB silently ignores a millisecond TTL, so the
//     failure mode is "nothing ever expires" with nothing to report it.
//   - Expiry-on-read is checked with the item verifiably still in the table, which
//     is the situation real DynamoDB leaves for up to ~48 hours after a deadline
//     passes.
//   - The concurrency rounds are an order of magnitude above the authors' 30x8.
//   - Faults are injected at the API boundary to prove no outage can present as an
//     authentication outcome, and no authentication outcome can present as a 500.
const (
	advRounds = 200
	advRacers = 16
)

// plausible epoch-seconds bounds. Anything at or above advTTLCeiling is a
// millisecond value that DynamoDB would accept and never act on; anything below
// advTTLFloor is not a date this code could have produced.
const (
	advTTLFloor   = int64(1_700_000_000) // 2023-11-14
	advTTLCeiling = int64(4_000_000_000) // 2096-10-02
)

// ---------------------------------------------------------------------------
// 1. TTL unit, read raw
// ---------------------------------------------------------------------------

// rawTTL returns the ttl attribute of an item exactly as DynamoDB stores it,
// asserting only that it is numeric. The value itself is left to the caller so the
// comparison cannot be made against the helper that produced it.
func rawTTL(t *testing.T, client *awsddb.Client, table, pk, sk string) int64 {
	t.Helper()
	m := rawItem(t, client, table, pk, sk)
	if len(m) == 0 {
		t.Fatalf("%s/%s does not exist, so it has no ttl to check", pk, sk)
	}
	av, ok := m[attrTTL]
	if !ok {
		t.Fatalf("%s/%s carries no %q attribute; DynamoDB will never expire it", pk, sk, attrTTL)
	}
	n, ok := av.(*types.AttributeValueMemberN)
	if !ok {
		t.Fatalf("%s/%s has %s of DynamoDB type %T, want N; TTL only acts on a Number", pk, sk, attrTTL, av)
	}
	v, err := strconv.ParseInt(n.Value, 10, 64)
	if err != nil {
		t.Fatalf("%s/%s has a non-integer %s %q", pk, sk, attrTTL, n.Value)
	}
	return v
}

// assertEpochSeconds is the unit check. It is written against the deadline the
// caller asked for rather than against anything the store computed.
func assertEpochSeconds(t *testing.T, what string, got int64, deadline time.Time) {
	t.Helper()
	if got != deadline.Unix() {
		t.Errorf("%s ttl = %d, want %d (epoch SECONDS). Milliseconds would be %d, "+
			"which DynamoDB accepts silently and never reaps.", what, got, deadline.Unix(), deadline.UnixMilli())
	}
	if got < advTTLFloor || got >= advTTLCeiling {
		t.Errorf("%s ttl = %d is outside the plausible epoch-seconds range [%d, %d); "+
			"a millisecond value lands here and means the item never expires",
			what, got, advTTLFloor, advTTLCeiling)
	}
	t.Logf("%-22s raw ttl = %d  (seconds=%d ms=%d) -> %s",
		what, got, deadline.Unix(), deadline.UnixMilli(), time.Unix(got, 0).UTC().Format(time.RFC3339))
}

// TestAdvTTLUnitOnEveryNewTTLBearingItem covers every item type the seven new
// stores write that carries a ttl, plus the two pre-existing ones as a regression
// guard. A deliberately lopsided deadline (not a round number of seconds) is used
// so a truncation bug cannot pass by coincidence.
func TestAdvTTLUnitOnEveryNewTTLBearingItem(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	// 91 days out, with a fractional second, so the value is far from now() and
	// cannot coincide with a millisecond reading of anything else.
	deadline := time.Now().UTC().Add(91*24*time.Hour + 1234*time.Millisecond).Truncate(time.Nanosecond)

	for _, c := range familyCases() {
		hash := hashOf(uniqueID(c.name))
		if err := c.issue(ctx, store, u.ID, "acme", hash, deadline); err != nil {
			t.Fatalf("%s issue: %v", c.name, err)
		}
		if !c.family.hasPointer() {
			// SMS keeps no pointer item at all. Assert that rather than assume it:
			// f.pk("") would be a bare hash as a partition key.
			if m := rawItem(t, client, store.table, c.family.pk(hash), skToken); len(m) != 0 {
				t.Errorf("%s wrote a pointer item %s/%s, which the family says it has none of",
					c.name, c.family.pk(hash), skToken)
			}
			continue
		}
		got := rawTTL(t, client, store.table, c.family.pk(hash), skToken)
		assertEpochSeconds(t, c.name+" pointer", got, deadline)
	}

	// The pending-link entry, whose deadline the store derives from a duration
	// rather than receiving directly. The clock is pinned so the deadline is known
	// exactly.
	clock := newTestClock()
	pinned, _ := newStore(t, func(o *Options) { o.Now = clock.now })
	links := pinned.PendingLinks()
	const ttl = 17*time.Minute + 500*time.Millisecond
	state := oauthStateKey()
	if err := links.Save(ctx, state, sampleMeta(), ttl); err != nil {
		t.Fatalf("save pending link: %v", err)
	}
	plinkDeadline := clock.now().Add(ttl)
	got := rawTTL(t, client, pinned.table, pendingLinkPK(state), skPendingLink)
	assertEpochSeconds(t, "pending link", got, plinkDeadline)

	// And the expiry the consume condition actually compares must be the padded,
	// fixed-width string — not an epoch number, and not a trimmed RFC 3339 value,
	// because the comparison is lexicographic.
	raw := rawItem(t, client, pinned.table, pendingLinkPK(state), skPendingLink)
	if got := getS(raw, attrExpiresAt); got != formatTime(plinkDeadline) {
		t.Errorf("pending link %s = %q, want the fixed-width %q", attrExpiresAt, got, formatTime(plinkDeadline))
	}

	// Regression: the two pre-existing TTL-bearing item types.
	sess := sampleSession(u)
	sess.ExpiresAt = deadline
	if _, err := store.CreateSession(ctx, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	sessTTL := rawTTL(t, client, store.table, sessionPK(sess.ID), skSession)
	if want := deadline.Add(store.ttlGrace).Unix(); sessTTL != want {
		t.Errorf("session ttl = %d, want %d (expiry + grace, in seconds)", sessTTL, want)
	}
	if sessTTL < advTTLFloor || sessTTL >= advTTLCeiling {
		t.Errorf("session ttl = %d is outside the plausible epoch-seconds range", sessTTL)
	}
	refTTL := rawTTL(t, client, store.table, refreshPK(sess.RefreshTokenHash), skRefresh)
	if refTTL < advTTLFloor || refTTL >= advTTLCeiling {
		t.Errorf("refresh pointer ttl = %d is outside the plausible epoch-seconds range", refTTL)
	}
	t.Logf("%-22s raw ttl = %d -> %s", "session", sessTTL, time.Unix(sessTTL, 0).UTC().Format(time.RFC3339))
	t.Logf("%-22s raw ttl = %d -> %s", "refresh pointer", refTTL, time.Unix(refTTL, 0).UTC().Format(time.RFC3339))
}

// ---------------------------------------------------------------------------
// 2. Expiry enforced on read, with the item still physically present
// ---------------------------------------------------------------------------

// TestAdvExpiredCredentialsAreRefusedWhileStillInTheTable is the §4.5 rule under
// the condition that makes it matter: DynamoDB's TTL sweeper lags by up to ~48
// hours, so an expired credential is still readable. Every assertion below first
// proves the item is still there, then proves the store refuses it anyway.
func TestAdvExpiredCredentialsAreRefusedWhileStillInTheTable(t *testing.T) {
	t.Parallel()

	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			clock := newTestClock()
			store, client := newStore(t, func(o *Options) { o.Now = clock.now })
			ctx := context.Background()
			u := newUser(t, store, "acme")

			hash := hashOf(uniqueID(c.name))
			deadline := clock.now().Add(10 * time.Minute)
			if err := c.issue(ctx, store, u.ID, "acme", hash, deadline); err != nil {
				t.Fatalf("issue: %v", err)
			}

			// Past the deadline, by less than the TTL lag.
			clock.advance(11 * time.Minute)

			// The credential is still on the profile: nothing has swept it.
			profile := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile)
			if getS(profile, c.family.hashAttr) != hash {
				t.Fatalf("precondition: the hash is already gone from the profile, "+
					"so this test would pass without proving anything (profile: %v)", profile)
			}
			if c.family.hasPointer() {
				if m := rawItem(t, client, store.table, c.family.pk(hash), skToken); len(m) == 0 {
					t.Fatalf("precondition: the pointer item is already gone")
				}
			}

			if _, err := c.consume(ctx, store, u.ID, "acme", hash); !errors.Is(err, c.family.invalidErr) {
				t.Fatalf("an expired %s value that TTL has not yet reaped was honoured: err = %v, want %v",
					c.name, err, c.family.invalidErr)
			}

			// A second attempt must give the same answer, not a different one.
			if _, err := c.consume(ctx, store, u.ID, "acme", hash); !errors.Is(err, c.family.invalidErr) {
				t.Errorf("retry of an expired %s value: err = %v, want %v", c.name, err, c.family.invalidErr)
			}
		})
	}

	// The pending-link namespaces: the consuming path and the re-readable one.
	for _, tc := range []struct {
		name  string
		state string
	}{
		{"oauth-state", oauthStateKey()},
		{"link-token", linkTokenKey()},
		{"conflict-stash", conflictKey("expired@example.test", "google")},
	} {
		t.Run("plink/"+tc.name, func(t *testing.T) {
			t.Parallel()
			clock := newTestClock()
			store, client := newStore(t, func(o *Options) { o.Now = clock.now })
			ctx := context.Background()
			links := store.PendingLinks()

			if err := links.Save(ctx, tc.state, sampleMeta(), 10*time.Minute); err != nil {
				t.Fatalf("save: %v", err)
			}
			clock.advance(11 * time.Minute)

			if m := rawItem(t, client, store.table, pendingLinkPK(tc.state), skPendingLink); len(m) == 0 {
				t.Fatalf("precondition: the entry is already gone, so nothing is being proved")
			}
			if _, err := links.Get(ctx, tc.state); !errors.Is(err, ErrPendingLinkExpired) {
				t.Fatalf("an expired pending link that TTL has not reaped was honoured: err = %v, want %v",
					err, ErrPendingLinkExpired)
			}
			if _, err := links.Get(ctx, tc.state); !errors.Is(err, ErrPendingLinkExpired) {
				t.Errorf("retry of an expired pending link: err = %v, want %v", err, ErrPendingLinkExpired)
			}
		})
	}
}

// TestAdvAMissingExpiryFailsClosed: a profile that carries a hash but no expiry
// attribute — the shape a partial write or an older writer could leave — must not
// be consumable. A condition of the form "#hash = :h AND #exp > :now" is what makes
// that true; one written as "#hash = :h AND (attribute_not_exists(#exp) OR ...)"
// would hand out a token that never expires.
func TestAdvAMissingExpiryFailsClosed(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")

	for _, c := range familyCases() {
		hash := hashOf(uniqueID(c.name))
		if err := c.issue(ctx, store, u.ID, "acme", hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("%s issue: %v", c.name, err)
		}
		// Strip only the expiry, behind the store's back.
		if _, err := client.UpdateItem(ctx, &awsddb.UpdateItemInput{
			TableName:                aws.String(store.table),
			Key:                      key(userPK("acme", u.ID), skProfile),
			UpdateExpression:         aws.String("REMOVE #exp"),
			ExpressionAttributeNames: map[string]string{"#exp": c.family.expAttr},
		}); err != nil {
			t.Fatalf("%s strip expiry: %v", c.name, err)
		}
		if _, err := c.consume(ctx, store, u.ID, "acme", hash); !errors.Is(err, c.family.invalidErr) {
			t.Errorf("%s: a hash with no expiry attribute was honoured: err = %v, want %v",
				c.name, err, c.family.invalidErr)
		}
	}
}

// ---------------------------------------------------------------------------
// 3. Double redemption, every route to it
// ---------------------------------------------------------------------------

// TestAdvNoRouteToASecondRedemption enumerates the ways a spent credential could
// come back to life and asserts each one does not.
func TestAdvNoRouteToASecondRedemption(t *testing.T) {
	t.Parallel()

	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, client := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")
			expiry := time.Now().Add(time.Hour)

			// (a) Straight replay.
			h := hashOf(uniqueID("a"))
			mustIssue(t, c, ctx, store, u.ID, "acme", h, expiry)
			mustConsume(t, c, ctx, store, u.ID, "acme", h)
			mustRefuse(t, c, ctx, store, u.ID, "acme", h, "a straight replay")

			// (b) Replay after the Clear the core issues next.
			h = hashOf(uniqueID("b"))
			mustIssue(t, c, ctx, store, u.ID, "acme", h, expiry)
			mustConsume(t, c, ctx, store, u.ID, "acme", h)
			if err := c.clear(ctx, store, u.ID, "acme"); err != nil {
				t.Fatalf("clear after consume must be an idempotent no-op: %v", err)
			}
			mustRefuse(t, c, ctx, store, u.ID, "acme", h, "a replay after Clear")

			// (c) Replay of a value that was superseded before it was ever used.
			// This is the one the "leave the old pointer behind" decision creates:
			// the pointer for old still resolves, so the profile has to be the
			// authority.
			old, replacement := hashOf(uniqueID("c1")), hashOf(uniqueID("c2"))
			mustIssue(t, c, ctx, store, u.ID, "acme", old, expiry)
			mustIssue(t, c, ctx, store, u.ID, "acme", replacement, expiry)
			if c.family.hasPointer() {
				if m := rawItem(t, client, store.table, c.family.pk(old), skToken); len(m) == 0 {
					t.Fatalf("precondition: the superseded pointer was deleted, so this "+
						"case is not exercising the stale-pointer path (%s)", c.family.pk(old))
				}
			}
			mustRefuse(t, c, ctx, store, u.ID, "acme", old, "a superseded value whose pointer survives")
			mustConsume(t, c, ctx, store, u.ID, "acme", replacement)

			// (d) Replay of a superseded value after the replacement was spent.
			old, replacement = hashOf(uniqueID("d1")), hashOf(uniqueID("d2"))
			mustIssue(t, c, ctx, store, u.ID, "acme", old, expiry)
			mustIssue(t, c, ctx, store, u.ID, "acme", replacement, expiry)
			mustConsume(t, c, ctx, store, u.ID, "acme", replacement)
			mustRefuse(t, c, ctx, store, u.ID, "acme", old, "a superseded value after the replacement was spent")
		})
	}
}

// TestAdvAStrandedPointerCannotResurrectAProfile is the nastiest shape of the
// stale-pointer design: the user is deleted while a superseded pointer survives
// the DeleteUser sweep (the sweep only knows the hash the profile still names).
// Resolving that pointer then hands a consume a (userID, tenantID) for an item that
// no longer exists — and UpdateItem creates missing items.
func TestAdvAStrandedPointerCannotResurrectAProfile(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	for _, f := range pointerFamilies {
		u := newUser(t, store, "acme")
		old, live := hashOf(uniqueID("stranded")), hashOf(uniqueID("live"))
		expiry := time.Now().Add(time.Hour)

		extras := []tokenExtra{}
		if len(f.extraIssueAttrs) > 0 {
			extras = append(extras, tokenExtra{attr: attrPendingEmail, value: uniqueEmail("pending")})
		}
		for _, h := range []string{old, live} {
			if err := store.issueSingleUseToken(ctx, f, u.ID, "acme", h, expiry, extras...); err != nil {
				t.Fatalf("%s issue: %v", f.name, err)
			}
		}
		if err := store.DeleteUser(ctx, u.ID, "acme"); err != nil {
			t.Fatalf("delete user: %v", err)
		}

		// The superseded pointer is exactly what DeleteUser cannot see.
		if m := rawItem(t, client, store.table, f.pk(old), skToken); len(m) == 0 {
			t.Skipf("%s: the superseded pointer was swept after all; nothing to attack", f.name)
		}

		if _, err := store.userBySingleUseToken(ctx, f, old); !errors.Is(err, f.invalidErr) {
			t.Errorf("%s: a pointer to a deleted user resolved: err = %v, want %v", f.name, err, f.invalidErr)
		}
		// The real damage a conditional-less UpdateItem would do.
		if m := rawItem(t, client, store.table, userPK("acme", u.ID), skProfile); len(m) != 0 {
			t.Errorf("%s: consuming a stranded pointer resurrected the profile item: %v", f.name, m)
		}
	}
}

// TestAdvPendingLinkCannotBeRedeemedTwice is the same enumeration for the two
// single-use OAuth namespaces, whose credential is the item rather than an
// attribute of one.
func TestAdvPendingLinkCannotBeRedeemedTwice(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	links := store.PendingLinks()

	for _, name := range pendingLinkSingleUsePrefixes {
		state := name + randomHex(20)

		if err := links.Save(ctx, state, sampleMeta(), time.Hour); err != nil {
			t.Fatalf("%s save: %v", name, err)
		}
		if _, err := links.Get(ctx, state); err != nil {
			t.Fatalf("%s first Get: %v", name, err)
		}
		if _, err := links.Get(ctx, state); !errors.Is(err, ErrPendingLinkNotFound) {
			t.Errorf("%s: a second Get succeeded: err = %v, want %v", name, err, ErrPendingLinkNotFound)
		}
		// The core discards Delete's error and calls it after the Get; that must not
		// make the entry readable again.
		if err := links.Delete(ctx, state); err != nil {
			t.Errorf("%s Delete after a consuming Get: %v", name, err)
		}
		if _, err := links.Get(ctx, state); !errors.Is(err, ErrPendingLinkNotFound) {
			t.Errorf("%s: readable after Delete: err = %v", name, err)
		}
	}
}

// ---------------------------------------------------------------------------
// 4. Concurrency, an order of magnitude above the authors' rounds
// ---------------------------------------------------------------------------

// TestAdvHighIterationSingleUseConsume reruns the central guarantee at
// advRounds x advRacers per family. A race that passes at 30x8 has not been shown
// to pass; the loser count is asserted exactly, so a single extra winner anywhere
// in 200 rounds fails the test.
func TestAdvHighIterationSingleUseConsume(t *testing.T) {
	t.Parallel()
	for _, c := range familyCases() {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t)
			ctx := context.Background()
			u := newUser(t, store, "acme")
			expiry := time.Now().Add(time.Hour)

			totalWinners := 0
			for round := range advRounds {
				hash := hashOf(uniqueID(c.name))
				if err := c.issue(ctx, store, u.ID, "acme", hash, expiry); err != nil {
					t.Fatalf("round %d issue: %v", round, err)
				}
				results := runRace(advRacers, func() error {
					_, err := c.consume(ctx, store, u.ID, "acme", hash)
					return err
				})
				winners, losers, unexpected := tally(results, c.family.invalidErr)
				totalWinners += winners
				if winners != 1 || losers != advRacers-1 {
					t.Fatalf("round %d: %d winners and %d losers over %d racers, want 1 and %d (unexpected: %v)",
						round, winners, losers, advRacers, advRacers-1, unexpected)
				}
			}
			if totalWinners != advRounds {
				t.Errorf("%d redemptions over %d rounds, want exactly %d", totalWinners, advRounds, advRounds)
			}
			t.Logf("%s: %d rounds x %d racers = %d consume attempts, %d redemptions",
				c.name, advRounds, advRacers, advRounds*advRacers, totalWinners)
		})
	}
}

// TestAdvHighIterationPendingLinkConsume is the same for the OAuth state nonce and
// the account-link token.
func TestAdvHighIterationPendingLinkConsume(t *testing.T) {
	t.Parallel()
	for _, prefix := range pendingLinkSingleUsePrefixes {
		t.Run(strings.TrimSuffix(prefix, ":"), func(t *testing.T) {
			t.Parallel()
			store, _ := newStore(t)
			ctx := context.Background()
			links := store.PendingLinks()

			totalWinners := 0
			for round := range advRounds {
				state := prefix + randomHex(20)
				meta := sampleMeta()
				if err := links.Save(ctx, state, meta, time.Hour); err != nil {
					t.Fatalf("round %d save: %v", round, err)
				}
				var mu sync.Mutex
				var got []auth.OAuthPendingMeta
				results := runRace(advRacers, func() error {
					m, err := links.Get(ctx, state)
					if err == nil {
						mu.Lock()
						got = append(got, m)
						mu.Unlock()
					}
					return err
				})
				winners, losers, unexpected := tally(results, ErrPendingLinkNotFound)
				totalWinners += winners
				if winners != 1 || losers != advRacers-1 {
					t.Fatalf("round %d: %d winners and %d losers, want 1 and %d (unexpected: %v)",
						round, winners, losers, advRacers-1, unexpected)
				}
				// The winner must get the whole entry, not a husk: a consume that
				// returned an empty meta would send LinkVerify down a path with no
				// user id.
				if len(got) == 1 && (got[0].UserID != meta.UserID || got[0].ProviderAccountID != meta.ProviderAccountID) {
					t.Fatalf("round %d: winner received %+v, want UserID=%q ProviderAccountID=%q",
						round, got[0], meta.UserID, meta.ProviderAccountID)
				}
			}
			t.Logf("%s: %d rounds x %d racers = %d Get attempts, %d redemptions",
				prefix, advRounds, advRacers, advRounds*advRacers, totalWinners)
		})
	}
}

// TestAdvHighIterationAuthCodeConsume is the same guarantee for an OIDC
// authorization code, and it is the one credential in this store whose
// single-use property is a written requirement rather than an inference: RFC
// 6749 §4.1.2 says the code "MUST NOT be used more than once", and the core's
// own interface spells out that ConsumeCode "must be atomic (a conditional
// delete, a row lock, or a DEL-and-check pipeline, not a read followed by a
// delete)".
//
// The threat is concrete. A code travels in a redirect's query string, so it
// lands in browser history, in a Referer header and in every access log between
// the user and the client; an attacker who reads one out of any of those wins if
// and only if they can redeem it a second time. The loser count is asserted
// exactly, so one extra winner anywhere in 200 rounds fails the test.
//
// The winner is also checked for content: a consume that answered success with
// an empty record would send the token endpoint to GetUserByID("") and hand out
// a session for nobody.
func TestAdvHighIterationAuthCodeConsume(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()

	totalWinners := 0
	for round := range advRounds {
		code := sampleAuthCode(hashOf(uniqueID("oidc")))
		if err := store.SaveCode(ctx, code); err != nil {
			t.Fatalf("round %d save: %v", round, err)
		}

		var mu sync.Mutex
		var got []auth.AuthCode
		results := runRace(advRacers, func() error {
			redeemed, err := store.ConsumeCode(ctx, code.CodeHash)
			if err == nil {
				mu.Lock()
				got = append(got, redeemed)
				mu.Unlock()
			}
			return err
		})
		winners, losers, unexpected := tally(results, auth.ErrInvalidCode)
		totalWinners += winners
		if winners != 1 || losers != advRacers-1 {
			t.Fatalf("round %d: %d winners and %d losers over %d racers, want 1 and %d (unexpected: %v)",
				round, winners, losers, advRacers, advRacers-1, unexpected)
		}
		if len(got) == 1 && (got[0].UserID != code.UserID || got[0].ClientID != code.ClientID) {
			t.Fatalf("round %d: winner received %+v, want UserID=%q ClientID=%q",
				round, got[0], code.UserID, code.ClientID)
		}
	}
	if totalWinners != advRounds {
		t.Errorf("%d redemptions over %d rounds, want exactly %d", totalWinners, advRounds, advRounds)
	}
	t.Logf("authorization code: %d rounds x %d racers = %d redemption attempts, %d redemptions",
		advRounds, advRacers, advRounds*advRacers, totalWinners)
}

// TestAdvHighIterationEmailChangeConfirm reruns the transactional confirm race.
// The invariant is one winner and, afterwards, one address resolving to the user
// with no uniqueness item left behind for the address it replaced.
func TestAdvHighIterationEmailChangeConfirm(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	const rounds = advRounds / 2

	for round := range rounds {
		u := newUser(t, store, "acme")
		next := uniqueEmail("moved")
		hash := hashOf(uniqueID("echg"))
		if err := store.UpdateEmailChangeToken(ctx, u.ID, "acme", next, hash, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("round %d issue: %v", round, err)
		}
		if _, err := store.GetUserByEmailChangeTokenHash(ctx, hash); err != nil {
			t.Fatalf("round %d consume: %v", round, err)
		}
		results := runRace(advRacers, func() error {
			return store.ApplyEmailChange(ctx, u.ID, "acme")
		})
		winners := 0
		for _, err := range results {
			switch {
			case err == nil:
				winners++
			case errors.Is(err, auth.ErrUserExists),
				errors.Is(err, auth.ErrInvalidToken),
				errors.Is(err, ErrNoPendingEmailChange):
				// All three are correct refusals of a second confirmation.
			default:
				t.Fatalf("round %d: a confirmation failed with a fault rather than a refusal: %v", round, err)
			}
		}
		if winners != 1 {
			t.Fatalf("round %d: %d confirmations of one change succeeded, want exactly 1", round, winners)
		}
		got, err := store.GetUserByEmail(ctx, next, "acme")
		if err != nil || got.ID != u.ID {
			t.Fatalf("round %d: new address resolves to %v (%v), want %s", round, got.ID, err, u.ID)
		}
		if m := rawItem(t, client, store.table, emailPK("acme", u.Email), skEmail); len(m) != 0 {
			t.Fatalf("round %d: the released address still has a uniqueness item: %v", round, m)
		}
	}
	t.Logf("email-change confirm: %d rounds x %d racers = %d confirmations attempted",
		rounds, advRacers, rounds*advRacers)
}

// TestAdvHighIterationLinkRebind hammers the compare-and-set in
// LinkedAccounts.Save. Several racers legitimately succeed — a rebind supersedes
// rather than conflicts — so the invariant is that the table ends in ONE
// consistent state: one canonical item, one surviving pointer belonging to it, no
// losing owner still listing the account.
func TestAdvHighIterationLinkRebind(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()
	links := store.LinkedAccounts()
	const rounds = advRounds / 4

	for round := range rounds {
		providerID := "sub-" + randomHex(8)
		owners := make([]auth.OAuthLinkedAccount, advRacers)
		for i := range owners {
			owners[i] = sampleLink(uniqueID("usr"), "google", providerID)
		}
		var wg sync.WaitGroup
		gate := make(chan struct{})
		errs := make([]error, advRacers)
		for i := range owners {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-gate
				errs[i] = links.Save(ctx, owners[i])
			}(i)
		}
		close(gate)
		wg.Wait()

		for i, err := range errs {
			if err != nil && !errors.Is(err, ErrLinkedAccountConflict) {
				t.Fatalf("round %d racer %d: %v", round, i, err)
			}
		}

		live, err := links.FindByProvider(ctx, "google", providerID)
		if err != nil {
			t.Fatalf("round %d: no surviving binding: %v", round, err)
		}
		// The survivor must be one racer's whole link, never a mixture.
		matched := false
		for _, o := range owners {
			if o.ID == live.ID && o.UserID == live.UserID {
				matched = true
			}
		}
		if !matched {
			t.Fatalf("round %d: surviving binding %+v matches no racer", round, live)
		}
		// Exactly one pointer survives, and it is the survivor's.
		for _, o := range owners {
			m := rawItem(t, client, store.table, linkIDPK(o.ID), skLinkID)
			switch {
			case o.ID == live.ID && len(m) == 0:
				t.Fatalf("round %d: the live binding %s has no LINKID pointer", round, live.ID)
			case o.ID != live.ID && len(m) != 0:
				t.Fatalf("round %d: superseded link id %s still has a pointer: %v", round, o.ID, m)
			}
			if o.UserID == live.UserID {
				continue
			}
			listed, err := links.ListForUser(ctx, o.UserID)
			if err != nil {
				t.Fatalf("round %d list: %v", round, err)
			}
			if len(listed) != 0 {
				t.Fatalf("round %d: losing owner %s still lists %d binding(s)", round, o.UserID, len(listed))
			}
		}
	}
	t.Logf("link rebind: %d rounds x %d racers", rounds, advRacers)
}

// ---------------------------------------------------------------------------
// 5. Tenant isolation lives in the key
// ---------------------------------------------------------------------------

// TestAdvTenantIsolationIsStructural attacks the tenant boundary directly, with
// the SAME user id present in two tenants — the shape that a post-read filter gets
// wrong and a key cannot.
func TestAdvTenantIsolationIsStructural(t *testing.T) {
	t.Parallel()
	store, client := newStore(t, func(o *Options) { o.MultiTenant = true })
	ctx := context.Background()

	// One id, two tenants. CreateUser has refused this since the by-id pointer
	// (user_lookup.go), but a table written before that release can hold it,
	// and the isolation must not depend on ids being globally unique — so the
	// second half is written the way the store used to write it.
	shared := uniqueID("usr")
	for i, tenant := range []string{"t1", "t2"} {
		u := sampleUser(tenant)
		u.ID = shared
		u.ResetTokenHash, u.ResetTokenExpiresAt = "", nil
		if i > 0 {
			putLegacyUser(t, client, store, u)
			continue
		}
		if _, err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("create %s/%s: %v", tenant, shared, err)
		}
	}

	expiry := time.Now().Add(time.Hour)

	// (a) SMS: the lookup carries the tenant, so the wrong tenant must find
	// nothing AND must burn nothing.
	code := hashOf(uniqueID("sms"))
	if err := store.UpdateSMSCode(ctx, shared, "t1", code, expiry); err != nil {
		t.Fatalf("issue sms for t1: %v", err)
	}
	if _, err := store.GetUserBySMSCodeHash(ctx, shared, "t2", code); !errors.Is(err, auth.ErrInvalidCode) {
		t.Errorf("t2 consumed t1's sms code: err = %v, want %v", err, auth.ErrInvalidCode)
	}
	got, err := store.GetUserBySMSCodeHash(ctx, shared, "t1", code)
	if err != nil {
		t.Errorf("the cross-tenant attempt burned t1's code: %v", err)
	} else if got.TenantID != "t1" {
		t.Errorf("consumed code resolved to tenant %q, want t1", got.TenantID)
	}

	// (b) A pointer-backed family: the lookup carries no tenant at all, so the
	// tenant must be re-derived from the stored pointer. t2 must not be able to
	// take over t1's pointer key, and the hash must keep resolving to t1.
	shared_hash := hashOf(uniqueID("magic"))
	if err := store.UpdateMagicLinkToken(ctx, shared, "t1", shared_hash, expiry); err != nil {
		t.Fatalf("issue magic for t1: %v", err)
	}
	err = store.UpdateMagicLinkToken(ctx, shared, "t2", shared_hash, expiry)
	if err == nil {
		t.Errorf("t2 wrote t1's pointer key %s; the ownership condition did not hold", familyMagic.pk(shared_hash))
	}
	raw := rawItem(t, client, store.table, familyMagic.pk(shared_hash), skToken)
	if got := getS(raw, attrTenantID); got != "t1" {
		t.Errorf("pointer tenantId = %q after the takeover attempt, want t1", got)
	}
	resolved, err := store.GetUserByMagicLinkTokenHash(ctx, shared_hash)
	if err != nil {
		t.Fatalf("t1's magic link stopped working: %v", err)
	}
	if resolved.TenantID != "t1" {
		t.Errorf("magic hash resolved to tenant %q, want t1", resolved.TenantID)
	}

	// (c) Key forgery by '#' injection. USER#a#b#c must not be reachable from two
	// different (tenant, user) splits.
	for _, bad := range []struct{ tenant, user string }{
		{"t1#t2", shared},
		{"t1", shared + "#x"},
		{"t1", "#" + shared},
	} {
		if err := store.UpdateMagicLinkToken(ctx, bad.user, bad.tenant, hashOf("x"), expiry); !errors.Is(err, ErrInvalidIdentifier) {
			t.Errorf("tenant=%q user=%q was accepted as a key: err = %v, want ErrInvalidIdentifier",
				bad.tenant, bad.user, err)
		}
	}

	// (d) The empty tenant in multi-tenant mode is a bug, not a wildcard, on every
	// new method as well as the old ones.
	for name, call := range map[string]func() error{
		"UpdateMagicLinkToken":         func() error { return store.UpdateMagicLinkToken(ctx, shared, "", "h", expiry) },
		"ClearMagicLinkToken":          func() error { return store.ClearMagicLinkToken(ctx, shared, "") },
		"UpdateSMSCode":                func() error { return store.UpdateSMSCode(ctx, shared, "", "h", expiry) },
		"GetUserBySMSCodeHash":         func() error { _, e := store.GetUserBySMSCodeHash(ctx, shared, "", "h"); return e },
		"ClearSMSCode":                 func() error { return store.ClearSMSCode(ctx, shared, "") },
		"UpdateEmailVerificationToken": func() error { return store.UpdateEmailVerificationToken(ctx, shared, "", "h", expiry) },
		"MarkEmailVerified":            func() error { return store.MarkEmailVerified(ctx, shared, "", true) },
		"ClearEmailVerificationToken":  func() error { return store.ClearEmailVerificationToken(ctx, shared, "") },
		"UpdateEmailChangeToken":       func() error { return store.UpdateEmailChangeToken(ctx, shared, "", "a@b.test", "h", expiry) },
		"ApplyEmailChange":             func() error { return store.ApplyEmailChange(ctx, shared, "") },
		"ClearEmailChangeToken":        func() error { return store.ClearEmailChangeToken(ctx, shared, "") },
		"UpdateTOTPSecret":             func() error { return store.UpdateTOTPSecret(ctx, shared, "", "s", true) },
		"UpdatePhoneNumber":            func() error { _, e := store.UpdatePhoneNumber(ctx, shared, "", "+3901"); return e },
	} {
		if err := call(); !errors.Is(err, ErrTenantRequired) {
			t.Errorf("%s with an empty tenant in multi-tenant mode: err = %v, want ErrTenantRequired", name, err)
		}
	}
}

// TestAdvSingleTenantEmptyTenantIsItsOwnPartition is the other half: with
// multi-tenancy off, "" is a real tenant and must not collide with a named one.
func TestAdvSingleTenantEmptyTenantIsItsOwnPartition(t *testing.T) {
	t.Parallel()
	store, client := newStore(t)
	ctx := context.Background()

	// The second half is a legacy write, for TestAdvTenantIsolationIsStructural's
	// reason.
	shared := uniqueID("usr")
	for i, tenant := range []string{"", "t1"} {
		u := sampleUser(tenant)
		u.ID = shared
		u.ResetTokenHash, u.ResetTokenExpiresAt = "", nil
		if i > 0 {
			putLegacyUser(t, client, store, u)
			continue
		}
		if _, err := store.CreateUser(ctx, u); err != nil {
			t.Fatalf("create %q/%s: %v", tenant, shared, err)
		}
	}
	code := hashOf(uniqueID("sms"))
	if err := store.UpdateSMSCode(ctx, shared, "", code, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("issue for the empty tenant: %v", err)
	}
	if _, err := store.GetUserBySMSCodeHash(ctx, shared, "t1", code); !errors.Is(err, auth.ErrInvalidCode) {
		t.Errorf("tenant t1 reached the empty tenant's code: err = %v", err)
	}
	if got, err := store.GetUserBySMSCodeHash(ctx, shared, "", code); err != nil {
		t.Errorf("the empty tenant's own code was refused: %v", err)
	} else if got.TenantID != "" {
		t.Errorf("resolved tenant = %q, want the empty tenant", got.TenantID)
	}
}

// ---------------------------------------------------------------------------
// 6. Faults are never authentication outcomes, and vice versa
// ---------------------------------------------------------------------------

// throttling is a transient server-side fault. It must never be reported as an
// invalid credential: an outage presenting as an auth failure is an outage nobody
// pages for.
func throttling() error {
	return &types.ProvisionedThroughputExceededException{
		Message: aws.String("Throughput exceeds the current capacity of your table or index"),
	}
}

// faultAPI injects a fault into one named operation and delegates the rest.
type faultAPI struct {
	API
	op   string
	err  error
	hits atomic.Int32
}

func (f *faultAPI) fail(op string) error {
	if f.op != op {
		return nil
	}
	f.hits.Add(1)
	return f.err
}

func (f *faultAPI) GetItem(ctx context.Context, in *awsddb.GetItemInput, o ...func(*awsddb.Options)) (*awsddb.GetItemOutput, error) {
	if err := f.fail("GetItem"); err != nil {
		return nil, err
	}
	return f.API.GetItem(ctx, in, o...)
}

func (f *faultAPI) UpdateItem(ctx context.Context, in *awsddb.UpdateItemInput, o ...func(*awsddb.Options)) (*awsddb.UpdateItemOutput, error) {
	if err := f.fail("UpdateItem"); err != nil {
		return nil, err
	}
	return f.API.UpdateItem(ctx, in, o...)
}

func (f *faultAPI) DeleteItem(ctx context.Context, in *awsddb.DeleteItemInput, o ...func(*awsddb.Options)) (*awsddb.DeleteItemOutput, error) {
	if err := f.fail("DeleteItem"); err != nil {
		return nil, err
	}
	return f.API.DeleteItem(ctx, in, o...)
}

func (f *faultAPI) PutItem(ctx context.Context, in *awsddb.PutItemInput, o ...func(*awsddb.Options)) (*awsddb.PutItemOutput, error) {
	if err := f.fail("PutItem"); err != nil {
		return nil, err
	}
	return f.API.PutItem(ctx, in, o...)
}

func (f *faultAPI) TransactWriteItems(ctx context.Context, in *awsddb.TransactWriteItemsInput, o ...func(*awsddb.Options)) (*awsddb.TransactWriteItemsOutput, error) {
	if err := f.fail("TransactWriteItems"); err != nil {
		return nil, err
	}
	return f.API.TransactWriteItems(ctx, in, o...)
}

// faultStore returns a store whose named operation always fails with err.
func faultStore(t *testing.T, base *Store, client *awsddb.Client, op string, err error) (*Store, *faultAPI) {
	t.Helper()
	f := &faultAPI{API: client, op: op, err: err}
	s, newErr := New(f, Options{TableName: base.table, Logger: base.log, Now: base.now})
	if newErr != nil {
		t.Fatalf("new store: %v", newErr)
	}
	return s, f
}

// authOutcomes are the errors that mean "this credential is no good". A fault must
// never produce one.
var authOutcomes = []error{
	auth.ErrInvalidToken, auth.ErrInvalidCode, auth.ErrUserExists,
	ErrUserNotFound, ErrNoPendingEmailChange,
	ErrPendingLinkNotFound, ErrPendingLinkExpired,
	ErrLinkedAccountNotFound,
}

func assertNotAnAuthOutcome(t *testing.T, what string, err error) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: a hard fault produced success", what)
		return
	}
	for _, outcome := range authOutcomes {
		if errors.Is(err, outcome) {
			t.Errorf("%s: a hard fault was reported as %v — an outage would surface as an "+
				"authentication failure. Got: %v", what, outcome, err)
			return
		}
	}
}

// TestAdvThrottlingIsNeverAnAuthOutcome walks every mutating method of the seven
// new stores with the underlying operation throttled.
func TestAdvThrottlingIsNeverAnAuthOutcome(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, base, "acme")
	expiry := time.Now().Add(time.Hour)

	// A live credential of every family, so the fault is the only reason to fail.
	live := map[string]string{}
	for _, c := range familyCases() {
		h := hashOf(uniqueID(c.name))
		if err := c.issue(ctx, base, u.ID, "acme", h, expiry); err != nil {
			t.Fatalf("%s issue: %v", c.name, err)
		}
		live[c.name] = h
	}
	state := oauthStateKey()
	if err := base.PendingLinks().Save(ctx, state, sampleMeta(), time.Hour); err != nil {
		t.Fatalf("save pending link: %v", err)
	}
	link := sampleLink(u.ID, "google", "sub-"+randomHex(8))
	if err := base.LinkedAccounts().Save(ctx, link); err != nil {
		t.Fatalf("save link: %v", err)
	}

	// UpdateItem throttled: every profile-attribute path.
	up, _ := faultStore(t, base, client, "UpdateItem", throttling())
	assertNotAnAuthOutcome(t, "UpdateSMSCode", up.UpdateSMSCode(ctx, u.ID, "acme", "h", expiry))
	assertNotAnAuthOutcome(t, "GetUserBySMSCodeHash",
		errOf(func() error { _, e := up.GetUserBySMSCodeHash(ctx, u.ID, "acme", live["sms"]); return e }))
	assertNotAnAuthOutcome(t, "ClearSMSCode", up.ClearSMSCode(ctx, u.ID, "acme"))
	assertNotAnAuthOutcome(t, "GetUserByMagicLinkTokenHash",
		errOf(func() error { _, e := up.GetUserByMagicLinkTokenHash(ctx, live["magic"]); return e }))
	assertNotAnAuthOutcome(t, "ClearMagicLinkToken", up.ClearMagicLinkToken(ctx, u.ID, "acme"))
	assertNotAnAuthOutcome(t, "GetUserByEmailVerificationTokenHash",
		errOf(func() error { _, e := up.GetUserByEmailVerificationTokenHash(ctx, live["verify"]); return e }))
	assertNotAnAuthOutcome(t, "MarkEmailVerified", up.MarkEmailVerified(ctx, u.ID, "acme", true))
	assertNotAnAuthOutcome(t, "ClearEmailVerificationToken", up.ClearEmailVerificationToken(ctx, u.ID, "acme"))
	assertNotAnAuthOutcome(t, "GetUserByEmailChangeTokenHash",
		errOf(func() error { _, e := up.GetUserByEmailChangeTokenHash(ctx, live["echg"]); return e }))
	assertNotAnAuthOutcome(t, "ClearEmailChangeToken", up.ClearEmailChangeToken(ctx, u.ID, "acme"))
	assertNotAnAuthOutcome(t, "UpdateTOTPSecret", up.UpdateTOTPSecret(ctx, u.ID, "acme", "JBSWY3DPEHPK3PXP", true))
	assertNotAnAuthOutcome(t, "UpdatePhoneNumber",
		errOf(func() error { _, e := up.UpdatePhoneNumber(ctx, u.ID, "acme", "+390111"); return e }))

	// GetItem throttled: every path that resolves a pointer before it writes.
	get, _ := faultStore(t, base, client, "GetItem", throttling())
	assertNotAnAuthOutcome(t, "GetUserByMagicLinkTokenHash/GetItem",
		errOf(func() error { _, e := get.GetUserByMagicLinkTokenHash(ctx, live["magic"]); return e }))
	assertNotAnAuthOutcome(t, "ApplyEmailChange/GetItem", get.ApplyEmailChange(ctx, u.ID, "acme"))
	assertNotAnAuthOutcome(t, "LinkedAccounts.FindByProvider",
		errOf(func() error {
			_, e := get.LinkedAccounts().FindByProvider(ctx, link.Provider, link.ProviderID)
			return e
		}))
	assertNotAnAuthOutcome(t, "LinkedAccounts.Save/GetItem", get.LinkedAccounts().Save(ctx, sampleLink(u.ID, "github", "gh-1")))
	assertNotAnAuthOutcome(t, "LinkedAccounts.Delete/GetItem", get.LinkedAccounts().Delete(ctx, link.ID))

	// DeleteItem throttled: the pending-link consume.
	del, _ := faultStore(t, base, client, "DeleteItem", throttling())
	assertNotAnAuthOutcome(t, "PendingLinks.Get",
		errOf(func() error { _, e := del.PendingLinks().Get(ctx, state); return e }))
	assertNotAnAuthOutcome(t, "PendingLinks.Delete", del.PendingLinks().Delete(ctx, state))

	// PutItem throttled: the pending-link save.
	put, _ := faultStore(t, base, client, "PutItem", throttling())
	assertNotAnAuthOutcome(t, "PendingLinks.Save", put.PendingLinks().Save(ctx, oauthStateKey(), sampleMeta(), time.Hour))

	// TransactWriteItems throttled: the issue paths and the two transactional ones.
	tx, _ := faultStore(t, base, client, "TransactWriteItems", throttling())
	assertNotAnAuthOutcome(t, "UpdateMagicLinkToken", tx.UpdateMagicLinkToken(ctx, u.ID, "acme", hashOf("x"), expiry))
	assertNotAnAuthOutcome(t, "UpdateEmailVerificationToken", tx.UpdateEmailVerificationToken(ctx, u.ID, "acme", hashOf("y"), expiry))
	assertNotAnAuthOutcome(t, "UpdateEmailChangeToken",
		tx.UpdateEmailChangeToken(ctx, u.ID, "acme", uniqueEmail("p"), hashOf("z"), expiry))
	assertNotAnAuthOutcome(t, "LinkedAccounts.Save/Tx", tx.LinkedAccounts().Save(ctx, sampleLink(u.ID, "gitlab", "gl-1")))

	// The still-live credential proves the faults burned nothing.
	if _, err := base.GetUserByMagicLinkTokenHash(ctx, live["magic"]); err != nil {
		t.Errorf("the magic link was burned by a throttled call: %v", err)
	}
}

// TestAdvAPersistentTransactionConflictIsNotAnAuthOutcome: a conflict means no
// ConditionExpression was ever evaluated, so it answers nothing about the
// credential. Reported as ErrUserNotFound or ErrInvalidToken it would turn an
// outage into an auth failure; reported as ErrLinkedAccountConflict it would blame
// a rebind that never happened.
func TestAdvAPersistentTransactionConflictIsNotAnAuthOutcome(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	ctx := context.Background()
	u := newUser(t, base, "acme")
	expiry := time.Now().Add(time.Hour)

	if err := base.UpdateEmailChangeToken(ctx, u.ID, "acme", uniqueEmail("pending"), hashOf("e"), expiry); err != nil {
		t.Fatalf("issue: %v", err)
	}

	store, f := faultStore(t, base, client, "TransactWriteItems", cancelledWith(reasonTransactionConflict))

	assertNotAnAuthOutcome(t, "issue behind a conflict",
		store.UpdateMagicLinkToken(ctx, u.ID, "acme", hashOf("m"), expiry))
	if got := f.hits.Load(); got != transactionConflictAttempts {
		t.Errorf("issue attempted %d times, want the %d-attempt bound", got, transactionConflictAttempts)
	}

	assertNotAnAuthOutcome(t, "ApplyEmailChange behind a conflict", store.ApplyEmailChange(ctx, u.ID, "acme"))

	err := store.LinkedAccounts().Save(ctx, sampleLink(u.ID, "google", "sub-x"))
	assertNotAnAuthOutcome(t, "LinkedAccounts.Save behind a conflict", err)
	if errors.Is(err, ErrLinkedAccountConflict) {
		t.Errorf("a TransactionConflict was reported as a concurrent rebind: %v", err)
	}
	// Delete needs a binding that really exists, or it returns before it ever
	// reaches a transaction — an absent link id is legitimately success.
	existing := sampleLink(u.ID, "github", "gh-"+randomHex(4))
	if err := base.LinkedAccounts().Save(ctx, existing); err != nil {
		t.Fatalf("save link: %v", err)
	}
	assertNotAnAuthOutcome(t, "LinkedAccounts.Delete behind a conflict",
		store.LinkedAccounts().Delete(ctx, existing.ID))
	// And the binding must survive a fault, rather than being reported as deleted.
	if _, err := base.LinkedAccounts().FindByProvider(ctx, existing.Provider, existing.ProviderID); err != nil {
		t.Errorf("a conflicted Delete lost the binding: %v", err)
	}
}

// TestAdvARefusalIsNeverAFault is the other direction: a replay must not become a
// 500. Every refusal below has to arrive as its typed sentinel with no fault
// wrapping.
func TestAdvARefusalIsNeverAFault(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	ctx := context.Background()
	u := newUser(t, store, "acme")
	expiry := time.Now().Add(time.Hour)

	for _, c := range familyCases() {
		h := hashOf(uniqueID(c.name))
		mustIssue(t, c, ctx, store, u.ID, "acme", h, expiry)
		mustConsume(t, c, ctx, store, u.ID, "acme", h)
		_, err := c.consume(ctx, store, u.ID, "acme", h)
		if !errors.Is(err, c.family.invalidErr) {
			t.Errorf("%s replay: err = %v, want the typed %v and nothing wrapping a fault",
				c.name, err, c.family.invalidErr)
		}
		if err != nil && strings.Contains(err.Error(), "dynamodb: consume") {
			t.Errorf("%s replay was wrapped as a store fault: %v", c.name, err)
		}
	}

	// An unknown value, of the right shape, is a refusal too.
	for _, c := range familyCases() {
		if _, err := c.consume(ctx, store, u.ID, "acme", hashOf(uniqueID("never-issued"))); !errors.Is(err, c.family.invalidErr) {
			t.Errorf("%s unknown value: err = %v, want %v", c.name, err, c.family.invalidErr)
		}
	}

	// And a pending link that was never saved.
	if _, err := store.PendingLinks().Get(ctx, oauthStateKey()); !errors.Is(err, ErrPendingLinkNotFound) {
		t.Errorf("unknown pending link: err = %v, want %v", err, ErrPendingLinkNotFound)
	}
}

// TestAdvConditionFailurePreImageIsAvailable pins the assumption the
// absent-versus-expired classification rests on: DynamoDB really does attach the
// pre-image to a failed conditional write when asked. If it stopped doing so, an
// expired credential would be reported as an unknown one — still a refusal, but the
// wire code would change silently, so it is asserted rather than assumed.
func TestAdvConditionFailurePreImageIsAvailable(t *testing.T) {
	t.Parallel()
	clock := newTestClock()
	store, _ := newStore(t, func(o *Options) { o.Now = clock.now })
	ctx := context.Background()
	links := store.PendingLinks()

	state := linkTokenKey()
	if err := links.Save(ctx, state, sampleMeta(), 5*time.Minute); err != nil {
		t.Fatalf("save: %v", err)
	}
	clock.advance(6 * time.Minute)

	_, err := links.Get(ctx, state)
	if errors.Is(err, ErrPendingLinkNotFound) {
		t.Fatalf("expired read came back as not-found, so the ALL_OLD pre-image on a "+
			"failed condition is not arriving and the two cases are indistinguishable: %v", err)
	}
	if !errors.Is(err, ErrPendingLinkExpired) {
		t.Fatalf("err = %v, want %v", err, ErrPendingLinkExpired)
	}
}

// ---------------------------------------------------------------------------
// 7. A stale GSI1 page must not carry ownership
// ---------------------------------------------------------------------------

// staleIndexAPI returns a caller-supplied page for an index Query on a given
// GSI1PK, and delegates everything else. That is exactly what an eventually
// consistent GSI does after a rebind moved GSI1PK from one owner to another: the
// old owner's partition still lists the entry for a while.
type staleIndexAPI struct {
	API
	owner string
	page  []map[string]types.AttributeValue
	hits  atomic.Int32
}

func (s *staleIndexAPI) Query(ctx context.Context, in *awsddb.QueryInput, o ...func(*awsddb.Options)) (*awsddb.QueryOutput, error) {
	if in.IndexName != nil {
		if av, ok := in.ExpressionAttributeValues[":owner"].(*types.AttributeValueMemberS); ok && av.Value == s.owner {
			s.hits.Add(1)
			return &awsddb.QueryOutput{Items: s.page}, nil
		}
	}
	return s.API.Query(ctx, in, o...)
}

// staleIndexPage builds the GSI1 projection of a linked account exactly as the
// index stores it: the table key, the index key, and the three INCLUDE attributes.
func staleIndexPage(link auth.OAuthLinkedAccount) []map[string]types.AttributeValue {
	return []map[string]types.AttributeValue{{
		attrPK:        avS(oauthPK(link.Provider, link.ProviderID)),
		attrSK:        avS(skOAuth),
		attrGSI1PK:    avS(gsi1UserID(link.UserID)),
		attrGSI1SK:    avS(oauthGSI1SK(link.Provider, link.ProviderID)),
		attrType:      avS(typeLink),
		attrLinkID:    avS(link.ID),
		attrCreatedAt: avS(formatTime(link.CreatedAt)),
	}}
}

// TestAdvAStaleIndexPageCannotLeakAnotherUsersBinding: ListForUser resolves the
// index keys against the canonical items, and the canonical item is the one that
// carries the owner. If the index page is stale the canonical item read back names
// the NEW owner — so a list built from it would show user A a binding that now
// belongs to user B, including B's provider email.
func TestAdvAStaleIndexPageCannotLeakAnotherUsersBinding(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	ctx := context.Background()

	alice := newUser(t, base, "acme")
	bob := newUser(t, base, "acme")
	providerID := "sub-" + randomHex(8)

	aliceLink := sampleLink(alice.ID, "google", providerID)
	if err := base.LinkedAccounts().Save(ctx, aliceLink); err != nil {
		t.Fatalf("save alice's link: %v", err)
	}
	// Bob takes the provider account over. The canonical item's GSI1PK moves to
	// Bob in the same write; the index has not caught up.
	bobLink := sampleLink(bob.ID, "google", providerID)
	bobLink.Email = "bob-private@example.test"
	if err := base.LinkedAccounts().Save(ctx, bobLink); err != nil {
		t.Fatalf("rebind to bob: %v", err)
	}

	stale := &staleIndexAPI{API: client, owner: gsi1UserID(alice.ID), page: staleIndexPage(aliceLink)}
	store, err := New(stale, Options{TableName: base.table, Logger: base.log})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	listed, err := store.LinkedAccounts().ListForUser(ctx, alice.ID)
	if err != nil {
		t.Fatalf("ListForUser: %v", err)
	}
	if stale.hits.Load() == 0 {
		t.Fatal("the stale index page was never served, so nothing is being tested")
	}
	for _, l := range listed {
		if l.UserID != alice.ID {
			t.Errorf("ListForUser(alice) returned a binding owned by %s (email %q): "+
				"a stale GSI page was trusted for ownership", l.UserID, l.Email)
		}
	}
	if len(listed) != 0 {
		t.Errorf("ListForUser(alice) returned %d binding(s) after the account was rebound to bob, want 0: %+v",
			len(listed), listed)
	}
}

// TestAdvAStaleIndexPageCannotDeleteAnotherUsersBinding is the same staleness with
// teeth. DeleteUser sweeps whatever the index hands it, and BatchWriteItem cannot
// carry a condition, so a stale page means deleting the canonical OAUTH# item —
// whose key is the same whoever owns it — out from under its current owner.
func TestAdvAStaleIndexPageCannotDeleteAnotherUsersBinding(t *testing.T) {
	t.Parallel()
	base, client := newStore(t)
	ctx := context.Background()

	alice := newUser(t, base, "acme")
	bob := newUser(t, base, "acme")
	providerID := "sub-" + randomHex(8)

	aliceLink := sampleLink(alice.ID, "google", providerID)
	if err := base.LinkedAccounts().Save(ctx, aliceLink); err != nil {
		t.Fatalf("save alice's link: %v", err)
	}
	bobLink := sampleLink(bob.ID, "google", providerID)
	if err := base.LinkedAccounts().Save(ctx, bobLink); err != nil {
		t.Fatalf("rebind to bob: %v", err)
	}

	stale := &staleIndexAPI{API: client, owner: gsi1UserID(alice.ID), page: staleIndexPage(aliceLink)}
	store, err := New(stale, Options{TableName: base.table, Logger: base.log})
	if err != nil {
		t.Fatalf("new store: %v", err)
	}

	if err := store.DeleteUser(ctx, alice.ID, "acme"); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if stale.hits.Load() == 0 {
		t.Fatal("the stale index page was never served, so nothing is being tested")
	}

	// Bob's binding must still be there, and must still be Bob's.
	got, err := base.LinkedAccounts().FindByProvider(ctx, "google", providerID)
	if err != nil {
		t.Fatalf("deleting alice destroyed bob's provider binding: %v", err)
	}
	if got.UserID != bob.ID {
		t.Errorf("binding owner = %s, want bob (%s)", got.UserID, bob.ID)
	}
	if m := rawItem(t, client, base.table, linkIDPK(bobLink.ID), skLinkID); len(m) == 0 {
		t.Errorf("deleting alice destroyed bob's LINKID pointer %s", bobLink.ID)
	}
}

// ---------------------------------------------------------------------------
// 8. An unclassifiable pending-link namespace is reported, not silent
// ---------------------------------------------------------------------------

// TestAdvAnUnknownPendingLinkNamespaceIsReported is the guard on the one coupling
// in these stores that no compiler and no route test can check: whether the auth
// core still composes its stash keys with the prefixes keys.go classifies. The core
// does not export oauthStateKey/linkTokenKey, and the unrecognised case is treated
// as re-readable, so a core upgrade that adds a single-use namespace would make that
// credential replayable with nothing failing. The warning is what makes it visible.
func TestAdvAnUnknownPendingLinkNamespaceIsReported(t *testing.T) {
	t.Parallel()
	var buf strings.Builder
	var mu sync.Mutex
	logger := slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	store, _ := newStore(t, func(o *Options) { o.Logger = logger })
	ctx := context.Background()
	links := store.PendingLinks()

	// A namespace a future core release might add.
	future := "device-code:" + randomHex(16)
	if err := links.Save(ctx, future, sampleMeta(), time.Hour); err != nil {
		t.Fatalf("save: %v", err)
	}
	if _, err := links.Get(ctx, future); err != nil {
		t.Fatalf("an unknown namespace must still be readable, as the reference reads it: %v", err)
	}

	mu.Lock()
	logged := buf.String()
	mu.Unlock()

	if !strings.Contains(logged, "unrecognised namespace") {
		t.Errorf("an unclassifiable pending-link namespace passed in silence; log was:\n%s", logged)
	}
	if !strings.Contains(logged, "device-code:") {
		t.Errorf("the warning does not name the namespace; log was:\n%s", logged)
	}
	// The rest of the key is the credential. It must never reach a log.
	if secret := strings.TrimPrefix(future, "device-code:"); strings.Contains(logged, secret) {
		t.Errorf("the warning logged the credential itself (%q); log was:\n%s", secret, logged)
	}

	// The two known namespaces must not warn, or the signal is worthless.
	var quiet strings.Builder
	var qmu sync.Mutex
	quietLogger := slog.New(slog.NewTextHandler(&lockedWriter{w: &quiet, mu: &qmu}, &slog.HandlerOptions{Level: slog.LevelWarn}))
	quietStore, _ := newStore(t, func(o *Options) { o.Logger = quietLogger })
	quietLinks := quietStore.PendingLinks()
	for _, state := range []string{oauthStateKey(), linkTokenKey(), conflictKey("who@example.test", "google")} {
		if err := quietLinks.Save(ctx, state, sampleMeta(), time.Hour); err != nil {
			t.Fatalf("save %s: %v", state, err)
		}
		if _, err := quietLinks.Get(ctx, state); err != nil {
			t.Fatalf("get %s: %v", state, err)
		}
	}
	qmu.Lock()
	quietLogged := quiet.String()
	qmu.Unlock()
	if strings.Contains(quietLogged, "unrecognised namespace") {
		t.Errorf("a namespace this build does classify produced the warning; log was:\n%s", quietLogged)
	}
}

// TestAdvTheKnownNamespacesStillMatchTheCore is a pure unit check that the three
// prefixes are spelled the way the core spells them, written as literals rather
// than derived from the store's own table so it cannot agree with the code by
// construction. It is the companion to the warning above: this catches a typo,
// the warning catches an addition.
func TestAdvTheKnownNamespacesStillMatchTheCore(t *testing.T) {
	t.Parallel()
	// oauth_wire.go:417-426, verbatim.
	for _, tc := range []struct {
		key        string
		singleUse  bool
		classified bool
	}{
		{"oauth-state:" + randomHex(16), true, true},
		{"link-token:" + hashOf("tok"), true, true},
		{"pending-link:someone@example.test|google", false, true},
		{"device-code:" + randomHex(8), false, false},
		{"no-colon-at-all", false, false},
	} {
		if got := pendingLinkIsSingleUse(tc.key); got != tc.singleUse {
			t.Errorf("pendingLinkIsSingleUse(%q) = %v, want %v", tc.key, got, tc.singleUse)
		}
		if got := pendingLinkIsKnown(tc.key); got != tc.classified {
			t.Errorf("pendingLinkIsKnown(%q) = %v, want %v", tc.key, got, tc.classified)
		}
	}
	if got := pendingLinkNamespace("oauth-state:deadbeef"); got != "oauth-state:" {
		t.Errorf("pendingLinkNamespace = %q, want %q", got, "oauth-state:")
	}
	if got := pendingLinkNamespace("no-colon-at-all"); strings.Contains(got, "no-colon") {
		t.Errorf("pendingLinkNamespace(%q) = %q, which would put the whole key in a log",
			"no-colon-at-all", got)
	}
}

// lockedWriter serialises writes to a strings.Builder, because slog handlers are
// called from whichever goroutine logged and -race would otherwise flag the test
// rather than the code.
type lockedWriter struct {
	w  *strings.Builder
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func errOf(fn func() error) error { return fn() }

func mustIssue(t *testing.T, c familyCase, ctx context.Context, s *Store, uid, tid, hash string, exp time.Time) {
	t.Helper()
	if err := c.issue(ctx, s, uid, tid, hash, exp); err != nil {
		t.Fatalf("%s issue: %v", c.name, err)
	}
}

func mustConsume(t *testing.T, c familyCase, ctx context.Context, s *Store, uid, tid, hash string) auth.User {
	t.Helper()
	u, err := c.consume(ctx, s, uid, tid, hash)
	if err != nil {
		t.Fatalf("%s consume: %v", c.name, err)
	}
	return u
}

func mustRefuse(t *testing.T, c familyCase, ctx context.Context, s *Store, uid, tid, hash, what string) {
	t.Helper()
	if _, err := c.consume(ctx, s, uid, tid, hash); !errors.Is(err, c.family.invalidErr) {
		t.Fatalf("%s: %s was honoured: err = %v, want %v", c.name, what, err, c.family.invalidErr)
	}
}

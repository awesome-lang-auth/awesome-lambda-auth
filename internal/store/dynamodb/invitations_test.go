package dynamodb

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// The InvitationStore contract (awesome-go-auth v0.15.0, invitation.go) against
// DynamoDB Local: the single-use consume, its expiry at exactly ExpiresAt, the
// revoke and the release that are atomic against it, the consistent per-user
// read a re-invitation depends on, and the race two accepts of one token run.

var invitationEpoch = time.Date(2026, 11, 21, 9, 0, 0, 0, time.UTC)

// newInvitation builds a pending invitation for userID with a fresh token,
// returning the token alongside so a test can show it is never stored.
func newInvitation(t *testing.T, userID string) (auth.Invitation, string) {
	t.Helper()
	token := "tok-" + randomHex(16)
	return auth.Invitation{
		ID:            "inv_" + randomHex(16),
		TokenHash:     hashOf(token),
		UserID:        userID,
		TenantID:      "",
		Email:         userID + "@example.com",
		Role:          "staff",
		Metadata:      map[string]any{"team": "ops", "seats": float64(3)},
		InvitedBy:     "arn:aws:iam::123456789012:role/backoffice",
		InvitedByKind: auth.InvitedByMachine,
		CreatedAt:     invitationEpoch,
		ExpiresAt:     invitationEpoch.Add(72 * time.Hour),
	}, token
}

func mustCreate(t *testing.T, s *Store, inv auth.Invitation) {
	t.Helper()
	if err := s.CreateInvitation(context.Background(), inv); err != nil {
		t.Fatalf("CreateInvitation: %v", err)
	}
}

func pendingIDs(t *testing.T, s *Store, userID string) []string {
	t.Helper()
	got, err := s.PendingInvitationsForUser(context.Background(), userID)
	if err != nil {
		t.Fatalf("PendingInvitationsForUser: %v", err)
	}
	ids := make([]string, 0, len(got))
	for _, inv := range got {
		ids = append(ids, inv.ID)
	}
	return ids
}

func listedIDs(t *testing.T, s *Store) []string {
	t.Helper()
	got, err := s.ListPendingInvitations(context.Background(), 100, 0)
	if err != nil {
		t.Fatalf("ListPendingInvitations: %v", err)
	}
	ids := make([]string, 0, len(got))
	for _, inv := range got {
		ids = append(ids, inv.ID)
	}
	return ids
}

func TestInvitationCreateConsumeReplay(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	inv, _ := newInvitation(t, "usr_alice")
	mustCreate(t, s, inv)

	if got := pendingIDs(t, s, "usr_alice"); len(got) != 1 || got[0] != inv.ID {
		t.Fatalf("pending for user = %v, want [%s]", got, inv.ID)
	}
	if got := listedIDs(t, s); len(got) != 1 || got[0] != inv.ID {
		t.Fatalf("listed = %v, want [%s]", got, inv.ID)
	}

	now := invitationEpoch.Add(time.Hour + 123456789*time.Nanosecond)
	got, err := s.ConsumeInvitation(ctx, inv.TokenHash, now)
	if err != nil {
		t.Fatalf("ConsumeInvitation: %v", err)
	}
	if got.ID != inv.ID || got.UserID != "usr_alice" || got.TokenHash != inv.TokenHash || got.Role != "staff" ||
		got.InvitedByKind != auth.InvitedByMachine || got.Metadata["team"] != "ops" || got.Metadata["seats"] != float64(3) {
		t.Fatalf("consumed record = %+v", got)
	}
	if got.AcceptedAt == nil || !got.AcceptedAt.Equal(now) {
		t.Fatalf("AcceptedAt = %v, want %v", got.AcceptedAt, now)
	}
	if !got.ExpiresAt.Equal(inv.ExpiresAt) || !got.CreatedAt.Equal(inv.CreatedAt) {
		t.Fatalf("times = %v / %v", got.CreatedAt, got.ExpiresAt)
	}

	// The replay, and every other shape of "no", is the one sentinel.
	if _, err := s.ConsumeInvitation(ctx, inv.TokenHash, now); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("replay = %v, want ErrInvitationNotFound", err)
	}
	for _, hash := range []string{hashOf("never-issued"), "", strings.Repeat("a", maxTokenHashLen+1)} {
		if _, err := s.ConsumeInvitation(ctx, hash, now); !errors.Is(err, auth.ErrInvitationNotFound) {
			t.Fatalf("consume %q = %v, want ErrInvitationNotFound", hash, err)
		}
	}
	if got := pendingIDs(t, s, "usr_alice"); len(got) != 0 {
		t.Fatalf("pending after consume = %v, want none", got)
	}
	if got := listedIDs(t, s); len(got) != 0 {
		t.Fatalf("listed after consume = %v, want none", got)
	}
	// Revoking an accepted invitation is NotPending, with the record.
	rec, err := s.RevokeInvitation(ctx, inv.ID, now)
	if !errors.Is(err, auth.ErrInvitationNotPending) || rec.ID != inv.ID || rec.AcceptedAt == nil {
		t.Fatalf("revoke accepted = %+v, %v", rec, err)
	}
}

func TestInvitationExpiryIsTheConsumesOwnClock(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	inv, _ := newInvitation(t, "usr_bob")
	mustCreate(t, s, inv)

	// Honoured strictly before ExpiresAt: refused at the instant itself.
	if _, err := s.ConsumeInvitation(ctx, inv.TokenHash, inv.ExpiresAt); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("consume at ExpiresAt = %v, want ErrInvitationNotFound", err)
	}
	// An expired invitation stays pending: listed, reserved for its user, and
	// revocable.
	if got := listedIDs(t, s); len(got) != 1 {
		t.Fatalf("expired invitation not listed: %v", got)
	}
	if got := pendingIDs(t, s, "usr_bob"); len(got) != 1 {
		t.Fatalf("expired invitation not pending for its user: %v", got)
	}
	// One nanosecond earlier it is honoured: the refusal above was the clock,
	// not a spent token.
	if _, err := s.ConsumeInvitation(ctx, inv.TokenHash, inv.ExpiresAt.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("consume a nanosecond before ExpiresAt: %v", err)
	}

	expired, _ := newInvitation(t, "usr_bob2")
	mustCreate(t, s, expired)
	at := expired.ExpiresAt.Add(time.Hour)
	rec, err := s.RevokeInvitation(ctx, expired.ID, at)
	if err != nil || rec.RevokedAt == nil || !rec.RevokedAt.Equal(at) {
		t.Fatalf("revoke expired = %+v, %v", rec, err)
	}
}

func TestInvitationRevoke(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	inv, _ := newInvitation(t, "usr_carol")
	mustCreate(t, s, inv)
	now := invitationEpoch.Add(2 * time.Hour)

	rec, err := s.RevokeInvitation(ctx, inv.ID, now)
	if err != nil || rec.RevokedAt == nil || !rec.RevokedAt.Equal(now) || rec.AcceptedAt != nil {
		t.Fatalf("revoke = %+v, %v", rec, err)
	}
	if got := pendingIDs(t, s, "usr_carol"); len(got) != 0 {
		t.Fatalf("pending after revoke = %v", got)
	}
	if got := listedIDs(t, s); len(got) != 0 {
		t.Fatalf("listed after revoke = %v", got)
	}
	if _, err := s.ConsumeInvitation(ctx, inv.TokenHash, now); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("consume revoked = %v", err)
	}
	again, err := s.RevokeInvitation(ctx, inv.ID, now.Add(time.Minute))
	if !errors.Is(err, auth.ErrInvitationNotPending) || again.RevokedAt == nil || !again.RevokedAt.Equal(now) {
		t.Fatalf("second revoke = %+v, %v; want the first revocation, ErrInvitationNotPending", again, err)
	}
	for _, id := range []string{"inv_" + randomHex(16), "", "inv#forged", strings.Repeat("x", 80)} {
		if _, err := s.RevokeInvitation(ctx, id, now); !errors.Is(err, auth.ErrInvitationNotFound) {
			t.Fatalf("revoke %q = %v, want ErrInvitationNotFound", id, err)
		}
	}
}

func TestInvitationRelease(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	inv, _ := newInvitation(t, "usr_dave")
	mustCreate(t, s, inv)

	first := invitationEpoch.Add(3*time.Hour + 7*time.Nanosecond)
	consumed, err := s.ConsumeInvitation(ctx, inv.TokenHash, first)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	// Another instant, even a nanosecond away, names another consume.
	if err := s.ReleaseInvitation(ctx, inv.ID, first.Add(time.Nanosecond)); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("release with the wrong acceptedAt = %v", err)
	}
	if err := s.ReleaseInvitation(ctx, inv.ID, *consumed.AcceptedAt); err != nil {
		t.Fatalf("release: %v", err)
	}
	// Pending again: listed, reserved, and its token honoured.
	if got := pendingIDs(t, s, "usr_dave"); len(got) != 1 {
		t.Fatalf("pending after release = %v", got)
	}
	if got := listedIDs(t, s); len(got) != 1 {
		t.Fatalf("listed after release = %v", got)
	}
	// A release that arrives twice finds nothing to release.
	if err := s.ReleaseInvitation(ctx, inv.ID, *consumed.AcceptedAt); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("second release = %v", err)
	}
	second := first.Add(time.Minute)
	if _, err := s.ConsumeInvitation(ctx, inv.TokenHash, second); err != nil {
		t.Fatalf("consume after release: %v", err)
	}
	// A late release of the first consume must not undo the second.
	if err := s.ReleaseInvitation(ctx, inv.ID, first); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("late release = %v", err)
	}
	if got := pendingIDs(t, s, "usr_dave"); len(got) != 0 {
		t.Fatalf("a late release reopened the invitation: %v", got)
	}

	// Pending and revoked records are not released; an unknown id neither.
	pending, _ := newInvitation(t, "usr_dave")
	mustCreate(t, s, pending)
	if err := s.ReleaseInvitation(ctx, pending.ID, first); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("release pending = %v", err)
	}
	if _, err := s.RevokeInvitation(ctx, pending.ID, first); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if err := s.ReleaseInvitation(ctx, pending.ID, first); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("release revoked = %v", err)
	}
	if err := s.ReleaseInvitation(ctx, "inv_"+randomHex(16), first); !errors.Is(err, auth.ErrInvitationNotFound) {
		t.Fatalf("release unknown = %v", err)
	}
}

// A re-invitation (Config.InvitationReinvite) reads the user's pending
// invitations, creates a new one, and revokes the earlier ones: the per-user
// read has to see every one of them, in id order, the moment each call
// returns.
func TestInvitationReinviteReadsAreConsistent(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	a, _ := newInvitation(t, "usr_erin")
	b, _ := newInvitation(t, "usr_erin")
	other, _ := newInvitation(t, "usr_frank")
	mustCreate(t, s, a)
	mustCreate(t, s, b)
	mustCreate(t, s, other)

	want := []string{a.ID, b.ID}
	if want[0] > want[1] {
		want[0], want[1] = want[1], want[0]
	}
	if got := pendingIDs(t, s, "usr_erin"); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("pending for erin = %v, want %v", got, want)
	}
	if _, err := s.RevokeInvitation(ctx, a.ID, invitationEpoch); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := pendingIDs(t, s, "usr_erin"); len(got) != 1 || got[0] != b.ID {
		t.Fatalf("pending after retiring the first = %v, want [%s]", got, b.ID)
	}
	if got := pendingIDs(t, s, "usr_frank"); len(got) != 1 || got[0] != other.ID {
		t.Fatalf("frank's pending = %v", got)
	}
	if got := pendingIDs(t, s, "usr_nobody"); len(got) != 0 {
		t.Fatalf("a user with no invitation has %v", got)
	}
	if got, err := s.PendingInvitationsForUser(ctx, "bad#id"); err != nil || len(got) != 0 {
		t.Fatalf("malformed user id = %v, %v", got, err)
	}
}

func TestInvitationCreateRefusesACollision(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	inv, _ := newInvitation(t, "usr_gina")
	mustCreate(t, s, inv)

	sameID, _ := newInvitation(t, "usr_gina")
	sameID.ID = inv.ID
	if err := s.CreateInvitation(ctx, sameID); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("same id = %v, want ErrAlreadyExists", err)
	}
	sameHash, _ := newInvitation(t, "usr_gina")
	sameHash.TokenHash = inv.TokenHash
	if err := s.CreateInvitation(ctx, sameHash); !errors.Is(err, auth.ErrAlreadyExists) {
		t.Fatalf("same token hash = %v, want ErrAlreadyExists", err)
	}
	// Neither refusal wrote anything: still exactly one pending invitation.
	if got := pendingIDs(t, s, "usr_gina"); len(got) != 1 {
		t.Fatalf("pending after refused creates = %v", got)
	}
	empty := inv
	empty.TokenHash = ""
	if err := s.CreateInvitation(ctx, empty); err == nil {
		t.Fatal("an invitation with no token hash was stored")
	}
}

// The token is the credential: only its hash may be in the table, and every
// item of an invitation carries the TTL of ExpiresAt plus the retention.
func TestInvitationStoresOnlyTheHashAndATTL(t *testing.T) {
	s, client := newStore(t)
	inv, token := newInvitation(t, "usr_hana")
	mustCreate(t, s, inv)

	out, err := client.Scan(context.Background(), &awsddb.ScanInput{TableName: aws.String(s.table)})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if len(out.Items) != 3 {
		t.Fatalf("an invitation wrote %d items, want 3 (record, token pointer, membership)", len(out.Items))
	}
	wantTTL := strconv.FormatInt(inv.ExpiresAt.Add(DefaultInvitationRetention).Unix(), 10)
	for _, it := range out.Items {
		for name, av := range it {
			if strings.Contains(attrString(av), token) {
				t.Fatalf("the plaintext token is stored in %s of %s", name, getS(it, attrPK))
			}
		}
		if ttl, ok := it[attrTTL].(*types.AttributeValueMemberN); !ok || ttl.Value != wantTTL {
			t.Fatalf("item %s ttl = %v, want %s", getS(it, attrPK), it[attrTTL], wantTTL)
		}
	}
}

func attrString(av types.AttributeValue) string {
	switch v := av.(type) {
	case *types.AttributeValueMemberS:
		return v.Value
	case *types.AttributeValueMemberM:
		var b strings.Builder
		for k, e := range v.Value {
			b.WriteString(k + "=" + attrString(e) + ";")
		}
		return b.String()
	}
	return ""
}

// Exactly one of any number of concurrent accepts of one token wins, and the
// rest see the one sentinel — the guarantee the core's own re-checks rest on.
func TestInvitationConcurrentConsumesHaveOneWinner(t *testing.T) {
	s, _ := newStore(t)
	for round := 0; round < 5; round++ {
		inv, _ := newInvitation(t, "usr_race")
		mustCreate(t, s, inv)

		const racers = 8
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			winners  int
			failures []error
		)
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, err := s.ConsumeInvitation(context.Background(), inv.TokenHash, invitationEpoch.Add(time.Duration(i)*time.Millisecond))
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					winners++
				case !errors.Is(err, auth.ErrInvitationNotFound):
					failures = append(failures, err)
				}
			}(i)
		}
		close(start)
		wg.Wait()
		if winners != 1 || len(failures) > 0 {
			t.Fatalf("round %d: %d winners, unexpected errors %v; want exactly one winner", round, winners, failures)
		}
	}
}

// A consume and a revoke racing on one invitation: accepted or revoked, never
// both, and the membership item gone either way.
func TestInvitationConsumeAndRevokeRace(t *testing.T) {
	s, _ := newStore(t)
	for round := 0; round < 5; round++ {
		inv, _ := newInvitation(t, "usr_duel")
		mustCreate(t, s, inv)
		var (
			wg                   sync.WaitGroup
			consumeErr, revokeEr error
		)
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			_, consumeErr = s.ConsumeInvitation(context.Background(), inv.TokenHash, invitationEpoch)
		}()
		go func() {
			defer wg.Done()
			<-start
			_, revokeEr = s.RevokeInvitation(context.Background(), inv.ID, invitationEpoch)
		}()
		close(start)
		wg.Wait()
		consumed, revoked := consumeErr == nil, revokeEr == nil
		if consumed == revoked {
			t.Fatalf("round %d: consume=%v revoke=%v; exactly one must win", round, consumeErr, revokeEr)
		}
		if !consumed && !errors.Is(consumeErr, auth.ErrInvitationNotFound) {
			t.Fatalf("round %d: losing consume = %v", round, consumeErr)
		}
		if !revoked && !errors.Is(revokeEr, auth.ErrInvitationNotPending) {
			t.Fatalf("round %d: losing revoke = %v", round, revokeEr)
		}
		if got := pendingIDs(t, s, "usr_duel"); len(got) != 0 {
			t.Fatalf("round %d: still pending for its user: %v", round, got)
		}
	}
}

func TestInvitationListingPages(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()
	var ids []string
	for i := 0; i < 5; i++ {
		inv, _ := newInvitation(t, "usr_page")
		mustCreate(t, s, inv)
		ids = append(ids, inv.ID)
	}
	// The second one ends: the listing skips it without a short page.
	if _, err := s.RevokeInvitation(ctx, ids[1], invitationEpoch); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	all := listedIDs(t, s)
	if len(all) != 4 {
		t.Fatalf("listed = %v, want 4", all)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1] >= all[i] {
			t.Fatalf("listing not in id order: %v", all)
		}
	}
	page, err := s.ListPendingInvitations(ctx, 2, 1)
	if err != nil || len(page) != 2 || page[0].ID != all[1] || page[1].ID != all[2] {
		t.Fatalf("page(2,1) = %v, %v; want %v", page, err, all[1:3])
	}
	if page, err := s.ListPendingInvitations(ctx, 0, 0); err != nil || len(page) != 0 {
		t.Fatalf("limit 0 = %v, %v", page, err)
	}
	if page, err := s.ListPendingInvitations(ctx, 10, -3); err != nil || len(page) != 4 {
		t.Fatalf("negative offset = %v, %v", page, err)
	}
}

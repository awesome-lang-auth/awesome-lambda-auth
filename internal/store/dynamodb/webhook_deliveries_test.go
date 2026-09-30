package dynamodb

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// These are the ledger's own claims (data-model.md §1.9), asserted against
// DynamoDB Local like every other conditional write in this package. The worker
// that uses the ledger has its own end-to-end race in cmd/webhook-worker; this
// file pins the state machine underneath it.

func TestWebhookDeliveryClaimIsGrantedOnceAndStamped(t *testing.T) {
	store, client := newStore(t)
	ctx := context.Background()
	id := uniqueID("dlv")

	got, err := store.ClaimWebhookDelivery(ctx, id, "whk_1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got.Outcome != WebhookClaimGranted || got.Claim.Claims != 1 || got.Claim.Owner == "" {
		t.Fatalf("first claim = %+v, want granted with claims 1 and an owner", got)
	}

	item := rawItem(t, client, store.table, webhookDeliveryPK(id), skWebhookDelivery)
	state, claims := webhookDeliveryStateOf(item)
	if state != WebhookDeliveryClaimed || claims != 1 {
		t.Errorf("stored state %q claims %d, want claimed/1", state, claims)
	}
	if getS(item, attrType) != typeWebhookDelivery || getS(item, attrDeliveryConfig) != "whk_1" {
		t.Errorf("stored _t %q configId %q", getS(item, attrType), getS(item, attrDeliveryConfig))
	}
	ttl := time.Unix(getN(item, attrTTL), 0)
	if d := time.Until(ttl); d < WebhookDeliveryWindow-time.Minute || d > WebhookDeliveryWindow+time.Minute {
		t.Errorf("ttl is %s away, want about %s", d, WebhookDeliveryWindow)
	}

	// A second claim while the lease is live is busy, with the lease reported.
	again, err := store.ClaimWebhookDelivery(ctx, id, "whk_1", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatalf("second claim: %v", err)
	}
	if again.Outcome != WebhookClaimBusy || time.Until(again.BusyUntil) <= 0 {
		t.Fatalf("second claim = %+v, want busy until a future lease", again)
	}
}

func TestWebhookDeliveryWithoutAConfigIDStoresNone(t *testing.T) {
	store, client := newStore(t)
	id := uniqueID("dlv")
	if _, err := store.ClaimWebhookDelivery(context.Background(), id, "", time.Now().Add(time.Minute)); err != nil {
		t.Fatalf("claim with no config id: %v", err)
	}
	item := rawItem(t, client, store.table, webhookDeliveryPK(id), skWebhookDelivery)
	if _, ok := item[attrDeliveryConfig]; ok {
		t.Error("an empty config id was written; the omission rule says absent")
	}
}

func TestWebhookDeliverySettlesThroughItsStates(t *testing.T) {
	store, client := newStore(t)
	ctx := context.Background()
	id := uniqueID("dlv")
	lease := func() time.Time { return time.Now().Add(time.Minute) }

	first, err := store.ClaimWebhookDelivery(ctx, id, "", lease())
	if err != nil {
		t.Fatal(err)
	}
	// A refusal releases the delivery for the next receive, and the counter
	// carries on: the second claim is the second attempt.
	if err := store.SettleWebhookDelivery(ctx, first.Claim, WebhookDeliveryFailed); err != nil {
		t.Fatalf("settle failed: %v", err)
	}
	item := rawItem(t, client, store.table, webhookDeliveryPK(id), skWebhookDelivery)
	if _, ok := item[attrDeliveryOwner]; ok {
		t.Error("a settled claim kept its owner token")
	}
	second, err := store.ClaimWebhookDelivery(ctx, id, "", lease())
	if err != nil {
		t.Fatal(err)
	}
	if second.Outcome != WebhookClaimGranted || second.Claim.Claims != 2 {
		t.Fatalf("claim after a failure = %+v, want granted with claims 2", second)
	}
	if err := store.SettleWebhookDelivery(ctx, second.Claim, WebhookDeliveryDelivered); err != nil {
		t.Fatalf("settle delivered: %v", err)
	}
	// Delivered is absorbing: every later receive acknowledges.
	for i := 0; i < 2; i++ {
		after, err := store.ClaimWebhookDelivery(ctx, id, "", lease())
		if err != nil {
			t.Fatal(err)
		}
		if after.Outcome != WebhookClaimDelivered {
			t.Fatalf("claim after delivery = %+v, want delivered", after)
		}
	}
	if _, claims := webhookDeliveryStateOf(rawItem(t, client, store.table, webhookDeliveryPK(id), skWebhookDelivery)); claims != 2 {
		t.Errorf("a refused claim advanced the counter to %d", claims)
	}
}

func TestWebhookDeliveryAbandonedIsAbsorbing(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	id := uniqueID("dlv")
	c, err := store.ClaimWebhookDelivery(ctx, id, "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SettleWebhookDelivery(ctx, c.Claim, WebhookDeliveryAbandoned); err != nil {
		t.Fatal(err)
	}
	after, err := store.ClaimWebhookDelivery(ctx, id, "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if after.Outcome != WebhookClaimAbandoned {
		t.Fatalf("claim after abandonment = %+v, want abandoned", after)
	}
}

func TestWebhookDeliveryLapsedLeaseIsTakenOverAndTheOldSettleLoses(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	id := uniqueID("dlv")

	// A claimant whose lease is already over — a crashed invocation.
	crashed, err := store.ClaimWebhookDelivery(ctx, id, "", time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	successor, err := store.ClaimWebhookDelivery(ctx, id, "", time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if successor.Outcome != WebhookClaimGranted || successor.Claim.Claims != 2 {
		t.Fatalf("claim over a lapsed lease = %+v, want granted with claims 2 (the crashed attempt counts)", successor)
	}
	// The crashed claimant waking up must not overwrite its successor.
	if err := store.SettleWebhookDelivery(ctx, crashed.Claim, WebhookDeliveryDelivered); !errors.Is(err, ErrWebhookClaimLost) {
		t.Fatalf("settle by a superseded claim = %v, want ErrWebhookClaimLost", err)
	}
	if err := store.SettleWebhookDelivery(ctx, successor.Claim, WebhookDeliveryFailed); err != nil {
		t.Fatalf("settle by the live claim: %v", err)
	}
}

func TestWebhookDeliveryClaimIsAtomicUnderConcurrency(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	const rounds, racers = 30, 8
	for round := 0; round < rounds; round++ {
		id := uniqueID("dlv")
		var granted, busy atomic.Int32
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < racers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				got, err := store.ClaimWebhookDelivery(ctx, id, "", time.Now().Add(time.Minute))
				if err != nil {
					t.Errorf("claim: %v", err)
					return
				}
				switch got.Outcome {
				case WebhookClaimGranted:
					granted.Add(1)
				case WebhookClaimBusy:
					busy.Add(1)
				}
			}()
		}
		close(start)
		wg.Wait()
		if granted.Load() != 1 || busy.Load() != racers-1 {
			t.Fatalf("round %d: %d granted and %d busy, want exactly 1 and %d", round, granted.Load(), busy.Load(), racers-1)
		}
	}
}

func TestWebhookDeliveryRefusesAnUnusableKeyOrState(t *testing.T) {
	store, _ := newStore(t)
	ctx := context.Background()
	if _, err := store.ClaimWebhookDelivery(ctx, "", "", time.Now()); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("empty delivery id: %v, want ErrInvalidIdentifier", err)
	}
	if _, err := store.ClaimWebhookDelivery(ctx, "a\nb", "", time.Now()); !errors.Is(err, ErrInvalidIdentifier) {
		t.Errorf("control character: %v, want ErrInvalidIdentifier", err)
	}
	if err := store.SettleWebhookDelivery(ctx, WebhookClaim{DeliveryID: "x", Owner: "y"}, WebhookDeliveryClaimed); err == nil {
		t.Error("settling into claimed was accepted")
	}
}

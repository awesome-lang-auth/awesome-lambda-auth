package dynamodb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// This file is the outgoing-webhook delivery ledger (data-model.md §1.9, rows
// #76-#78): the idempotency record the SQS webhook worker keeps, one item per
// delivery, so that at-least-once queue delivery does not become
// more-than-once webhook delivery.
//
// Like the rate-limit counter it implements no awesome-go-auth interface and no
// auth route reaches it. Its only caller is cmd/webhook-worker (D9b), whose IAM
// role is scoped to this partition prefix and nothing else in the table. It
// lives here rather than beside the worker because every key in this table is
// composed in this package, which is what keeps one namespace from forging
// another's.
//
// ── why a ledger and not the reserved boolean ─────────────────────────────────
//
// §2.3 reserved PK=IDEM#<scope>#<key>, SK=IDEM, attribute_not_exists(PK). That
// shape is right for a consumer that must act at most once per key, and wrong
// for this one. The key is WebhookAttempt.DeliveryID, which the core mints and
// the worker resends unchanged on every retry of one queued delivery (the core's
// WebhookDeliverer contract: "resend the header it was handed"). A put that
// refused an existing key would therefore let the first attempt through and
// silently swallow every retry after a refusal — the webhook would be tried
// once and never again. What must be single is the *successful* POST, so the
// item carries a state and a lease:
//
//	claimed   a worker holds a lease and may be mid-request
//	failed    the last request was refused; the next receive may claim
//	delivered a 2xx was seen; every later receive acknowledges, no request
//	abandoned the budget is spent and the message went to the dead-letter queue
//
// and a claim succeeds in exactly the three situations where a request is
// allowed: nobody has tried, the last try failed, or the last claimant's lease
// lapsed without a settle (it crashed or timed out — and may or may not have
// reached the receiver, which is at-least-once and not exactly-once, stated).
//
// ── what one attempt costs ────────────────────────────────────────────────────
//
// Two writes, the claim and the settle, each on an item well under 1 KB: 2 WCU
// per attempt. A duplicate receive costs one failed conditional write — billed —
// and nothing else: the pre-image comes back on the failure itself
// (ReturnValuesOnConditionCheckFailure), so classifying a lost claim needs no
// read. docs/cost-model.md §3.3 carries the numbers.

// Delivery-ledger key space.
const (
	// pkWebhookDeliveryPrefix is §2.3's reserved IDEM# namespace with the one
	// scope that uses it. The delivery id is the whole tail, so a '#' inside it
	// is unambiguous; checkOpaque is the validation.
	pkWebhookDeliveryPrefix = "IDEM" + keySep + "webhook" + keySep

	// skWebhookDelivery is the single sort key of the partition, as for the
	// rate-limit counter: one item per delivery, nothing to distinguish.
	skWebhookDelivery = "IDEM"
)

// typeWebhookDelivery is the ledger item's _t.
const typeWebhookDelivery = "webhookdelivery"

// Ledger attributes. Plain names: the item is written twice per attempt and
// read by an operator after a dead-letter, and readability wins over the bytes.
const (
	attrDeliveryState  = "state"
	attrDeliveryClaims = "claims"
	attrDeliveryOwner  = "owner"
	attrDeliveryLease  = "leaseUntil"
	attrDeliveryConfig = "configId"
	attrDeliveryAt     = "updatedAt"
)

// WebhookDeliveryWindow is how long a ledger item outlives its last write
// before TTL may reap it, and therefore how long after its last attempt a
// duplicate of a delivery is still recognised.
//
// Twenty-four hours, rewritten on every claim and settle. SQS duplicates arrive
// within minutes; the longest gap between two attempts of one delivery is SQS's
// twelve-hour visibility maximum, which the worker caps its back-off at, so a
// window refreshed at every transition outlives every gap in any schedule the
// worker can produce.
const WebhookDeliveryWindow = 24 * time.Hour

// maxWebhookDeliveryIDLen bounds the delivery id segment. The core mints a
// 36-byte UUID; the bound is for a message that did not come from the core.
const maxWebhookDeliveryIDLen = 128

// maxWebhookConfigIDLen bounds the optional configId attribute, which is data
// and not key, so the bound is only there to keep a forged message from
// writing a large item.
const maxWebhookConfigIDLen = 256

// WebhookDeliveryState is the ledger's state attribute.
type WebhookDeliveryState string

// The four states. See the file header.
const (
	WebhookDeliveryClaimed   WebhookDeliveryState = "claimed"
	WebhookDeliveryFailed    WebhookDeliveryState = "failed"
	WebhookDeliveryDelivered WebhookDeliveryState = "delivered"
	WebhookDeliveryAbandoned WebhookDeliveryState = "abandoned"
)

// WebhookClaimOutcome is what ClaimWebhookDelivery found.
type WebhookClaimOutcome int

const (
	// WebhookClaimGranted: the caller holds the delivery and may POST.
	WebhookClaimGranted WebhookClaimOutcome = iota + 1
	// WebhookClaimDelivered: a previous attempt succeeded; acknowledge, send
	// nothing.
	WebhookClaimDelivered
	// WebhookClaimAbandoned: a previous attempt spent the budget and handed
	// the message to the dead-letter queue; the caller should make sure it is
	// there and acknowledge, sending nothing.
	WebhookClaimAbandoned
	// WebhookClaimBusy: another claimant holds a live lease. The caller must
	// NOT acknowledge — the message may be the only copy that claimant's retry
	// depends on — and should come back after BusyUntil.
	WebhookClaimBusy
)

// WebhookClaim is a granted claim, which is what SettleWebhookDelivery needs.
type WebhookClaim struct {
	DeliveryID string
	// Owner is this claim's random token. The settle is conditional on it, so
	// a claimant whose lease lapsed and was taken over cannot overwrite its
	// successor's outcome.
	Owner string
	// Claims is the number of claims this delivery has had, this one
	// included: the attempt counter (data-model.md §1.9 — a receive is not an
	// attempt, a claim is).
	Claims int
}

// WebhookClaimResult is ClaimWebhookDelivery's answer.
type WebhookClaimResult struct {
	Outcome WebhookClaimOutcome
	// Claim is set when Outcome is WebhookClaimGranted.
	Claim WebhookClaim
	// BusyUntil is the live claimant's lease when Outcome is WebhookClaimBusy.
	BusyUntil time.Time
}

// ErrWebhookClaimLost means a settle found the delivery no longer held by the
// caller's claim: its lease lapsed and another claimant took it. The caller's
// outcome is not recorded, which is right — the successor's is the current one.
var ErrWebhookClaimLost = errors.New("dynamodb: the webhook delivery claim was lost to another claimant")

func webhookDeliveryPK(deliveryID string) string { return pkWebhookDeliveryPrefix + deliveryID }

// ClaimWebhookDelivery takes the lease on one delivery until leaseUntil, or
// reports why it cannot (data-model.md §1.9 #76, #77).
//
// leaseUntil is the claimant's own deadline — the worker passes its
// invocation's — because a claim must not outlive the process that holds it:
// once it has lapsed the delivery is claimable again, and a claimant that
// crashed mid-request has its attempt counted, because it may have reached the
// receiver.
//
// configID is recorded for an operator reading the table after a dead-letter,
// and may be empty.
func (s *Store) ClaimWebhookDelivery(ctx context.Context, deliveryID, configID string, leaseUntil time.Time) (WebhookClaimResult, error) {
	if err := checkOpaque("webhook delivery id", deliveryID, maxWebhookDeliveryIDLen); err != nil {
		return WebhookClaimResult{}, err
	}
	if len(configID) > maxWebhookConfigIDLen {
		return WebhookClaimResult{}, fmt.Errorf("%w: webhook config id longer than %d bytes", ErrInvalidIdentifier, maxWebhookConfigIDLen)
	}
	owner, err := newClaimToken()
	if err != nil {
		return WebhookClaimResult{}, err
	}
	now := s.nowUTC()

	set := "SET #state = :claimed, #owner = :owner, #lease = :lease, " +
		"#claims = if_not_exists(#claims, :zero) + :one, #at = :at, #ttl = :ttl, #etype = :type, #ever = :ver"
	values := map[string]types.AttributeValue{
		":claimed": avS(string(WebhookDeliveryClaimed)),
		":failed":  avS(string(WebhookDeliveryFailed)),
		":owner":   avS(owner),
		":lease":   avN(leaseUntil.UnixMilli()),
		":now":     avN(now.UnixMilli()),
		":zero":    avN(0),
		":one":     avN(1),
		":at":      avS(formatTime(now)),
		":ttl":     avN(now.Add(WebhookDeliveryWindow).Unix()),
		":type":    avS(typeWebhookDelivery),
		":ver":     avN(schemaVersion),
	}
	// Aliases written out for the reason rate_limit.go gives: two of the names
	// are _t and _v. Built per call because DynamoDB refuses an alias the
	// expressions do not use, and #config is used only when there is one.
	names := map[string]string{
		"#pk":     attrPK,
		"#state":  attrDeliveryState,
		"#owner":  attrDeliveryOwner,
		"#lease":  attrDeliveryLease,
		"#claims": attrDeliveryClaims,
		"#at":     attrDeliveryAt,
		"#ttl":    attrTTL,
		"#etype":  attrType,
		"#ever":   attrVer,
	}
	if configID != "" {
		set += ", #config = :config"
		values[":config"] = avS(configID)
		names["#config"] = attrDeliveryConfig
	}

	out, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:        aws.String(s.table),
		Key:              key(webhookDeliveryPK(deliveryID), skWebhookDelivery),
		UpdateExpression: aws.String(set),
		// The three situations in which a request is allowed, and no other:
		// nobody has tried, the last try was refused, or the last claimant's
		// lease lapsed without a settle. delivered and abandoned are absorbing.
		ConditionExpression:       aws.String("attribute_not_exists(#pk) OR #state = :failed OR (#state = :claimed AND #lease < :now)"),
		ExpressionAttributeNames:  names,
		ExpressionAttributeValues: values,
		ReturnValues:              types.ReturnValueAllNew,
		// A lost claim carries the item that beat it, so #77 is not a read.
		ReturnValuesOnConditionCheckFailure: types.ReturnValuesOnConditionCheckFailureAllOld,
	})
	if err == nil {
		return WebhookClaimResult{
			Outcome: WebhookClaimGranted,
			Claim: WebhookClaim{
				DeliveryID: deliveryID,
				Owner:      owner,
				Claims:     int(getN(out.Attributes, attrDeliveryClaims)),
			},
		}, nil
	}
	old, lost := conditionFailedItem(err)
	if !lost {
		return WebhookClaimResult{}, fmt.Errorf("dynamodb: claim webhook delivery: %w", err)
	}
	switch WebhookDeliveryState(getS(old, attrDeliveryState)) {
	case WebhookDeliveryDelivered:
		return WebhookClaimResult{Outcome: WebhookClaimDelivered}, nil
	case WebhookDeliveryAbandoned:
		return WebhookClaimResult{Outcome: WebhookClaimAbandoned}, nil
	case WebhookDeliveryClaimed:
		return WebhookClaimResult{
			Outcome:   WebhookClaimBusy,
			BusyUntil: time.UnixMilli(getN(old, attrDeliveryLease)).UTC(),
		}, nil
	default:
		// A state this build does not know, written by a newer one. Busy for a
		// short while is the answer that neither sends nor loses anything.
		return WebhookClaimResult{Outcome: WebhookClaimBusy, BusyUntil: now.Add(time.Minute)}, nil
	}
}

// SettleWebhookDelivery records a granted claim's outcome (§1.9 #78):
// delivered after a 2xx, failed after a refusal with budget left, abandoned
// when the budget is spent and the message is being dead-lettered.
//
// It is conditional on the claim still being the caller's. ErrWebhookClaimLost
// means it was not; the caller logs it and carries on, because the delivery's
// current outcome is its successor's to record.
func (s *Store) SettleWebhookDelivery(ctx context.Context, claim WebhookClaim, state WebhookDeliveryState) error {
	switch state {
	case WebhookDeliveryDelivered, WebhookDeliveryFailed, WebhookDeliveryAbandoned:
	default:
		return fmt.Errorf("dynamodb: %q is not a state a claim settles into", state)
	}
	if err := checkOpaque("webhook delivery id", claim.DeliveryID, maxWebhookDeliveryIDLen); err != nil {
		return err
	}
	now := s.nowUTC()
	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:           aws.String(s.table),
		Key:                 key(webhookDeliveryPK(claim.DeliveryID), skWebhookDelivery),
		UpdateExpression:    aws.String("SET #state = :state, #at = :at, #ttl = :ttl REMOVE #owner, #lease"),
		ConditionExpression: aws.String("#state = :claimed AND #owner = :owner"),
		ExpressionAttributeNames: map[string]string{
			"#state": attrDeliveryState,
			"#owner": attrDeliveryOwner,
			"#lease": attrDeliveryLease,
			"#at":    attrDeliveryAt,
			"#ttl":   attrTTL,
		},
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":state":   avS(string(state)),
			":claimed": avS(string(WebhookDeliveryClaimed)),
			":owner":   avS(claim.Owner),
			":at":      avS(formatTime(now)),
			":ttl":     avN(now.Add(WebhookDeliveryWindow).Unix()),
		},
	})
	switch {
	case err == nil:
		return nil
	case isConditionFailed(err):
		return ErrWebhookClaimLost
	default:
		return fmt.Errorf("dynamodb: settle webhook delivery: %w", err)
	}
}

// newClaimToken is a claim's owner token: 128 random bits, hex. It is not a
// secret — it only has to differ between two claimants of one delivery.
func newClaimToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("dynamodb: claim token: %w", err)
	}
	return hex.EncodeToString(b[:]), nil
}

// webhookDeliveryStateOf reads a raw ledger item's state and claim count, for
// tests and for an operator tool; the worker never needs it.
func webhookDeliveryStateOf(item map[string]types.AttributeValue) (WebhookDeliveryState, int) {
	return WebhookDeliveryState(getS(item, attrDeliveryState)), int(getN(item, attrDeliveryClaims))
}

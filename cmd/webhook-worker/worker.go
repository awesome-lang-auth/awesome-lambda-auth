package main

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The worker's per-record logic. main.go only reads the environment and
// starts the handler; everything that decides anything is here, where the
// tests reach it.
//
// ── what one record goes through ──────────────────────────────────────────────
//
//  1. Decode. The Schema and RetryDelayMs attributes and the body must all be
//     what awsintegration.SQSWebhookDeliverer writes. A message that is not is
//     dead-lettered with reason "malformed" and acknowledged: nothing about it
//     can be scheduled, and guessing a delay or a URL would be delivering
//     something nobody enqueued.
//  2. Claim the delivery in the ledger (data-model.md §1.9). delivered →
//     acknowledge, no request. abandoned → make sure it is in the DLQ
//     ("abandoned-earlier"), acknowledge. busy → another invocation holds a
//     live claim on the same delivery id — a duplicate receive — so report a
//     batch-item failure with the visibility set to the end of that lease and
//     do NOT acknowledge: this copy may be the one the other claimant's retry
//     depends on. The ledger unreachable → no request, back to the queue.
//  3. POST, with the core's own HTTP deliverer, the headers and body exactly as
//     the core built them. The only header added is X-Correlation-Id, which the
//     in-process path adds in its transport too; the signature covers the body
//     alone, so a header added is survivable and a body changed is not.
//  4. 2xx → settle delivered, acknowledge. Anything else → if the budget is
//     spent, settle abandoned, dead-letter ("exhausted"), acknowledge;
//     otherwise settle failed, set the message's visibility to the reference's
//     back-off for this attempt, report a batch-item failure, and let SQS hand
//     it back when the wait is over.
//
// ── the schedule, and where it is counted ────────────────────────────────────
//
// The core numbered the attempt it handed the deliverer — normally attempt 0
// with Remaining equal to the subscription's Retries() — and the reference's
// wait after the n-th failure, counting from zero, is RetryDelay × 2ⁿ
// (webhook-sender.ts:45-46; the core's webhookBackoff). The worker continues
// that numbering: its k-th claim of a delivery is attempt Attempt+k with
// Remaining−k left, and a failure there waits RetryDelay × 2^(Attempt+k). The
// counter is the ledger's claim count and not SQS's ApproximateReceiveCount,
// because a receive is not an attempt — a duplicate bounced off a live claim
// made no request, and counting it would spend a retry the receiver never saw.
//
// Two limits of SQS shape what that can reproduce, and both are stated rather
// than hidden:
//
//   - Visibility is whole seconds and at most twelve hours from the receive.
//     A wait is rounded UP to the second — never earlier than the reference
//     for the copy the wait is set on — and capped just under twelve hours.
//     With the defaults (1 s, three retries: waits of 1, 2 and 4 s) neither
//     bites; a subscription whose schedule reaches half a day waits half a day
//     rather than longer. The visibility is a property of one receipt, not of
//     the delivery: an SQS duplicate copy of the message that happens to be
//     visible when an attempt fails can claim the settled "failed" at once and
//     make the next attempt early. It spends a slot of the budget as numbered,
//     and standard-queue duplicates are rare; closing it would take a
//     retry-after time in the ledger and a fourth branch in the claim, which is
//     not bought here.
//   - The queue's redrive policy has one maxReceiveCount for every message,
//     and Retries() is per subscription. So the queue's count is a CEILING on
//     receives — attempts, duplicate bounces, receives that met the ledger
//     unreachable, and crashes together: every one of them is a receive — and
//     the per-subscription count is enforced here, by the ledger, with an
//     explicit dead-letter when it is spent. Whenever a receive would hand the
//     message back to the queue and it is the receive the queue would redrive
//     next, the worker dead-letters it itself, with the reason that held it
//     back: "receive-ceiling" after a refused POST with attempts left,
//     "busy-at-ceiling" after a duplicate bounce, "ledger-unavailable" when no
//     claim could be made. So a message reaches the DLQ without a reason only
//     when the worker did not finish its last receive at all — it crashed or
//     timed out on it, or the hand-off to the DLQ itself failed. The
//     template's default ceiling is twelve receives: the largest attempt count
//     the schema lets tools.outboundWebhooks.defaults.maxRetries produce (10
//     retries, 11 attempts) plus one receive of slack. A row given more
//     retries through the admin API meets the ceiling, and so can a row at the
//     schema's maximum whose receives were also spent on bounces or on the
//     ledger — the price of one number for the whole queue.
//   - The queue keeps a message for its MessageRetentionPeriod (fourteen days
//     in the template) from the original enqueue, and then deletes it without
//     redriving it anywhere. A message this worker would hand back with less
//     than expiryMargin of that left after its wait is dead-lettered instead,
//     reason "expiring", where it gets a fresh fourteen days and the alarm. A
//     message that is never received before it expires — a backlog deeper than
//     the worker drains, or a worker that cannot start — is beyond this: SQS
//     drops it unseen, and the docs say so (config-reference.md §17.4).

// ledger is the slice of the DynamoDB store the worker uses: the delivery
// ledger and nothing else. *ddbstore.Store satisfies it.
type ledger interface {
	ClaimWebhookDelivery(ctx context.Context, deliveryID, configID string, leaseUntil time.Time) (ddbstore.WebhookClaimResult, error)
	SettleWebhookDelivery(ctx context.Context, claim ddbstore.WebhookClaim, state ddbstore.WebhookDeliveryState) error
}

var _ ledger = (*ddbstore.Store)(nil)

// Dead-letter reasons, written as the DeadLetterReason attribute on the copy
// the DLQ receives. The file header says when each is written.
const (
	reasonMalformed         = "malformed"
	reasonExhausted         = "exhausted"
	reasonReceiveCeiling    = "receive-ceiling"
	reasonBusyAtCeiling     = "busy-at-ceiling"
	reasonLedgerUnavailable = "ledger-unavailable"
	reasonExpiring          = "expiring"
	// reasonAbandonedEarlier is a receive that found the ledger already
	// abandoned: an earlier receive gave the delivery up and handed a copy to
	// the DLQ with the real reason — or tried to and failed, which is why this
	// one hands another. The ledger does not keep the first reason, so this
	// copy does not repeat one it cannot know.
	reasonAbandonedEarlier = "abandoned-earlier"
)

// expiryMargin is how much of the queue's retention a message must still have
// after the wait it is handed back with, or it is dead-lettered as expiring:
// twelve hours, which is the longest wait the worker sets, again — room for a
// message to sit visible behind a backlog before it is received.
const expiryMargin = 12 * time.Hour

// queueDefault as a hand-back wait leaves the message's visibility to the
// queue's own VisibilityTimeout rather than setting one.
const queueDefault time.Duration = -1

// maxVisibility is the longest wait the worker asks SQS for: twelve hours,
// SQS's maximum counted from the receive, less a minute for the time this
// invocation has already spent since it received the message.
const maxVisibility = 12*time.Hour - time.Minute

// defaultLease is the claim lease when the context carries no deadline. The
// Lambda runtime always sets one; this is for a caller that does not.
const defaultLease = time.Minute

type worker struct {
	sqs    awsintegration.SQSAPI
	ledger ledger
	// deliver POSTs. The core's HTTPWebhookDeliverer in production, so the
	// request is built by the code the in-process path uses (WebhookAttempt.
	// NewRequest) and a 2xx means what the reference's res.ok means.
	deliver auth.WebhookDeliverer

	queueURL string
	dlqURL   string
	// maxReceives is the queue's RedrivePolicy.maxReceiveCount.
	maxReceives int
	// retention is the queue's MessageRetentionPeriod; zero turns the
	// expiring check off.
	retention time.Duration

	now func() time.Time
	log *slog.Logger
}

// Handle is the SQS event handler. Records are processed concurrently — each is
// an independent request to a possibly slow third party, so the batch's
// duration is its slowest record and not the sum — and the answer lists the
// records to be retried. It never returns an error: an error fails the whole
// batch, and every record's fate has already been decided on its own.
func (w *worker) Handle(ctx context.Context, ev events.SQSEvent) (events.SQSEventResponse, error) {
	var (
		mu       sync.Mutex
		failures []events.SQSBatchItemFailure
		wg       sync.WaitGroup
	)
	for _, rec := range ev.Records {
		wg.Add(1)
		go func(rec events.SQSMessage) {
			defer wg.Done()
			if !w.process(ctx, rec) {
				mu.Lock()
				failures = append(failures, events.SQSBatchItemFailure{ItemIdentifier: rec.MessageId})
				mu.Unlock()
			}
		}(rec)
	}
	wg.Wait()
	return events.SQSEventResponse{BatchItemFailures: failures}, nil
}

// queued is one decoded record.
type queued struct {
	webhook       awsintegration.QueuedWebhook
	retryDelay    time.Duration
	correlationID string
}

func decode(rec events.SQSMessage) (queued, error) {
	schema, ok := rec.MessageAttributes[awsintegration.WebhookAttrSchema]
	if !ok || schema.StringValue == nil || *schema.StringValue != strconv.Itoa(awsintegration.QueuedWebhookSchema) {
		return queued{}, errors.New("missing or unknown schema attribute")
	}
	delayAttr, ok := rec.MessageAttributes[awsintegration.WebhookAttrRetryDelayMs]
	if !ok || delayAttr.StringValue == nil {
		return queued{}, errors.New("missing retry delay attribute")
	}
	delayMs, err := strconv.ParseInt(*delayAttr.StringValue, 10, 64)
	if err != nil || delayMs < 0 {
		return queued{}, errors.New("unreadable retry delay attribute")
	}
	var q awsintegration.QueuedWebhook
	if err := json.Unmarshal([]byte(rec.Body), &q); err != nil {
		return queued{}, errors.New("unreadable body")
	}
	if q.DeliveryID == "" || q.URL == "" || q.Remaining < 0 || q.Attempt < 0 {
		return queued{}, errors.New("incomplete attempt")
	}
	out := queued{webhook: q, retryDelay: time.Duration(delayMs) * time.Millisecond}
	if c, ok := rec.MessageAttributes[awsintegration.WebhookAttrCorrelationID]; ok && c.StringValue != nil {
		out.correlationID = *c.StringValue
	}
	return out, nil
}

// process decides one record and reports whether it may be deleted.
func (w *worker) process(ctx context.Context, rec events.SQSMessage) bool {
	log := w.log.With(slog.String("messageId", rec.MessageId))
	q, err := decode(rec)
	if err != nil {
		log.Error("webhook message is not one this worker can schedule; dead-lettering it",
			slog.String("reason", reasonMalformed), slog.String("detail", err.Error()))
		return w.deadLetter(ctx, rec, reasonMalformed, 0, log)
	}
	log = log.With(
		slog.String("deliveryId", q.webhook.DeliveryID),
		slog.String("configId", q.webhook.ConfigID),
		slog.String("event", q.webhook.Event))

	lease := w.now().Add(defaultLease)
	if deadline, ok := ctx.Deadline(); ok {
		lease = deadline
	}
	claimed, err := w.ledger.ClaimWebhookDelivery(ctx, q.webhook.DeliveryID, q.webhook.ConfigID, lease)
	if err != nil {
		// The ledger is unreachable. Retry on the queue's own visibility
		// timeout; POSTing without a claim would give up the one guarantee
		// the ledger exists for.
		log.Warn("webhook delivery claim failed; the message will be retried", slog.String("error", err.Error()))
		return w.handBack(ctx, rec, queueDefault, reasonLedgerUnavailable, 0, nil, log)
	}

	switch claimed.Outcome {
	case ddbstore.WebhookClaimDelivered:
		log.Info("webhook already delivered; acknowledging a duplicate")
		return true
	case ddbstore.WebhookClaimAbandoned:
		// The budget was spent on an earlier receive; the hand-off to the DLQ
		// may not have completed, so make sure of it. A second copy in the
		// DLQ is the cheap failure; none is the expensive one.
		return w.deadLetter(ctx, rec, reasonAbandonedEarlier, 0, log)
	case ddbstore.WebhookClaimBusy:
		wait := claimed.BusyUntil.Sub(w.now())
		if wait < time.Second {
			wait = time.Second
		}
		log.Info("webhook delivery is held by another invocation; retrying after its lease",
			slog.Duration("after", wait))
		// At the ceiling this copy is dead-lettered rather than redriven
		// without a reason. The live claimant keeps its own copy; if it
		// delivers, this DLQ copy is a duplicate the ledger shows as delivered.
		return w.handBack(ctx, rec, wait, reasonBusyAtCeiling, 0, nil, log)
	case ddbstore.WebhookClaimGranted:
	default:
		log.Error("webhook delivery claim returned an unknown outcome", slog.Int("outcome", int(claimed.Outcome)))
		return false
	}

	// This claim's place in the schedule: see the file header.
	k := claimed.Claim.Claims - 1
	attemptNo := q.webhook.Attempt + k
	remaining := q.webhook.Remaining - k
	log = log.With(slog.Int("attempt", attemptNo), slog.Int("remaining", remaining))
	if remaining < 0 {
		// More claims than the message had attempts: earlier invocations
		// claimed and crashed. Every one of those may have reached the
		// receiver, so this is exhaustion, not a free retry.
		w.settle(ctx, claimed.Claim, ddbstore.WebhookDeliveryAbandoned, log)
		log.Warn("webhook attempts exhausted by earlier claims; dead-lettering", slog.String("reason", reasonExhausted))
		return w.deadLetter(ctx, rec, reasonExhausted, 0, log)
	}

	attempt := q.webhook.WebhookAttempt()
	attempt.Attempt, attempt.Remaining = attemptNo, remaining
	if q.correlationID != "" && attempt.Headers.Get(auth.CorrelationIDHeader) == "" {
		attempt.Headers.Set(auth.CorrelationIDHeader, q.correlationID)
	}

	sendErr := w.deliver.DeliverWebhook(ctx, attempt)
	if sendErr == nil {
		w.settle(ctx, claimed.Claim, ddbstore.WebhookDeliveryDelivered, log)
		log.Info("webhook delivered")
		return true
	}
	status := statusOf(sendErr)
	// Never the error text: a transport failure is a *url.Error that quotes
	// the whole receiver URL, query and capability token included.
	log = log.With(slog.Int("status", status), slog.String("failure", failureClass(sendErr)))

	if remaining == 0 {
		w.settle(ctx, claimed.Claim, ddbstore.WebhookDeliveryAbandoned, log)
		log.Warn("webhook delivery gave up after its last attempt; dead-lettering", slog.String("reason", reasonExhausted))
		return w.deadLetter(ctx, rec, reasonExhausted, status, log)
	}
	wait := backoff(q.retryDelay, attemptNo)
	log.Info("webhook delivery failed; retrying after the back-off", slog.Duration("after", wait))
	return w.handBack(ctx, rec, wait, reasonReceiveCeiling, status, &claimed.Claim, log)
}

// handBack returns a record to the queue for another receive after wait —
// settling its claim, if it holds one, as failed — unless the queue would not
// give it one: on the receive the queue would redrive next (atCeiling names
// what held it back) or when the message would expire first ("expiring"). In
// those two cases it dead-letters the record itself, with the reason, and
// settles a held claim as abandoned. It returns process's answer.
func (w *worker) handBack(ctx context.Context, rec events.SQSMessage, wait time.Duration, atCeiling string, status int, claim *ddbstore.WebhookClaim, log *slog.Logger) bool {
	reason := ""
	switch {
	case w.maxReceives > 0 && receiveCount(rec) >= w.maxReceives:
		reason = atCeiling
		log.Warn("webhook message is on the queue's last receive with its delivery unfinished; dead-lettering it rather than let the queue redrive it without a reason",
			slog.String("reason", reason), slog.Int("maxReceiveCount", w.maxReceives))
	case w.expiresFirst(rec, wait):
		reason = reasonExpiring
		log.Warn("webhook message would reach the queue's retention before its next attempt; dead-lettering it rather than let SQS drop it",
			slog.String("reason", reason), slog.Duration("retention", w.retention))
	}
	if reason != "" {
		if claim != nil {
			w.settle(ctx, *claim, ddbstore.WebhookDeliveryAbandoned, log)
		}
		return w.deadLetter(ctx, rec, reason, status, log)
	}
	if claim != nil {
		w.settle(ctx, *claim, ddbstore.WebhookDeliveryFailed, log)
	}
	if wait != queueDefault {
		w.setVisibility(ctx, rec, wait, log)
	}
	return false
}

// expiresFirst reports whether a record handed back with wait would have less
// than expiryMargin of the queue's retention left when it next becomes
// visible. The age is SQS's SentTimestamp, the original enqueue — which a
// visibility change does not reset.
func (w *worker) expiresFirst(rec events.SQSMessage, wait time.Duration) bool {
	if w.retention <= 0 {
		return false
	}
	ms, err := strconv.ParseInt(rec.Attributes["SentTimestamp"], 10, 64)
	if err != nil || ms <= 0 {
		return false
	}
	wait = min(max(wait, 0), maxVisibility)
	age := w.now().Sub(time.UnixMilli(ms))
	return age+wait+expiryMargin >= w.retention
}

// settle records a claim's outcome. A failure is logged and not acted on: the
// message's own fate is decided by the return value of process, and a claim
// that could not be settled lapses with its lease, after which the delivery is
// claimable again (at worst, one extra request on a delivered webhook whose
// settle failed — at-least-once).
func (w *worker) settle(ctx context.Context, claim ddbstore.WebhookClaim, state ddbstore.WebhookDeliveryState, log *slog.Logger) {
	if err := w.ledger.SettleWebhookDelivery(ctx, claim, state); err != nil {
		log.Warn("webhook delivery ledger was not updated", slog.String("state", string(state)), slog.String("error", err.Error()))
	}
}

// setVisibility asks SQS to hand the record back after wait. If it fails, the
// queue's own visibility timeout applies instead — later than the schedule,
// never earlier — and that is logged.
func (w *worker) setVisibility(ctx context.Context, rec events.SQSMessage, wait time.Duration, log *slog.Logger) {
	seconds := visibilitySeconds(wait)
	if _, err := w.sqs.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl:          awssdk.String(w.queueURL),
		ReceiptHandle:     awssdk.String(rec.ReceiptHandle),
		VisibilityTimeout: seconds,
	}); err != nil {
		log.Warn("could not set the webhook message's visibility; the queue's default applies",
			slog.Int("seconds", int(seconds)), slog.String("error", err.Error()))
	}
}

// deadLetter hands a copy of the record to the DLQ, body and attributes as
// received plus the reason, and reports whether that worked — which is whether
// the original may be deleted.
func (w *worker) deadLetter(ctx context.Context, rec events.SQSMessage, reason string, status int, log *slog.Logger) bool {
	attrs := make(map[string]sqstypes.MessageAttributeValue, len(rec.MessageAttributes)+2)
	for name, a := range rec.MessageAttributes {
		if a.StringValue == nil || a.DataType == "" {
			continue
		}
		attrs[name] = sqstypes.MessageAttributeValue{DataType: awssdk.String(a.DataType), StringValue: awssdk.String(*a.StringValue)}
	}
	attrs[awsintegration.WebhookAttrDeadLetterReason] = sqstypes.MessageAttributeValue{DataType: awssdk.String("String"), StringValue: awssdk.String(reason)}
	if status > 0 {
		attrs[awsintegration.WebhookAttrLastStatus] = sqstypes.MessageAttributeValue{DataType: awssdk.String("Number"), StringValue: awssdk.String(strconv.Itoa(status))}
	}
	if _, err := w.sqs.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:          awssdk.String(w.dlqURL),
		MessageBody:       awssdk.String(rec.Body),
		MessageAttributes: attrs,
	}); err != nil {
		log.Error("could not hand the webhook message to the dead-letter queue; it will be retried",
			slog.String("reason", reason), slog.String("error", err.Error()))
		return false
	}
	log.Warn("webhook message dead-lettered", slog.String("reason", reason))
	return true
}

// backoff is the reference's wait after the attempt-th failure, counting from
// zero: base × 2^attempt (webhook-sender.ts:45-46), doubling with saturation
// exactly as the core's unexported webhookBackoff does.
func backoff(base time.Duration, attempt int) time.Duration {
	if base <= 0 {
		return 0
	}
	d := base
	for i := 0; i < attempt; i++ {
		if d > maxVisibility {
			return d
		}
		d *= 2
	}
	return d
}

// visibilitySeconds rounds a wait up to SQS's whole seconds — never earlier
// than the reference — and caps it at maxVisibility.
func visibilitySeconds(wait time.Duration) int32 {
	if wait <= 0 {
		return 0
	}
	if wait > maxVisibility {
		wait = maxVisibility
	}
	return int32(math.Ceil(wait.Seconds()))
}

func receiveCount(rec events.SQSMessage) int {
	n, err := strconv.Atoi(rec.Attributes["ApproximateReceiveCount"])
	if err != nil {
		return 0
	}
	return n
}

func statusOf(err error) int {
	var se *auth.WebhookStatusError
	if errors.As(err, &se) {
		return se.StatusCode
	}
	return 0
}

// failureClass names a failure without quoting it.
func failureClass(err error) string {
	switch {
	case statusOf(err) != 0:
		return "status"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	default:
		return "transport"
	}
}

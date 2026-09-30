package aws

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	auth "github.com/nik2208/awesome-go-auth"
)

// Outgoing webhooks on SQS (D9b): the WebhookDeliverer the auth function hands
// the core, and the message format the webhook worker reads back.
//
// ── why a queue ──────────────────────────────────────────────────────────────
//
// The core's default deliverer POSTs in process, on a goroutine the emitter
// detaches from the request, with the reference's back-off between attempts.
// On Lambda the execution environment is frozen when the response is written,
// so a receiver slower than the request is delivered to late or never, and the
// one-two-four-second schedule is almost never honoured (deviation
// outgoing-webhook-delivery-races-the-response). The core's answer is the seam
// this file implements: WebhookDeliverer receives an attempt that is already
// built, signed and numbered, with no secret in it, and "a Lambda deployment
// puts the attempt on a queue with a dead-letter queue behind it and returns as
// soon as the enqueue is durable" (awesome-go-auth webhook_sender.go,
// WebhookDeliverer). SendMessage returning is that durability: SQS has stored
// the message redundantly before it answers.
//
// ── what crosses, and what does not ──────────────────────────────────────────
//
// The body is the attempt, whole: URL, the complete header set with the
// signature already computed, and the body bytes the signature covers,
// base64-encoded so that they arrive as bytes and not as a re-serialised JSON
// value. The worker re-encodes nothing — it POSTs Body with Headers — which is
// the only way a signature computed here survives the trip.
//
// The attributes carry what the worker needs to *schedule* without reading the
// webhook store: the subscription's resolved RetryDelay (the retry count is
// already in the attempt, as Remaining), and the caller's correlation id, which
// the in-process path puts on the request through the correlating transport and
// which a queued request would otherwise lose. Nothing secret is in either: the
// subscription's secret never crosses the seam, and the signature it produced
// is only as sensitive as the body it signs.
//
// The envelope is this product's, with its own JSON names and a schema number,
// rather than json.Marshal of auth.WebhookAttempt. That struct has no tags, so
// its field names would be the wire, and a core release that renamed a field
// would strand every message in flight across the upgrade — the kind of drift
// TestQueuedWebhookShapeIsPinned exists to make loud.

// SQSAPI is the slice of SQS this product calls: SendMessage for the deliverer
// and for the worker's dead-letter hand-off, ChangeMessageVisibility for the
// worker's back-off. Nothing receives or deletes: the Lambda event source does
// both on the worker's behalf.
type SQSAPI interface {
	SendMessage(ctx context.Context, in *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error)
	ChangeMessageVisibility(ctx context.Context, in *sqs.ChangeMessageVisibilityInput, optFns ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error)
}

// SQSOptions configures NewSQSClient. The zero value is what a Lambda uses.
type SQSOptions struct {
	// Region overrides AWS_REGION. The queue URL names its region too; the two
	// must agree, and in the template they always do.
	Region string
}

// NewSQSClient returns an SQSAPI whose SDK client is built on the first call,
// for the cold-start reason lazyClient gives: a deployment whose events match
// no subscription never pays for it.
func NewSQSClient(opts SQSOptions) SQSAPI {
	shared := &lazyConfig{region: opts.Region}
	return &lazySQS{client: &lazyClient[SQSAPI]{
		build: func(ctx context.Context) (SQSAPI, error) {
			cfg, err := shared.get(ctx)
			if err != nil {
				return nil, err
			}
			return sqs.NewFromConfig(cfg), nil
		},
	}}
}

type lazySQS struct{ client *lazyClient[SQSAPI] }

func (l *lazySQS) SendMessage(ctx context.Context, in *sqs.SendMessageInput, optFns ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	api, err := l.client.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqs: cannot build a client: %w", err)
	}
	return api.SendMessage(ctx, in, optFns...)
}

func (l *lazySQS) ChangeMessageVisibility(ctx context.Context, in *sqs.ChangeMessageVisibilityInput, optFns ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error) {
	api, err := l.client.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("sqs: cannot build a client: %w", err)
	}
	return api.ChangeMessageVisibility(ctx, in, optFns...)
}

// QueuedWebhookSchema is the envelope version, carried as the Schema
// attribute. A worker refuses — dead-letters — a schema it does not know rather
// than guessing at it.
const QueuedWebhookSchema = 1

// The message attribute names. The worker reads them without parsing the body
// first, and an operator reading the dead-letter queue in the console sees them
// as columns, which is why the triage fields are here as well as in the body.
const (
	WebhookAttrSchema        = "Schema"
	WebhookAttrRetryDelayMs  = "RetryDelayMs"
	WebhookAttrCorrelationID = "CorrelationId"
	WebhookAttrConfigID      = "ConfigId"
	WebhookAttrEvent         = "Event"

	// Set by the worker on the copy it hands the dead-letter queue, never by
	// the deliverer (cmd/webhook-worker/worker.go lists the reasons). A message
	// in the DLQ without a reason got there by the queue's own redrive: the
	// worker did not finish its last receive at all — it crashed or timed out
	// on it, or its own hand-off to the DLQ failed.
	WebhookAttrDeadLetterReason = "DeadLetterReason"
	WebhookAttrLastStatus       = "LastStatus"
)

// MaxQueuedWebhookBytes is the largest message the deliverer will send, body
// and attributes together as SQS counts them: SQS's classic 256 KiB, the
// ceiling every queue has whatever its configured MaximumMessageSize. Base64
// makes the payload budget about three quarters of it, roughly 190 KiB of
// envelope, which is far above anything an identity event carries and is
// stated in docs/config-reference.md all the same.
const MaxQueuedWebhookBytes = 256 * 1024

// DefaultSQSSendTimeout bounds one SendMessage when SQSWebhookDeliverer.Timeout
// is unset. The emitter's context has no deadline by design ("a fire-and-forget
// delivery must not die with the request that caused it"), so the bound is
// this type's to set; two seconds is an SQS round trip many times over and
// short enough that cmd/auth's flush, which waits for the enqueue before the
// response leaves, never holds a login for long.
const DefaultSQSSendTimeout = 2 * time.Second

// QueuedWebhook is the SQS message body: one auth.WebhookAttempt, field for
// field, with this product's JSON names.
type QueuedWebhook struct {
	ConfigID   string      `json:"configId,omitempty"`
	URL        string      `json:"url"`
	Event      string      `json:"event"`
	DeliveryID string      `json:"deliveryId"`
	Attempt    int         `json:"attempt"`
	Remaining  int         `json:"remaining"`
	Headers    http.Header `json:"headers"`
	// Body is the signed bytes, base64 on the wire (encoding/json's []byte
	// rule), so they come back identical rather than re-serialised.
	Body []byte `json:"body"`
}

// NewQueuedWebhook copies an attempt into the envelope.
func NewQueuedWebhook(a auth.WebhookAttempt) QueuedWebhook {
	return QueuedWebhook{
		ConfigID:   a.ConfigID,
		URL:        a.URL,
		Event:      a.Event,
		DeliveryID: a.DeliveryID,
		Attempt:    a.Attempt,
		Remaining:  a.Remaining,
		Headers:    a.Headers.Clone(),
		Body:       append([]byte(nil), a.Body...),
	}
}

// WebhookAttempt is the inverse of NewQueuedWebhook, for the worker, which
// sends it with the core's own HTTP deliverer so that the request is built by
// the same code the in-process path uses.
func (q QueuedWebhook) WebhookAttempt() auth.WebhookAttempt {
	return auth.WebhookAttempt{
		ConfigID:   q.ConfigID,
		URL:        q.URL,
		Event:      q.Event,
		DeliveryID: q.DeliveryID,
		Attempt:    q.Attempt,
		Remaining:  q.Remaining,
		Headers:    q.Headers.Clone(),
		Body:       append([]byte(nil), q.Body...),
	}
}

// ErrWebhookTooLargeToQueue means the envelope exceeds MaxQueuedWebhookBytes.
// It is permanent: the core retries it like any other error and every retry
// fails the same way, which is why cmd/auth's flush stops waiting at the first
// one. The error reaches the fan-out log through OnError, which is where an
// operator learns an event's payload has outgrown the queue.
var ErrWebhookTooLargeToQueue = errors.New("sqs: the webhook is larger than an SQS message can carry")

// SQSWebhookDeliverer is the auth.WebhookDeliverer that enqueues instead of
// POSTing: the durable half of at-least-once, with the worker as the other.
//
// Safe for concurrent use: it holds no state of its own, and the SDK client is.
type SQSWebhookDeliverer struct {
	// QueueURL is the webhook queue. Required.
	QueueURL string
	// Client sends. Required; NewSQSClient in production, a fake in tests.
	Client SQSAPI
	// RetryDelay returns the base back-off of the subscription the attempt
	// belongs to — WebhookConfig.RetryDelay(), resolved exactly as the core
	// resolved it for this attempt. Required: the attempt carries the retry
	// count (Remaining) and not the delay, and the worker must not re-read the
	// store to learn it. cmd/auth answers it from the snapshot it took at
	// FindByEvent; see there for why that snapshot and not a store read.
	RetryDelay func(ctx context.Context, attempt auth.WebhookAttempt) time.Duration
	// CorrelationID returns the id to carry for the worker to put back on the
	// request as X-Correlation-Id, or "" for none. Optional.
	CorrelationID func(ctx context.Context) string
	// Timeout bounds one SendMessage. Zero means DefaultSQSSendTimeout.
	Timeout time.Duration
}

var _ auth.WebhookDeliverer = (*SQSWebhookDeliverer)(nil)

// DeliverWebhook enqueues the attempt. nil means SQS stored the message; any
// error means it did not, and the core's own back-off retries the enqueue.
//
// That retry spends the subscription's budget. The core numbers attempts
// without knowing what a deliverer does with them, so an enqueue that failed
// once is followed by attempt 1 with Remaining one lower, and the worker then
// has one retry fewer to give the receiver than the reference would have. It
// is the core's contract ("the back-off implemented here covers only failures
// to hand the attempt over") and the budget is honoured as numbered; an SQS
// SendMessage that fails is rare enough that the lost retry is noted here and
// not engineered around.
//
// The error never quotes the URL, the headers or the body: it reaches the
// structured log through the facade's OnError, and a receiver URL is where a
// Slack- or Zapier-style endpoint keeps its capability token.
func (d *SQSWebhookDeliverer) DeliverWebhook(ctx context.Context, attempt auth.WebhookAttempt) error {
	if d == nil || d.Client == nil || d.QueueURL == "" || d.RetryDelay == nil {
		return errors.New("sqs: the webhook deliverer is not configured")
	}
	body, err := json.Marshal(NewQueuedWebhook(attempt))
	if err != nil {
		return fmt.Errorf("sqs: encode webhook %s: %w", attempt.Event, err)
	}
	correlation := ""
	if d.CorrelationID != nil {
		correlation = d.CorrelationID(ctx)
	}
	attrs := QueuedWebhookAttributes(attempt, d.RetryDelay(ctx, attempt), correlation)
	// SQS counts the attributes toward the limit with the body — each one's
	// name, type and value — so an envelope just under the bound with its
	// attributes over it would otherwise fail as SQS's InvalidParameterValue,
	// retried like a network error, instead of as this.
	if size := len(body) + MessageAttributesSize(attrs); size > MaxQueuedWebhookBytes {
		return fmt.Errorf("%w: %s is %d bytes encoded with its attributes, the limit is %d", ErrWebhookTooLargeToQueue, attempt.Event, size, MaxQueuedWebhookBytes)
	}
	input := &sqs.SendMessageInput{
		QueueUrl:          awssdk.String(d.QueueURL),
		MessageBody:       awssdk.String(string(body)),
		MessageAttributes: attrs,
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = DefaultSQSSendTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if _, err := d.Client.SendMessage(ctx, input); err != nil {
		return fmt.Errorf("sqs: enqueue webhook %s for %s: %w", attempt.Event, attempt.ConfigID, err)
	}
	return nil
}

// QueuedWebhookAttributes are the message attributes one attempt is enqueued
// with. Exported so the shape test and the worker's tests build the same map
// the deliverer sends.
//
// RetryDelayMs is whole milliseconds, the unit the reference stores
// (retryDelayMs); a negative delay — which WebhookConfig.RetryDelay can return
// for a hand-written row — is written as 0, which is what the core's own
// back-off does with it.
func QueuedWebhookAttributes(a auth.WebhookAttempt, retryDelay time.Duration, correlationID string) map[string]sqstypes.MessageAttributeValue {
	delayMs := retryDelay.Milliseconds()
	if delayMs < 0 {
		delayMs = 0
	}
	attrs := map[string]sqstypes.MessageAttributeValue{
		WebhookAttrSchema:       numberAttr(QueuedWebhookSchema),
		WebhookAttrRetryDelayMs: numberAttr(delayMs),
	}
	// SQS refuses an attribute with an empty value, so the optional ones are
	// absent rather than blank.
	if a.Event != "" {
		attrs[WebhookAttrEvent] = stringAttr(a.Event)
	}
	if a.ConfigID != "" {
		attrs[WebhookAttrConfigID] = stringAttr(a.ConfigID)
	}
	if correlationID != "" {
		attrs[WebhookAttrCorrelationID] = stringAttr(correlationID)
	}
	return attrs
}

// MessageAttributesSize is what SQS counts of a message's attributes toward
// its size limit: every name, data type and value, in bytes.
func MessageAttributesSize(attrs map[string]sqstypes.MessageAttributeValue) int {
	n := 0
	for name, a := range attrs {
		n += len(name) + len(awssdk.ToString(a.DataType)) + len(awssdk.ToString(a.StringValue)) + len(a.BinaryValue)
	}
	return n
}

func numberAttr(n int64) sqstypes.MessageAttributeValue {
	return sqstypes.MessageAttributeValue{DataType: awssdk.String("Number"), StringValue: awssdk.String(strconv.FormatInt(n, 10))}
}

func stringAttr(s string) sqstypes.MessageAttributeValue {
	return sqstypes.MessageAttributeValue{DataType: awssdk.String("String"), StringValue: awssdk.String(s)}
}

package aws

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"

	auth "github.com/nik2208/awesome-go-auth"
)

// fakeSQS records every call and answers with whatever err holds.
type fakeSQS struct {
	mu          sync.Mutex
	sent        []*sqs.SendMessageInput
	visibility  []*sqs.ChangeMessageVisibilityInput
	hadDeadline bool
	err         error
}

func (f *fakeSQS) SendMessage(ctx context.Context, in *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, f.hadDeadline = ctx.Deadline()
	f.sent = append(f.sent, in)
	if f.err != nil {
		return nil, f.err
	}
	return &sqs.SendMessageOutput{MessageId: awssdk.String("m-1")}, nil
}

func (f *fakeSQS) ChangeMessageVisibility(_ context.Context, in *sqs.ChangeMessageVisibilityInput, _ ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visibility = append(f.visibility, in)
	return &sqs.ChangeMessageVisibilityOutput{}, f.err
}

// pinnedAttempt is a fully built attempt of the shape the core's sender makes:
// five headers, the signature computed over the body.
func pinnedAttempt() auth.WebhookAttempt {
	h := make(http.Header)
	h.Set("Content-Type", "application/json")
	h.Set("X-Webhook-Event", "identity.auth.login.success")
	h.Set("X-Webhook-Delivery", "0b6f3f9e-8f5a-4c1e-9d2b-6a7c8e9f0a1b")
	h.Set("X-Webhook-Timestamp", "2026-09-30T12:00:00.000Z")
	h.Set("X-Webhook-Signature", "sha256=00ff")
	return auth.WebhookAttempt{
		ConfigID:   "whk_1",
		URL:        "https://receiver.example.test/hook?token=capability",
		Event:      "identity.auth.login.success",
		DeliveryID: "0b6f3f9e-8f5a-4c1e-9d2b-6a7c8e9f0a1b",
		Attempt:    0,
		Remaining:  3,
		Headers:    h,
		Body:       []byte(`{"a":1}`),
	}
}

func deliverer(f *fakeSQS) *SQSWebhookDeliverer {
	return &SQSWebhookDeliverer{
		QueueURL:      "https://sqs.eu-west-1.amazonaws.example.test/queue",
		Client:        f,
		RetryDelay:    func(context.Context, auth.WebhookAttempt) time.Duration { return 1500 * time.Millisecond },
		CorrelationID: func(context.Context) string { return "corr-1" },
	}
}

// TestQueuedWebhookShapeIsPinned pins the message byte for byte: the worker
// reads these names and nothing else, so a drift here is a queue full of
// messages the next worker cannot schedule — silently, until the dead-letter
// alarm.
func TestQueuedWebhookShapeIsPinned(t *testing.T) {
	t.Parallel()
	f := &fakeSQS{}
	if err := deliverer(f).DeliverWebhook(context.Background(), pinnedAttempt()); err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(f.sent) != 1 {
		t.Fatalf("sent %d messages, want 1", len(f.sent))
	}
	in := f.sent[0]
	if got := awssdk.ToString(in.QueueUrl); got != "https://sqs.eu-west-1.amazonaws.example.test/queue" {
		t.Errorf("QueueUrl = %q", got)
	}
	const wantBody = `{"configId":"whk_1","url":"https://receiver.example.test/hook?token=capability",` +
		`"event":"identity.auth.login.success","deliveryId":"0b6f3f9e-8f5a-4c1e-9d2b-6a7c8e9f0a1b",` +
		`"attempt":0,"remaining":3,"headers":{"Content-Type":["application/json"],` +
		`"X-Webhook-Delivery":["0b6f3f9e-8f5a-4c1e-9d2b-6a7c8e9f0a1b"],"X-Webhook-Event":["identity.auth.login.success"],` +
		`"X-Webhook-Signature":["sha256=00ff"],"X-Webhook-Timestamp":["2026-09-30T12:00:00.000Z"]},"body":"eyJhIjoxfQ=="}`
	if got := awssdk.ToString(in.MessageBody); got != wantBody {
		t.Errorf("body drifted:\n got %s\nwant %s", got, wantBody)
	}
	want := map[string][2]string{
		"Schema":        {"Number", "1"},
		"RetryDelayMs":  {"Number", "1500"},
		"Event":         {"String", "identity.auth.login.success"},
		"ConfigId":      {"String", "whk_1"},
		"CorrelationId": {"String", "corr-1"},
	}
	if len(in.MessageAttributes) != len(want) {
		t.Errorf("attributes = %v, want exactly %v", keysOf(in.MessageAttributes), want)
	}
	for name, w := range want {
		got, ok := in.MessageAttributes[name]
		if !ok {
			t.Errorf("attribute %s missing", name)
			continue
		}
		if awssdk.ToString(got.DataType) != w[0] || awssdk.ToString(got.StringValue) != w[1] {
			t.Errorf("attribute %s = %s/%s, want %s/%s", name, awssdk.ToString(got.DataType), awssdk.ToString(got.StringValue), w[0], w[1])
		}
	}
	if !f.hadDeadline {
		t.Error("SendMessage ran with no deadline; the emitter's context has none, so the deliverer must set one")
	}
}

func keysOf(m map[string]sqstypes.MessageAttributeValue) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestQueuedWebhookRoundTripsTheSignedBytes: what the worker decodes is the
// attempt the core built, header for header and byte for byte — including a
// body with the characters encoding/json would escape if it were re-encoded
// rather than carried.
func TestQueuedWebhookRoundTripsTheSignedBytes(t *testing.T) {
	t.Parallel()
	a := pinnedAttempt()
	a.Body = []byte("{\"html\":\"<b>&amp;</b>\",\"u\":\" \"}\n")
	raw, err := json.Marshal(NewQueuedWebhook(a))
	if err != nil {
		t.Fatal(err)
	}
	var q QueuedWebhook
	if err := json.Unmarshal(raw, &q); err != nil {
		t.Fatal(err)
	}
	back := q.WebhookAttempt()
	if string(back.Body) != string(a.Body) {
		t.Errorf("body changed across the queue:\n got %q\nwant %q", back.Body, a.Body)
	}
	for name, values := range a.Headers {
		if strings.Join(back.Headers[name], ",") != strings.Join(values, ",") {
			t.Errorf("header %s changed: %v -> %v", name, values, back.Headers[name])
		}
	}
	if len(back.Headers) != len(a.Headers) {
		t.Errorf("header set changed: %v -> %v", a.Headers, back.Headers)
	}
	if back.URL != a.URL || back.DeliveryID != a.DeliveryID || back.Attempt != a.Attempt ||
		back.Remaining != a.Remaining || back.ConfigID != a.ConfigID || back.Event != a.Event {
		t.Errorf("attempt changed: %+v -> %+v", a, back)
	}
}

func TestQueuedWebhookOmitsEmptyOptionalAttributes(t *testing.T) {
	t.Parallel()
	a := pinnedAttempt()
	a.ConfigID = ""
	attrs := QueuedWebhookAttributes(a, -time.Second, "")
	for _, name := range []string{WebhookAttrConfigID, WebhookAttrCorrelationID} {
		if _, ok := attrs[name]; ok {
			t.Errorf("%s written empty; SQS refuses an empty attribute", name)
		}
	}
	if got := awssdk.ToString(attrs[WebhookAttrRetryDelayMs].StringValue); got != "0" {
		t.Errorf("a negative delay was written as %s, want 0", got)
	}
}

// TestSQSDelivererErrorsNeverQuoteTheReceiver: the error reaches the fan-out
// log, and the URL's query is where a capability token lives.
func TestSQSDelivererErrorsNeverQuoteTheReceiver(t *testing.T) {
	t.Parallel()
	f := &fakeSQS{err: errors.New("throttled")}
	err := deliverer(f).DeliverWebhook(context.Background(), pinnedAttempt())
	if err == nil {
		t.Fatal("a failed enqueue returned nil; the core would believe the delivery durable")
	}
	for _, leak := range []string{"receiver.example.test", "capability", "sha256=00ff"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("error %q quotes %q", err, leak)
		}
	}

	big := pinnedAttempt()
	big.Body = []byte(strings.Repeat("x", MaxQueuedWebhookBytes))
	if err := deliverer(&fakeSQS{}).DeliverWebhook(context.Background(), big); !errors.Is(err, ErrWebhookTooLargeToQueue) {
		t.Errorf("oversized envelope: %v, want ErrWebhookTooLargeToQueue", err)
	}

	var unset *SQSWebhookDeliverer
	if err := unset.DeliverWebhook(context.Background(), pinnedAttempt()); err == nil {
		t.Error("an unconfigured deliverer reported success")
	}
}

// TestQueuedWebhookSizeCountsTheAttributes: SQS counts the attributes toward
// the 256 KiB limit with the body, so an envelope that fits alone and not with
// its attributes is refused here, as ErrWebhookTooLargeToQueue, and never
// reaches SQS to come back as an InvalidParameterValue retried like an outage.
func TestQueuedWebhookSizeCountsTheAttributes(t *testing.T) {
	t.Parallel()
	a := pinnedAttempt()
	attrs := MessageAttributesSize(QueuedWebhookAttributes(a, 1500*time.Millisecond, "corr-1"))
	if attrs < 40 {
		t.Fatalf("the attributes count %d bytes, which is less than their names alone", attrs)
	}
	encoded := func(n int) int {
		a.Body = []byte(strings.Repeat("x", n))
		b, err := json.Marshal(NewQueuedWebhook(a))
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	// The largest body whose envelope alone fits.
	n := MaxQueuedWebhookBytes * 3 / 4
	for encoded(n) > MaxQueuedWebhookBytes {
		n--
	}
	if encoded(n)+attrs <= MaxQueuedWebhookBytes {
		t.Fatalf("no envelope in the gap: %d + %d fits", encoded(n), attrs)
	}
	f := &fakeSQS{}
	if err := deliverer(f).DeliverWebhook(context.Background(), a); !errors.Is(err, ErrWebhookTooLargeToQueue) {
		t.Errorf("an envelope of %d bytes with %d of attributes: %v, want ErrWebhookTooLargeToQueue", encoded(n), attrs, err)
	}
	if len(f.sent) != 0 {
		t.Error("the oversized message reached SQS")
	}
}

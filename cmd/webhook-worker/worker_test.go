package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeSQS struct {
	mu         sync.Mutex
	sent       []*sqs.SendMessageInput
	visibility []*sqs.ChangeMessageVisibilityInput
}

func (f *fakeSQS) SendMessage(_ context.Context, in *sqs.SendMessageInput, _ ...func(*sqs.Options)) (*sqs.SendMessageOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, in)
	return &sqs.SendMessageOutput{MessageId: awssdk.String("m")}, nil
}

func (f *fakeSQS) ChangeMessageVisibility(_ context.Context, in *sqs.ChangeMessageVisibilityInput, _ ...func(*sqs.Options)) (*sqs.ChangeMessageVisibilityOutput, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.visibility = append(f.visibility, in)
	return &sqs.ChangeMessageVisibilityOutput{}, nil
}

func (f *fakeSQS) lastVisibility(t *testing.T) int32 {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.visibility) == 0 {
		t.Fatal("no visibility change was made")
	}
	return f.visibility[len(f.visibility)-1].VisibilityTimeout
}

// memLedger is the ledger's state machine in memory, for the branch tests; the
// race is asserted against the real store on DynamoDB Local below.
type memLedger struct {
	mu    sync.Mutex
	items map[string]*memItem
}

type memItem struct {
	state  ddbstore.WebhookDeliveryState
	claims int
	owner  string
	lease  time.Time
}

func newMemLedger() *memLedger { return &memLedger{items: map[string]*memItem{}} }

func (m *memLedger) ClaimWebhookDelivery(_ context.Context, id, _ string, lease time.Time) (ddbstore.WebhookClaimResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	it, ok := m.items[id]
	if !ok {
		it = &memItem{}
		m.items[id] = it
	}
	switch {
	case ok && it.state == ddbstore.WebhookDeliveryDelivered:
		return ddbstore.WebhookClaimResult{Outcome: ddbstore.WebhookClaimDelivered}, nil
	case ok && it.state == ddbstore.WebhookDeliveryAbandoned:
		return ddbstore.WebhookClaimResult{Outcome: ddbstore.WebhookClaimAbandoned}, nil
	case ok && it.state == ddbstore.WebhookDeliveryClaimed && it.lease.After(time.Now()):
		return ddbstore.WebhookClaimResult{Outcome: ddbstore.WebhookClaimBusy, BusyUntil: it.lease}, nil
	}
	it.claims++
	it.state, it.lease, it.owner = ddbstore.WebhookDeliveryClaimed, lease, strconv.Itoa(it.claims)
	return ddbstore.WebhookClaimResult{Outcome: ddbstore.WebhookClaimGranted,
		Claim: ddbstore.WebhookClaim{DeliveryID: id, Owner: it.owner, Claims: it.claims}}, nil
}

func (m *memLedger) SettleWebhookDelivery(_ context.Context, c ddbstore.WebhookClaim, s ddbstore.WebhookDeliveryState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	it := m.items[c.DeliveryID]
	if it == nil || it.state != ddbstore.WebhookDeliveryClaimed || it.owner != c.Owner {
		return ddbstore.ErrWebhookClaimLost
	}
	it.state, it.owner, it.lease = s, "", time.Time{}
	return nil
}

// receiver records every request and answers from a script of statuses, the
// last one repeating.
type receiver struct {
	srv      *httptest.Server
	mu       sync.Mutex
	requests []recorded
	statuses []int
	delay    time.Duration
	hits     atomic.Int32
}

type recorded struct {
	header http.Header
	body   []byte
}

func newReceiver(t *testing.T, statuses ...int) *receiver {
	t.Helper()
	r := &receiver{statuses: statuses}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		n := int(r.hits.Add(1))
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.requests = append(r.requests, recorded{header: req.Header.Clone(), body: body})
		status := http.StatusOK
		if len(r.statuses) > 0 {
			status = r.statuses[min(n, len(r.statuses))-1]
		}
		delay := r.delay
		r.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// url carries a query, because the query is where a capability token lives and
// the tests assert it never reaches the log.
func (r *receiver) url() string { return r.srv.URL + "/hook?token=capability-secret" }

// ── helpers ──────────────────────────────────────────────────────────────────

const testSecret = "whsec_test"

// coreAttempts builds the attempt the core would hand a deliverer, by running
// the core's own sender against a deliverer that enqueues on a fake SQS — the
// production path, up to the queue.
func coreAttempts(t *testing.T, url string, retries, delayMs int) (auth.WebhookAttempt, *sqs.SendMessageInput) {
	t.Helper()
	q := &fakeSQS{}
	var captured auth.WebhookAttempt
	enqueue := &awsintegration.SQSWebhookDeliverer{
		QueueURL: "https://sqs.example.test/queue",
		Client:   q,
		RetryDelay: func(context.Context, auth.WebhookAttempt) time.Duration {
			return time.Duration(delayMs) * time.Millisecond
		},
		CorrelationID: func(context.Context) string { return "corr-42" },
	}
	sender := &auth.WebhookSender{Deliverer: auth.WebhookDelivererFunc(func(ctx context.Context, a auth.WebhookAttempt) error {
		captured = a
		return enqueue.DeliverWebhook(ctx, a)
	})}
	config := auth.WebhookConfig{ID: "whk_" + randomHex(4), URL: url, Secret: testSecret, MaxRetries: &retries, RetryDelayMs: &delayMs}
	ev := auth.Event{Name: "identity.auth.login.success", UserID: "u1", Data: map[string]any{"html": "<b>&</b>"}}
	if err := sender.Send(context.Background(), config, ev.OutgoingWebhook("")); err != nil {
		t.Fatalf("core send: %v", err)
	}
	if len(q.sent) != 1 {
		t.Fatalf("the core enqueued %d messages, want 1", len(q.sent))
	}
	return captured, q.sent[0]
}

// record turns an enqueued message into what the event source delivers.
func record(in *sqs.SendMessageInput, messageID string, receives int) events.SQSMessage {
	attrs := map[string]events.SQSMessageAttribute{}
	for name, a := range in.MessageAttributes {
		attrs[name] = events.SQSMessageAttribute{DataType: awssdk.ToString(a.DataType), StringValue: a.StringValue}
	}
	return events.SQSMessage{
		MessageId:         messageID,
		ReceiptHandle:     "rh-" + messageID + "-" + strconv.Itoa(receives),
		Body:              awssdk.ToString(in.MessageBody),
		Attributes:        map[string]string{"ApproximateReceiveCount": strconv.Itoa(receives)},
		MessageAttributes: attrs,
	}
}

func newTestWorker(q *fakeSQS, l ledger, timeout time.Duration, logs io.Writer) *worker {
	if logs == nil {
		logs = io.Discard
	}
	return &worker{
		sqs:         q,
		ledger:      l,
		deliver:     &auth.HTTPWebhookDeliverer{Client: &http.Client{}, Timeout: timeout},
		queueURL:    "https://sqs.example.test/queue",
		dlqURL:      "https://sqs.example.test/dlq",
		maxReceives: 10,
		now:         time.Now,
		log:         slog.New(slog.NewJSONHandler(logs, nil)),
	}
}

func handle(t *testing.T, w *worker, recs ...events.SQSMessage) events.SQSEventResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := w.Handle(ctx, events.SQSEvent{Records: recs})
	if err != nil {
		t.Fatalf("Handle returned an error, which fails the whole batch: %v", err)
	}
	return resp
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ── the tests ────────────────────────────────────────────────────────────────

// TestWorkerSendsTheBytesTheCoreSigned is the property everything else depends
// on: a receiver verifying X-Webhook-Signature against the raw body must see
// the core's body, byte for byte, and the core's headers, value for value. The
// only header the worker adds is X-Correlation-Id, which the in-process path's
// transport adds as well.
func TestWorkerSendsTheBytesTheCoreSigned(t *testing.T) {
	t.Parallel()
	rcv := newReceiver(t, http.StatusOK)
	built, msg := coreAttempts(t, rcv.url(), 3, 1000)

	resp := handle(t, newTestWorker(&fakeSQS{}, newMemLedger(), time.Second, nil), record(msg, "m1", 1))
	if len(resp.BatchItemFailures) != 0 {
		t.Fatalf("a 2xx was reported as a failure: %+v", resp)
	}
	if len(rcv.requests) != 1 {
		t.Fatalf("receiver saw %d requests, want 1", len(rcv.requests))
	}
	got := rcv.requests[0]
	if !bytes.Equal(got.body, built.Body) {
		t.Errorf("body changed between the core and the receiver:\n got %q\nwant %q", got.body, built.Body)
	}
	for name, values := range built.Headers {
		if strings.Join(got.header.Values(name), "\x00") != strings.Join(values, "\x00") {
			t.Errorf("header %s = %q, the core built %q", name, got.header.Values(name), values)
		}
	}
	if got.header.Get(auth.CorrelationIDHeader) != "corr-42" {
		t.Errorf("X-Correlation-Id = %q, want the caller's id carried across the queue", got.header.Get(auth.CorrelationIDHeader))
	}
	if err := auth.VerifyWebhookSignature(testSecret, got.body, got.header.Get("X-Webhook-Signature")); err != nil {
		t.Errorf("the receiver cannot verify the signature: %v", err)
	}
}

// TestWorkerReproducesTheReferenceSchedule: with the defaults (three retries,
// one second), a receiver answering 500 is tried four times, the waits between
// them are 1, 2 and 4 seconds, every try carries the delivery id the core
// minted, and the fourth refusal goes to the DLQ with its reason and status.
func TestWorkerReproducesTheReferenceSchedule(t *testing.T) {
	t.Parallel()
	rcv := newReceiver(t, http.StatusInternalServerError)
	built, msg := coreAttempts(t, rcv.url(), 3, 1000)
	q := &fakeSQS{}
	w := newTestWorker(q, newMemLedger(), time.Second, nil)

	for receive, wantWait := range []int32{1, 2, 4} {
		resp := handle(t, w, record(msg, "m1", receive+1))
		if len(resp.BatchItemFailures) != 1 || resp.BatchItemFailures[0].ItemIdentifier != "m1" {
			t.Fatalf("receive %d: %+v, want m1 reported for retry", receive+1, resp)
		}
		if got := q.lastVisibility(t); got != wantWait {
			t.Errorf("receive %d: visibility %d s, want %d s (RetryDelay x 2^attempt)", receive+1, got, wantWait)
		}
	}
	resp := handle(t, w, record(msg, "m1", 4))
	if len(resp.BatchItemFailures) != 0 {
		t.Fatalf("the exhausted delivery was not acknowledged after dead-lettering: %+v", resp)
	}
	if len(q.sent) != 1 {
		t.Fatalf("%d messages sent to the DLQ, want 1", len(q.sent))
	}
	dl := q.sent[0]
	if awssdk.ToString(dl.QueueUrl) != "https://sqs.example.test/dlq" || awssdk.ToString(dl.MessageBody) != awssdk.ToString(msg.MessageBody) {
		t.Errorf("the DLQ copy is not the original message on the DLQ")
	}
	if r := awssdk.ToString(dl.MessageAttributes[awsintegration.WebhookAttrDeadLetterReason].StringValue); r != reasonExhausted {
		t.Errorf("DeadLetterReason = %q, want %q", r, reasonExhausted)
	}
	if s := awssdk.ToString(dl.MessageAttributes[awsintegration.WebhookAttrLastStatus].StringValue); s != "500" {
		t.Errorf("LastStatus = %q, want 500", s)
	}
	if len(rcv.requests) != 4 {
		t.Fatalf("receiver saw %d requests, want 4 (retries+1)", len(rcv.requests))
	}
	for i, r := range rcv.requests {
		if r.header.Get("X-Webhook-Delivery") != built.DeliveryID {
			t.Errorf("request %d carried delivery id %q, want the core's %q (resent, never re-minted)", i, r.header.Get("X-Webhook-Delivery"), built.DeliveryID)
		}
	}
	// And a fifth receive — an SQS duplicate of the dead-lettered message —
	// makes no request, and hands a second copy to the DLQ under a reason that
	// does not claim to know the first one's.
	handle(t, w, record(msg, "m1", 5))
	if len(rcv.requests) != 4 {
		t.Errorf("an abandoned delivery was POSTed again")
	}
	if len(q.sent) != 2 {
		t.Fatalf("%d DLQ sends after the duplicate, want 2", len(q.sent))
	}
	if r := awssdk.ToString(q.sent[1].MessageAttributes[awsintegration.WebhookAttrDeadLetterReason].StringValue); r != reasonAbandonedEarlier {
		t.Errorf("the duplicate's DeadLetterReason = %q, want %q", r, reasonAbandonedEarlier)
	}
}

// unreachableLedger is the ledger during a DynamoDB outage.
type unreachableLedger struct{}

func (unreachableLedger) ClaimWebhookDelivery(context.Context, string, string, time.Time) (ddbstore.WebhookClaimResult, error) {
	return ddbstore.WebhookClaimResult{}, errors.New("throttled")
}

func (unreachableLedger) SettleWebhookDelivery(context.Context, ddbstore.WebhookClaim, ddbstore.WebhookDeliveryState) error {
	return errors.New("throttled")
}

// TestWorkerNeverLetsTheQueueRedriveWithoutAReason: every path that hands a
// record back to the queue — not only a refused POST — checks the receive
// ceiling, so a message the worker handled on its last receive reaches the DLQ
// with the reason that held it back, and never as SQS's reasonless redrive.
func TestWorkerNeverLetsTheQueueRedriveWithoutAReason(t *testing.T) {
	t.Parallel()
	rcv := newReceiver(t, http.StatusOK)
	built, msg := coreAttempts(t, rcv.url(), 3, 1000)

	for name, tc := range map[string]struct {
		ledger func() ledger
		want   string
	}{
		"the ledger is unreachable": {func() ledger { return unreachableLedger{} }, reasonLedgerUnavailable},
		"a live claim holds the delivery": {func() ledger {
			l := newMemLedger()
			_, _ = l.ClaimWebhookDelivery(context.Background(), built.DeliveryID, "", time.Now().Add(20*time.Second))
			return l
		}, reasonBusyAtCeiling},
	} {
		// Below the ceiling: handed back, nothing dead-lettered.
		q := &fakeSQS{}
		w := newTestWorker(q, tc.ledger(), time.Second, nil)
		if resp := handle(t, w, record(msg, "m1", w.maxReceives-1)); len(resp.BatchItemFailures) != 1 || len(q.sent) != 0 {
			t.Errorf("%s, below the ceiling: failures %v and %d DLQ sends, want handed back and none", name, resp.BatchItemFailures, len(q.sent))
		}
		// On the last receive: dead-lettered with its reason, acknowledged.
		q = &fakeSQS{}
		w = newTestWorker(q, tc.ledger(), time.Second, nil)
		resp := handle(t, w, record(msg, "m1", w.maxReceives))
		if len(resp.BatchItemFailures) != 0 || len(q.sent) != 1 {
			t.Errorf("%s, on the last receive: failures %v and %d DLQ sends, want one hand-off and an acknowledgement", name, resp.BatchItemFailures, len(q.sent))
			continue
		}
		if r := awssdk.ToString(q.sent[0].MessageAttributes[awsintegration.WebhookAttrDeadLetterReason].StringValue); r != tc.want {
			t.Errorf("%s: DeadLetterReason %q, want %q", name, r, tc.want)
		}
	}
	if rcv.hits.Load() != 0 {
		t.Errorf("a record that could not be claimed made %d requests", rcv.hits.Load())
	}
}

// TestWorkerDeadLettersAMessageAboutToExpire: SQS deletes a message at its
// retention without redriving it, so a failing delivery whose next attempt
// would come too close to that is dead-lettered as "expiring" — with a fresh
// fourteen days and the alarm — while a young one is simply retried.
func TestWorkerDeadLettersAMessageAboutToExpire(t *testing.T) {
	t.Parallel()
	rcv := newReceiver(t, http.StatusServiceUnavailable)
	const retention = 14 * 24 * time.Hour

	for name, tc := range map[string]struct {
		age      time.Duration
		expiring bool
	}{
		"young":                         {time.Minute, false},
		"a day from expiry":             {retention - 25*time.Hour, false},
		"inside the margin after a wait": {retention - expiryMargin, true},
	} {
		_, msg := coreAttempts(t, rcv.url(), 3, 1000)
		q := &fakeSQS{}
		l := newMemLedger()
		w := newTestWorker(q, l, time.Second, nil)
		w.retention = retention
		rec := record(msg, "m1", 1)
		rec.Attributes["SentTimestamp"] = strconv.FormatInt(time.Now().Add(-tc.age).UnixMilli(), 10)

		resp := handle(t, w, rec)
		if !tc.expiring {
			if len(resp.BatchItemFailures) != 1 || len(q.sent) != 0 {
				t.Errorf("%s: failures %v, %d DLQ sends; want a plain retry", name, resp.BatchItemFailures, len(q.sent))
			}
			continue
		}
		if len(resp.BatchItemFailures) != 0 || len(q.sent) != 1 {
			t.Errorf("%s: failures %v, %d DLQ sends; want dead-lettered and acknowledged", name, resp.BatchItemFailures, len(q.sent))
			continue
		}
		if r := awssdk.ToString(q.sent[0].MessageAttributes[awsintegration.WebhookAttrDeadLetterReason].StringValue); r != reasonExpiring {
			t.Errorf("%s: DeadLetterReason %q, want %q", name, r, reasonExpiring)
		}
		if s := awssdk.ToString(q.sent[0].MessageAttributes[awsintegration.WebhookAttrLastStatus].StringValue); s != "503" {
			t.Errorf("%s: LastStatus %q, want 503", name, s)
		}
		var id string
		for k := range l.items {
			id = k
		}
		if st := l.items[id].state; st != ddbstore.WebhookDeliveryAbandoned {
			t.Errorf("%s: ledger state %q, want abandoned so a duplicate does not retry it", name, st)
		}
	}
}

// TestWorkerTimeoutIsARetryAndTheLogNeverQuotesTheReceiver: a receiver slower
// than the deliverer's timeout is a failure like a 500, and the log line about
// it says "timeout" without the transport error's text — which quotes the
// whole URL, capability token included.
func TestWorkerTimeoutIsARetryAndTheLogNeverQuotesTheReceiver(t *testing.T) {
	t.Parallel()
	rcv := newReceiver(t, http.StatusOK)
	rcv.delay = 500 * time.Millisecond
	_, msg := coreAttempts(t, rcv.url(), 3, 1000)
	var logs bytes.Buffer
	var mu sync.Mutex
	q := &fakeSQS{}
	w := newTestWorker(q, newMemLedger(), 50*time.Millisecond, &lockedWriter{w: &logs, mu: &mu})

	resp := handle(t, w, record(msg, "m1", 1))
	if len(resp.BatchItemFailures) != 1 {
		t.Fatalf("a timed-out delivery was acknowledged: %+v", resp)
	}
	if got := q.lastVisibility(t); got != 1 {
		t.Errorf("visibility after a timeout = %d, want 1", got)
	}
	mu.Lock()
	out := logs.String()
	mu.Unlock()
	if !strings.Contains(out, `"failure":"timeout"`) {
		t.Errorf("the log does not classify the timeout:\n%s", out)
	}
	for _, leak := range []string{"capability-secret", "/hook", rcv.srv.URL, "sha256="} {
		if strings.Contains(out, leak) {
			t.Errorf("the log quotes %q:\n%s", leak, out)
		}
	}
}

type lockedWriter struct {
	w  io.Writer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

func TestBackoffAndVisibilityArithmetic(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		base    time.Duration
		attempt int
		want    int32
	}{
		{time.Second, 0, 1},
		{time.Second, 1, 2},
		{time.Second, 2, 4},
		{time.Second, 3, 8},
		{1500 * time.Millisecond, 0, 2}, // rounded up: never earlier than the reference
		{250 * time.Millisecond, 0, 1},
		{0, 5, 0}, // retryDelayMs 0: retry at once, as the core does
		{time.Hour, 20, int32(maxVisibility / time.Second)},
		{time.Second, 1 << 20, int32(maxVisibility / time.Second)}, // saturates, never wraps
	} {
		if got := visibilitySeconds(backoff(tc.base, tc.attempt)); got != tc.want {
			t.Errorf("base %s attempt %d: %d s, want %d s", tc.base, tc.attempt, got, tc.want)
		}
	}
}

func TestWorkerDeadLettersWhatItCannotSchedule(t *testing.T) {
	t.Parallel()
	_, msg := coreAttempts(t, "https://receiver.example.test/hook", 3, 1000)
	for name, mutate := range map[string]func(*events.SQSMessage){
		"no schema": func(r *events.SQSMessage) { delete(r.MessageAttributes, awsintegration.WebhookAttrSchema) },
		"future schema": func(r *events.SQSMessage) {
			v := "2"
			r.MessageAttributes[awsintegration.WebhookAttrSchema] = events.SQSMessageAttribute{DataType: "Number", StringValue: &v}
		},
		"no delay": func(r *events.SQSMessage) { delete(r.MessageAttributes, awsintegration.WebhookAttrRetryDelayMs) },
		"bad body": func(r *events.SQSMessage) { r.Body = "{" },
	} {
		q := &fakeSQS{}
		rec := record(msg, "m1", 1)
		mutate(&rec)
		resp := handle(t, newTestWorker(q, newMemLedger(), time.Second, nil), rec)
		if len(resp.BatchItemFailures) != 0 || len(q.sent) != 1 {
			t.Errorf("%s: failures %v, %d DLQ sends; want acknowledged after one DLQ send", name, resp.BatchItemFailures, len(q.sent))
			continue
		}
		if r := awssdk.ToString(q.sent[0].MessageAttributes[awsintegration.WebhookAttrDeadLetterReason].StringValue); r != reasonMalformed {
			t.Errorf("%s: reason %q", name, r)
		}
	}
}

// TestWorkerDeadLettersAtTheReceiveCeiling: a subscription that wants more
// attempts than the queue's maxReceiveCount allows is dead-lettered by the
// worker, with a reason, on the receive the queue would otherwise redrive
// silently.
func TestWorkerDeadLettersAtTheReceiveCeiling(t *testing.T) {
	t.Parallel()
	rcv := newReceiver(t, http.StatusBadGateway)
	_, msg := coreAttempts(t, rcv.url(), 8, 1000)
	q := &fakeSQS{}
	w := newTestWorker(q, newMemLedger(), time.Second, nil)
	w.maxReceives = 2

	if resp := handle(t, w, record(msg, "m1", 1)); len(resp.BatchItemFailures) != 1 {
		t.Fatalf("first failure: %+v", resp)
	}
	if resp := handle(t, w, record(msg, "m1", 2)); len(resp.BatchItemFailures) != 0 {
		t.Fatalf("the ceiling receive was not acknowledged: %+v", resp)
	}
	if len(q.sent) != 1 || awssdk.ToString(q.sent[0].MessageAttributes[awsintegration.WebhookAttrDeadLetterReason].StringValue) != reasonReceiveCeiling {
		t.Fatalf("want one DLQ send with reason %q, got %d", reasonReceiveCeiling, len(q.sent))
	}
}

// TestWorkerDoesNotAcknowledgeADuplicateOfALiveClaim: the busy branch reports a
// failure and makes no request, so the copy the live claimant may need
// survives.
func TestWorkerDoesNotAcknowledgeADuplicateOfALiveClaim(t *testing.T) {
	t.Parallel()
	rcv := newReceiver(t, http.StatusOK)
	built, msg := coreAttempts(t, rcv.url(), 3, 1000)
	l := newMemLedger()
	if _, err := l.ClaimWebhookDelivery(context.Background(), built.DeliveryID, "", time.Now().Add(20*time.Second)); err != nil {
		t.Fatal(err)
	}
	q := &fakeSQS{}
	resp := handle(t, newTestWorker(q, l, time.Second, nil), record(msg, "m1", 1))
	if len(resp.BatchItemFailures) != 1 {
		t.Fatalf("a duplicate of a live claim was acknowledged: %+v", resp)
	}
	if rcv.hits.Load() != 0 {
		t.Errorf("a duplicate of a live claim made a request")
	}
	if got := q.lastVisibility(t); got < 15 || got > 20 {
		t.Errorf("visibility %d s, want the remaining lease (about 20 s)", got)
	}
}

// TestWorkerDeliversOnceUnderDuplicateReceives is the idempotency race against
// the real ledger on DynamoDB Local: two copies of one message in one batch —
// processed concurrently, as Handle does — make exactly one request, and a
// third copy after the delivery makes none.
func TestWorkerDeliversOnceUnderDuplicateReceives(t *testing.T) {
	store := localStore(t)
	for round := 0; round < 10; round++ {
		rcv := newReceiver(t, http.StatusOK)
		rcv.delay = 150 * time.Millisecond
		_, msg := coreAttempts(t, rcv.url(), 3, 1000)
		w := newTestWorker(&fakeSQS{}, store, time.Second, nil)

		resp := handle(t, w, record(msg, "copy-a", 1), record(msg, "copy-b", 1))
		if got := rcv.hits.Load(); got != 1 {
			t.Fatalf("round %d: two copies of one delivery made %d requests, want exactly 1", round, got)
		}
		if len(resp.BatchItemFailures) != 1 {
			t.Fatalf("round %d: %d failures, want the losing copy reported for retry and the winner acknowledged", round, len(resp.BatchItemFailures))
		}
		again := handle(t, w, record(msg, resp.BatchItemFailures[0].ItemIdentifier, 2))
		if len(again.BatchItemFailures) != 0 || rcv.hits.Load() != 1 {
			t.Fatalf("round %d: the returning duplicate was not acknowledged without a request (%d requests)", round, rcv.hits.Load())
		}
	}
}

// localStore is the real DynamoDB store on DynamoDB Local at DYNAMODB_ENDPOINT.
// Unlike the store package's harness, which falls back to localhost:8000, it
// skips when the variable is unset. The repository's CI sets it
// (.github/workflows/go.yml), so the race runs there; so does the workspace
// gate (.tools/gate-lambda.sh, outside this repository), which is also meant
// to fail a run whose log shows a DynamoDB Local skip.
func localStore(t *testing.T) *ddbstore.Store {
	t.Helper()
	endpoint := strings.TrimSpace(os.Getenv("DYNAMODB_ENDPOINT"))
	if endpoint == "" {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run the worker's idempotency race")
	}
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")
	ctx := context.Background()
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for DYNAMODB_ENDPOINT=%s: %v", endpoint, err)
	}
	table := "authtest_worker_" + randomHex(4)
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at DYNAMODB_ENDPOINT=%s (dynamodb local unreachable?): %v", table, endpoint, err)
	}
	store, err := ddbstore.New(client, ddbstore.Options{TableName: table})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestNewWorkerRefusesAnIncompleteEnvironment(t *testing.T) {
	full := map[string]string{
		envQueueURL: "https://sqs.example.test/q", envDLQURL: "https://sqs.example.test/d",
		envTable: "t", envMaxReceives: "10", envRetention: "1209600",
	}
	for missing := range full {
		env := map[string]string{}
		for k, v := range full {
			if k != missing {
				env[k] = v
			}
		}
		_, err := newWorker(context.Background(), func(k string) (string, bool) { v, ok := env[k]; return v, ok }, slog.New(slog.NewJSONHandler(io.Discard, nil)))
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Errorf("without %s: %v, want a refusal naming it", missing, err)
		}
	}
	env := map[string]string{}
	for k, v := range full {
		env[k] = v
	}
	env[envMaxReceives] = "0"
	if _, err := newWorker(context.Background(), func(k string) (string, bool) { v, ok := env[k]; return v, ok }, slog.New(slog.NewJSONHandler(io.Discard, nil))); err == nil {
		t.Error("a maxReceiveCount of 0 was accepted")
	}
}

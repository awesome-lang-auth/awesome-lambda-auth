package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// D9b's composition: which deliverer the sender gets, what the queued one is
// told, and that the response waits for the enqueue.

const testQueueURL = "https://sqs.eu-west-1.amazonaws.com/000000000000/awesome-auth-webhooks"

// recordingDeliverer stands in for the SQS deliverer. It is slow on purpose, so
// that a test reading it the instant Handle returns proves the flush and not
// the scheduler's luck.
type recordingDeliverer struct {
	mu       sync.Mutex
	delay    time.Duration
	err      error
	attempts []auth.WebhookAttempt
	// contexts is the context each attempt arrived with: what the production
	// SQS deliverer reads the correlation id from.
	contexts []context.Context
}

func (r *recordingDeliverer) DeliverWebhook(ctx context.Context, a auth.WebhookAttempt) error {
	time.Sleep(r.delay)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.attempts = append(r.attempts, a)
	r.contexts = append(r.contexts, ctx)
	return r.err
}

func (r *recordingDeliverer) contextOf(event string) (context.Context, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, a := range r.attempts {
		if a.Event == event {
			return r.contexts[i], true
		}
	}
	return nil, false
}

func (r *recordingDeliverer) seen() []auth.WebhookAttempt {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]auth.WebhookAttempt(nil), r.attempts...)
}

func newQueuedApp(t *testing.T, bundle *toolsBundle, rec auth.WebhookDeliverer, kv ...string) *App {
	t.Helper()
	env := toolsEnv(append([]string{"AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_QUEUE_URL", testQueueURL}, kv...)...)
	app, err := New(context.Background(), Options{
		Getenv: envFunc(env), Logger: discardLogger(), Stores: bundle.factory, WebhookDeliverer: rec,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

func subscribe(t *testing.T, bundle *toolsBundle, cfg auth.WebhookConfig) auth.WebhookConfig {
	t.Helper()
	stored, err := bundle.bundle.webhooks.(*auth.MemoryWebhookStore).AddWebhook(context.Background(), cfg)
	if err != nil {
		t.Fatalf("add webhook: %v", err)
	}
	return stored
}

func intPtr(n int) *int { return &n }

// TestQueuedWebhookIsEnqueuedBeforeTheResponseLeaves: with a queue configured,
// the login's delivery reaches the queued deliverer — not the receiver — and it
// has done so by the time Handle returns, because a Lambda freezes the moment
// it does. The attempt is the core's first, carrying the subscription's own
// retry count, and the deliverer is told the subscription's own delay.
func TestQueuedWebhookIsEnqueuedBeforeTheResponseLeaves(t *testing.T) {
	t.Parallel()
	bundle := newToolsBundle()
	hook := subscribe(t, bundle, auth.WebhookConfig{
		URL: "https://receiver.example.test/hook", Events: []string{auth.EventAuthLoginSuccess},
		Secret: "s", MaxRetries: intPtr(5), RetryDelayMs: intPtr(2500),
	})
	rec := &recordingDeliverer{delay: 150 * time.Millisecond}
	app := newQueuedApp(t, bundle, rec)

	// With a correlation id, because a bridged delivery must carry the
	// caller's across the queue as the in-process client carries it on the POST.
	const correlation = "queued-test-51c9"
	invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(testEmail))
	login := invoke(t, app, http.MethodPost, "/auth/login",
		jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer, "x-correlation-id", correlation), nil, registerBody(testEmail))
	if login.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d", login.StatusCode)
	}
	// The production deliverer's CorrelationID is queuedCorrelationID over the
	// context the attempt arrives with, and this is that context.
	if ctx, ok := rec.contextOf(auth.EventAuthLoginSuccess); !ok {
		t.Error("no login attempt reached the deliverer")
	} else {
		if got := queuedCorrelationID(ctx); got != correlation {
			t.Errorf("the queued delivery would carry CorrelationId %q, want the login's %q", got, correlation)
		}
		// And the deliverer built without an injection is wired to it. No I/O:
		// the SQS client is built on its first call.
		sqsd, ok := newWebhookQueue(app.Config, nil).inner.(*awsintegration.SQSWebhookDeliverer)
		if !ok || sqsd.CorrelationID == nil {
			t.Fatal("the production webhook queue is not an SQS deliverer with a CorrelationID")
		}
		if got := sqsd.CorrelationID(ctx); got != correlation {
			t.Errorf("the production SQS deliverer reads CorrelationId %q, want the login's %q", got, correlation)
		}
	}

	// No polling: the flush is the property under test.
	var logins []auth.WebhookAttempt
	for _, a := range rec.seen() {
		if a.Event == auth.EventAuthLoginSuccess {
			logins = append(logins, a)
		}
	}
	if len(logins) != 1 {
		t.Fatalf("%d login attempt(s) had been enqueued when Handle returned, want exactly 1", len(logins))
	}
	a := logins[0]
	if a.ConfigID != hook.ID || a.Attempt != 0 || a.Remaining != 5 {
		t.Errorf("attempt = config %q attempt %d remaining %d, want %q/0/5", a.ConfigID, a.Attempt, a.Remaining, hook.ID)
	}
	if a.Headers.Get("X-Webhook-Signature") == "" || len(a.Body) == 0 {
		t.Error("the queued attempt is not the signed request the core built")
	}
	if got := app.tools.queue.retryDelay(context.Background(), a); got != 2500*time.Millisecond {
		t.Errorf("the deliverer is told a retry delay of %s, want the subscription's 2.5s", got)
	}
}

// TestQueuedWebhookSnapshotAppliesTheStackDefaults: a row with no retry values
// of its own is scheduled on tools.outboundWebhooks.defaults, as the in-process
// path schedules it (webhookDefaults) — not on the core's literals.
func TestQueuedWebhookSnapshotAppliesTheStackDefaults(t *testing.T) {
	t.Parallel()
	bundle := newToolsBundle()
	hook := subscribe(t, bundle, auth.WebhookConfig{URL: "https://receiver.example.test/hook", Events: []string{auth.EventAuthLoginSuccess}})
	rec := &recordingDeliverer{}
	app := newQueuedApp(t, bundle, rec,
		"AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_MAX_RETRIES", "7",
		"AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_RETRY_DELAY_MS", "300")

	invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(testEmail))
	invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody(testEmail))
	var found bool
	for _, a := range rec.seen() {
		if a.Event != auth.EventAuthLoginSuccess {
			continue
		}
		found = true
		if a.ConfigID != hook.ID || a.Remaining != 7 {
			t.Errorf("attempt for %q remaining %d, want the stack default 7", a.ConfigID, a.Remaining)
		}
		if got := app.tools.queue.retryDelay(context.Background(), a); got != 300*time.Millisecond {
			t.Errorf("retry delay %s, want the stack default 300ms", got)
		}
	}
	if !found {
		t.Fatal("no login attempt was enqueued")
	}
	// An attempt the snapshot never saw — a host calling Send with a config of
	// its own — is scheduled on the same default.
	if got := app.tools.queue.retryDelay(context.Background(), auth.WebhookAttempt{ConfigID: "whk_unknown"}); got != 300*time.Millisecond {
		t.Errorf("unknown config: %s, want the stack default", got)
	}
}

// TestQueuedWebhookFailureDoesNotHoldTheResponse: an enqueue that fails on its
// last attempt settles the count, so the flush does not wait out its bound.
func TestQueuedWebhookFailureDoesNotHoldTheResponse(t *testing.T) {
	t.Parallel()
	bundle := newToolsBundle()
	subscribe(t, bundle, auth.WebhookConfig{URL: "https://receiver.example.test/hook", Events: []string{auth.EventAuthLoginSuccess}, MaxRetries: intPtr(0)})
	rec := &recordingDeliverer{err: errors.New("sqs down")}
	logs := &lockedBuffer{}
	env := toolsEnv("AWESOME_AUTH_TOOLS_OUTBOUND_WEBHOOKS_QUEUE_URL", testQueueURL)
	app, err := New(context.Background(), Options{
		Getenv: envFunc(env), Logger: newLogger(logs, slog.LevelWarn), Stores: bundle.factory, WebhookDeliverer: rec,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Close)
	invoke(t, app, http.MethodPost, "/auth/register", jsonHeaders(), nil, registerBody(testEmail))
	invoke(t, app, http.MethodPost, "/auth/login", jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody(testEmail))
	if len(rec.seen()) == 0 {
		t.Fatal("no attempt reached the deliverer")
	}
	// Timing a login under -race proves nothing; the flush's own warning is
	// the evidence that it waited out its bound. Matched on the constant the
	// code logs, so a reworded warning cannot make this vacuous.
	if out := logs.String(); strings.Contains(out, webhookFlushTimedOut) {
		t.Errorf("a failed last attempt did not settle, and the flush waited out its bound:\n%s", out)
	}
}

// TestTooLargeEnvelopeDoesNotHoldTheResponse: an envelope SQS cannot carry is
// refused on every attempt, so the count settles at the first refusal and the
// flush returns at once instead of waiting out its two-second bound while the
// core backs off — and the core's later retries of the same delivery do not
// settle again and release some other delivery's wait. The core's own sender,
// with its real one-second back-off, is what drives it.
func TestTooLargeEnvelopeDoesNotHoldTheResponse(t *testing.T) {
	t.Parallel()
	rec := &recordingDeliverer{err: fmt.Errorf("%w: test", awsintegration.ErrWebhookTooLargeToQueue)}
	q := &webhookQueue{inner: rec, fallback: time.Second}
	cfg := auth.WebhookConfig{ID: "whk_big", URL: "https://receiver.example.test/hook", MaxRetries: intPtr(3), RetryDelayMs: intPtr(1000)}
	q.observe([]auth.WebhookConfig{cfg})

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sender := &auth.WebhookSender{Deliverer: q}
	ev := auth.Event{Name: auth.EventAuthLoginSuccess, UserID: "u1"}
	go func() { _ = sender.Send(ctx, cfg, ev.OutgoingWebhook("")) }()

	start := time.Now()
	if !q.flush(context.Background()) {
		t.Fatal("the flush waited out its bound for an envelope that can never be queued")
	}
	// The core's first back-off is one second; settling only on the last
	// attempt would have left the flush waiting two.
	if elapsed := time.Since(start); elapsed >= 900*time.Millisecond {
		t.Errorf("the flush took %s, want it released at the first refusal, well before the core's 1 s back-off", elapsed)
	}

	// Another delivery in the next request, while the core retries the big
	// one after its back-off: that retry must not settle the new count.
	q.observe([]auth.WebhookConfig{{ID: "whk_other", URL: "https://receiver.example.test/other"}})
	deadline := time.Now().Add(3 * time.Second)
	for len(rec.seen()) < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if len(rec.seen()) < 2 {
		t.Fatal("the core never retried the refused enqueue")
	}
	if got := q.pending.outstanding(); got != 1 {
		t.Errorf("after the core's retry of the refused delivery, %d pending, want 1 (the other delivery's)", got)
	}
}

// TestNoQueueKeepsTheInProcessDeliverer: unset, nothing of D9b is built and
// the cold-start line says the in-process deliverer is in force.
func TestNoQueueKeepsTheInProcessDeliverer(t *testing.T) {
	t.Parallel()
	app := newToolsApp(t, toolsEnv(), nil)
	if app.tools.queue != nil {
		t.Fatal("a webhook queue was built with tools.outboundWebhooks.queueUrl unset")
	}
	if line := outgoingWebhooksLine(app.Config); !strings.Contains(line, "in process") {
		t.Errorf("cold-start line without a queue: %q", line)
	}
	queued := newQueuedApp(t, newToolsBundle(), &recordingDeliverer{})
	if line := outgoingWebhooksLine(queued.Config); !strings.Contains(line, "SQS") {
		t.Errorf("cold-start line with a queue: %q", line)
	}
}

func TestPendingDeliveriesAreBoundedAndRecover(t *testing.T) {
	t.Parallel()
	var p pendingDeliveries
	if !p.wait(context.Background(), time.Millisecond) {
		t.Fatal("a wait with nothing pending did not return at once")
	}
	p.expect(2)
	p.settle()
	go func() { time.Sleep(20 * time.Millisecond); p.settle() }()
	if !p.wait(context.Background(), time.Second) {
		t.Fatal("the wait did not see both settlements")
	}

	// A settlement that never comes: the bound releases the wait and resets the
	// count, so the next request does not inherit it.
	p.expect(1)
	if p.wait(context.Background(), 20*time.Millisecond) {
		t.Fatal("a wait on a stuck enqueue reported success")
	}
	start := time.Now()
	if !p.wait(context.Background(), time.Second) || time.Since(start) > 100*time.Millisecond {
		t.Fatal("the count was not reset after a timed-out wait")
	}
	// The stuck one settling late is absorbed at zero.
	p.settle()
	p.expect(1)
	p.settle()
	if !p.wait(context.Background(), 20*time.Millisecond) {
		t.Fatal("a late settlement took the count below zero")
	}
}

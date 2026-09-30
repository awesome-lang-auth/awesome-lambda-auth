package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// D9b: outgoing webhooks delivered from a queue.
//
// D9a left WebhookSender.Deliverer at the core's in-process HTTP deliverer and
// registered what that costs on this runtime
// (outgoing-webhook-delivery-races-the-response). With
// tools.outboundWebhooks.queueUrl set, this file fills that one field with a
// deliverer that enqueues each signed attempt on SQS
// (awsintegration.SQSWebhookDeliverer), and cmd/webhook-worker delivers it.
// Unset — the default, and the template's default through EnableWebhookQueue
// — nothing here is built and D9a's arrangement stands unchanged.
//
// Three things the queue needs that the core's seam does not hand over are
// decided here, because this is the composition that can see both sides.
//
// ── where the retry delay comes from ─────────────────────────────────────────
//
// The worker reproduces the reference's schedule — at most Retries() further
// attempts, the first after RetryDelay(), each wait twice the last — and the
// attempt it receives carries half of that: Remaining, which on the attempt the
// deliverer normally sees (attempt 0) IS Retries(). RetryDelay() is not on the
// attempt. Three sources were weighed:
//
//   - The stack-wide default (tools.outboundWebhooks.defaults.retryDelayMs).
//     Rejected: the reference honours a per-subscription retryDelayMs, and a
//     deployment that silently used the default for every webhook would be a
//     registered deviation dressed up as a shortcut.
//   - A store read, at enqueue or in the worker. Rejected. The core's
//     WebhookStore has no by-id getter — FindByEvent is the only method it
//     requires, and it needs the event's tenant, which the attempt does not
//     carry — so a read means a product-only query per delivery, on the
//     request path at enqueue or once per attempt in the worker, to learn a
//     value this process already held a few microseconds earlier. And a
//     worker-side read would see a subscription edited after the event, so
//     the delay and the retry count (fixed at enqueue, in Remaining) could
//     come from two different versions of the row.
//   - The configuration the core itself used. Chosen. webhookDefaults (the
//     D9a decorator that applies the stack defaults to a row with no values of
//     its own) is the store the emitter calls, synchronously, immediately
//     before it hands each returned config to the sender. So it records each
//     config's resolved RetryDelay() by ID as it returns it, and the deliverer
//     reads the entry for the attempt's ConfigID. It is the same snapshot the
//     core resolved Retries() from, costs no request, and cannot disagree with
//     the Remaining it travels beside. The entry is carried as the RetryDelayMs
//     message attribute, so the worker never reads the store for policy.
//
// An attempt whose ConfigID the snapshot does not hold — a host embedding this
// package and calling WebhookSender.Send with a config of its own — falls back
// to the stack default, which is the value such a config's nil RetryDelayMs
// would have resolved to through webhookDefaults anyway.
//
// ── the enqueue must finish before the response leaves ───────────────────────
//
// The emitter delivers on goroutines it detaches and does not wait for. With
// the in-process deliverer that is the whole problem D9a registered; with this
// one it is a much smaller copy of the same problem: SendMessage takes tens of
// milliseconds, and a Lambda that writes its response before the goroutine has
// had them freezes the goroutine mid-request. The enqueue would then complete
// on some later invocation, or never, and "at-least-once" would be at-most-once
// with a queue behind it.
//
// So App.Handle waits for the enqueues the request started before it returns
// the response to the runtime, bounded by webhookFlushBound. The count has to
// be taken before the goroutines exist, or a goroutine not yet scheduled would
// be missed: webhookDefaults.FindByEvent — synchronous, on the request
// goroutine, the step before the emitter spawns — expects one settlement per
// config it returns, and this deliverer settles one when an attempt succeeds,
// when it was the last (Remaining 0), or at once for an envelope too large to
// queue (DeliverWebhook says why). A config with a negative Retries() is not
// counted, because the core makes no attempt for it. One path leaves a count
// unsettled: the core's Send returning before it calls the deliverer at all (an
// encode or UUID failure). A JSON-decoded payload cannot fail to encode, and
// the flush bound caps what it would cost in any case.
//
// What that costs is the SendMessage latency on the requests that match a
// webhook, instead of a delivery lost to the freeze (docs/cost-model.md §3.3).
// A bound that expires — SQS unreachable, or an enqueue retried on the core's
// back-off — releases the response and logs; the enqueue carries on and
// completes, if the environment is thawed, exactly as before this block.
//
// ── what the queue does not change ───────────────────────────────────────────
//
// The format. The envelope, the headers, the signature and the attempt
// numbering are the core's and cross the queue as bytes. One observable
// difference is registered: a retry now carries the delivery id of the attempt
// it retries, where the reference mints a fresh one per attempt
// (queued-webhook-retries-reuse-the-delivery-id).

// webhookFlushBound is the longest App.Handle waits for the request's enqueues.
// DefaultSQSSendTimeout bounds each SendMessage at the same two seconds, so a
// bound this long covers one full enqueue and cuts off only the core's
// retry-after-back-off, which is exactly the case where holding a login for
// seconds would be worse than the risk it avoids.
const webhookFlushBound = 2 * time.Second

// webhookQueue is the deliverer the sender is handed when the queue is
// configured: the SQS deliverer, wrapped with the snapshot and the settlement
// count above.
type webhookQueue struct {
	inner auth.WebhookDeliverer

	// delays maps WebhookConfig.ID to the RetryDelay() webhookDefaults
	// resolved for it.
	delays sync.Map
	// fallback is the stack default, for an attempt the snapshot does not
	// hold.
	fallback time.Duration

	pending pendingDeliveries
}

// newWebhookQueue builds the queued deliverer, or returns nil when
// tools.outboundWebhooks.queueUrl is empty. injected replaces the SQS
// deliverer, for a test; it switches nothing on.
func newWebhookQueue(cfg *config.Config, injected auth.WebhookDeliverer) *webhookQueue {
	queueURL := strings.TrimSpace(cfg.Tools.OutboundWebhooks.QueueURL)
	if queueURL == "" {
		return nil
	}
	q := &webhookQueue{
		fallback: time.Duration(cfg.Tools.OutboundWebhooks.Defaults.RetryDelayMs) * time.Millisecond,
	}
	if injected != nil {
		q.inner = injected
		return q
	}
	q.inner = &awsintegration.SQSWebhookDeliverer{
		QueueURL:      queueURL,
		Client:        awsintegration.NewSQSClient(awsintegration.SQSOptions{}),
		RetryDelay:    q.retryDelay,
		CorrelationID: queuedCorrelationID,
	}
	return q
}

// queuedCorrelationID is the id the correlating transport would have put on an
// in-process POST, filtered the same way (logging.go, correlatingTransport),
// for the worker to put back. A named function rather than a closure so that
// the test which captures a bridged delivery's context runs exactly this.
func queuedCorrelationID(ctx context.Context) string {
	return forwardableCorrelationID(correlationIDOf(ctx))
}

// observe is webhookDefaults.FindByEvent's hook: record each config's resolved
// delay, and expect one settlement per config the core will attempt.
func (q *webhookQueue) observe(configs []auth.WebhookConfig) {
	expected := 0
	for _, c := range configs {
		if c.ID != "" {
			q.delays.Store(c.ID, c.RetryDelay())
		}
		if c.Retries() >= 0 {
			expected++
		}
	}
	q.pending.expect(expected)
}

// retryDelay answers SQSWebhookDeliverer.RetryDelay from the snapshot.
func (q *webhookQueue) retryDelay(_ context.Context, attempt auth.WebhookAttempt) time.Duration {
	if v, ok := q.delays.Load(attempt.ConfigID); ok {
		return v.(time.Duration)
	}
	return q.fallback
}

// DeliverWebhook enqueues through the inner deliverer and settles the
// request's count exactly once per delivery: when an attempt is stored, when
// the last attempt fails, or — for an envelope too large to queue — at the
// first failure.
//
// The last case is not a retry worth waiting for. The size is deterministic:
// the core serialises the body once for every attempt, and the headers and
// attributes differ between attempts only in values of fixed length (a v4
// delivery id), so if attempt 0 is too large every attempt is. Waiting on the
// core's back-off would hold the response for the whole flush bound — two
// seconds of the auth function at 512 MB — for an enqueue that cannot happen,
// and whoever can make an event carry a large payload (POST <tools>/track
// under tools.auth none or session) could buy that per request. So the count
// is settled at attempt 0 and, because the retries that follow fail the same
// way, never again for this delivery: settling on the last one too would
// release another delivery's wait early.
func (q *webhookQueue) DeliverWebhook(ctx context.Context, attempt auth.WebhookAttempt) error {
	err := q.inner.DeliverWebhook(ctx, attempt)
	permanent := errors.Is(err, awsintegration.ErrWebhookTooLargeToQueue)
	switch {
	case err == nil:
		q.pending.settle()
	case permanent:
		if attempt.Attempt == 0 {
			q.pending.settle()
		}
	case attempt.Remaining <= 0:
		q.pending.settle()
	}
	return err
}

// flush waits for the enqueues the current request started, up to
// webhookFlushBound or ctx, and reports whether they all finished.
func (q *webhookQueue) flush(ctx context.Context) bool {
	return q.pending.wait(ctx, webhookFlushBound)
}

// pendingDeliveries counts the enqueues a request is still owed.
//
// A Lambda execution environment serves one invocation at a time, so a
// process-wide count is the current request's count. A wait that times out
// zeroes it, so that one stuck enqueue does not make every later request wait
// the bound too; a settlement arriving after that is absorbed at zero. The
// price is that such a late settlement can release a later request's wait one
// enqueue early, which leaves that enqueue exactly where the in-process
// deliverer leaves every delivery — racing the freeze — and requires a timeout
// first.
type pendingDeliveries struct {
	mu   sync.Mutex
	n    int
	zero chan struct{}
}

func (p *pendingDeliveries) expect(k int) {
	if k <= 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == 0 {
		p.zero = make(chan struct{})
	}
	p.n += k
}

// outstanding is the current count, for the tests.
func (p *pendingDeliveries) outstanding() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.n
}

func (p *pendingDeliveries) settle() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.n == 0 {
		return
	}
	p.n--
	if p.n == 0 {
		close(p.zero)
	}
}

func (p *pendingDeliveries) wait(ctx context.Context, bound time.Duration) bool {
	p.mu.Lock()
	if p.n == 0 {
		p.mu.Unlock()
		return true
	}
	done := p.zero
	p.mu.Unlock()

	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-done:
		return true
	case <-timer.C:
	case <-ctx.Done():
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.zero == done && p.n > 0 {
		p.n = 0
		close(done)
	}
	return false
}

// webhookFlushTimedOut is the request log's message when the flush bound gave
// out first. A constant because the tests match on it, and a reworded warning
// must not turn their assertion vacuous.
const webhookFlushTimedOut = "outgoing webhook enqueue still in flight when the response was ready"

// flushWebhookQueue is App.Handle's call: wait for the request's enqueues and
// say so when the bound gave out first.
func flushWebhookQueue(ctx context.Context, tw *toolsWiring, log *slog.Logger) {
	if tw == nil || tw.queue == nil {
		return
	}
	if !tw.queue.flush(ctx) {
		log.Warn(webhookFlushTimedOut,
			slog.String("path", "tools.outboundWebhooks.queueUrl"),
			slog.String("effect", "the response was released after "+webhookFlushBound.String()+"; the enqueue continues and completes if this execution environment is thawed, and is lost if it is not"))
	}
}

// outgoingWebhooksLine is the cold-start log's sentence about which deliverer
// is in force.
func outgoingWebhooksLine(cfg *config.Config) string {
	if strings.TrimSpace(cfg.Tools.OutboundWebhooks.QueueURL) != "" {
		return "enqueued on SQS (tools.outboundWebhooks.queueUrl) before the response leaves, and delivered by the webhook worker on the reference's retry schedule, with a dead-letter queue behind it"
	}
	return "delivered in process on a detached goroutine, which a Lambda freezes with the response: best-effort unless tools.outboundWebhooks.queueUrl is set (deviation outgoing-webhook-delivery-races-the-response)"
}

// webhookQueueKnobGaps reports a queue URL that nothing will enqueue on.
func webhookQueueKnobGaps(cfg *config.Config) []knobGap {
	if strings.TrimSpace(cfg.Tools.OutboundWebhooks.QueueURL) == "" {
		return nil
	}
	switch {
	case !cfg.Tools.Enabled:
		return []knobGap{{
			Path:    "tools.outboundWebhooks.queueUrl",
			Problem: "a webhook queue is configured and tools.enabled is off, so no event reaches the webhook fan-out and nothing is ever enqueued",
			Remedy:  "set tools.enabled: true to deliver outgoing webhooks through the queue, or leave the queue unset; until then it costs nothing and does nothing",
		}}
	case !cfg.Stores.Enable.Webhooks:
		return []knobGap{{
			Path:    "tools.outboundWebhooks.queueUrl",
			Problem: "a webhook queue is configured and stores.enable.webhooks is off, so no subscription can match an event and nothing is ever enqueued",
			Remedy:  "set stores.enable.webhooks: true, or leave the queue unset",
		}}
	}
	return nil
}

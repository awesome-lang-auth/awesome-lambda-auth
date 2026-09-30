package contract

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// An outgoing webhook, end to end (D9b): subscribe through the admin console,
// log in, and watch the deployment POST the login to a receiver this suite
// runs, signed with the secret this suite chose.
//
// ── why it is opt-in ─────────────────────────────────────────────────────────
//
// Every other case is a request the suite makes and a response it reads. This
// one is a request the DEPLOYMENT makes, to a URL it can reach — and a Lambda
// cannot reach a laptop. So the suite cannot run it on its own: somebody has to
// give the stack a public URL that ends at the suite. Two variables do that,
// and without the first the case skips with that sentence:
//
//	AWESOME_AUTH_CONTRACT_WEBHOOK_RECEIVER_URL  the public URL the stack will POST to
//	AWESOME_AUTH_CONTRACT_WEBHOOK_LISTEN        where the suite listens for it (default :8787)
//
// A tunnel (cloudflared, ngrok, an SSH reverse forward) from the first to the
// second is the whole setup. The suite runs the receiver itself rather than
// trusting a request bin because the property under test is the signature, and
// only the party that chose the secret can check it.
//
// It also needs the admin console and a declared administrator (the
// subscription is created through POST <admin>/api/webhooks, D8), and a tools
// block with the webhook store on, which is what fans a login out at all. Those
// two are checked inside the case and skip it with the reason: the store by the
// console's own 404 for a webhook POST without one (admin.router.ts:1391), the
// tools block by an anonymous POST <tools>/track answering 404, the same
// request the tools probes make. Not by CapTools, which is "the router answers
// this suite's session" and is absent under tools.auth: apiKey, the template's
// default — where the login below is fanned out all the same.
//
// ── what it pins, and what it does not ───────────────────────────────────────
//
// The trigger is a login, and that is this product's behaviour, not the
// reference's: the reference's AuthTools is fed by track alone and nothing
// links a login to a webhook, so a reference deployment fails this case by
// timing out. The delivery reaches the receiver because of the registered
// deviation library-events-are-bridged-into-the-tools-fan-out. What the case
// holds against the reference is the wire of the delivery itself
// (src/tools/webhook-sender.ts:17-48): the four X-Webhook-* headers, the
// timestamp as toISOString writes it and equal to the body's, a v4 delivery
// id, the envelope's five members, and the signature over the raw body.
//
// It asserts at least one delivery, not exactly one: queued delivery is
// at-least-once (queued-webhooks-are-delivered-at-least-once). It passes
// against either deliverer — in process or queued — because the wire is the
// same; against the in-process one on Lambda it may fail by timing out, which
// is the registered deviation outgoing-webhook-delivery-races-the-response
// showing itself and is the reason D9b exists.

const (
	WebhookReceiverURLEnv    = "AWESOME_AUTH_CONTRACT_WEBHOOK_RECEIVER_URL"
	WebhookReceiverListenEnv = "AWESOME_AUTH_CONTRACT_WEBHOOK_LISTEN"

	defaultWebhookListen = ":8787"

	// webhookArrivalTimeout covers a queued delivery's enqueue, the event
	// source's poll and the POST, with room for one retry at the default
	// one-second back-off.
	webhookArrivalTimeout = 90 * time.Second
)

var (
	// uuidV4 is crypto.randomUUID()'s output: lowercase, version 4, variant 10.
	uuidV4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	// isoMillisUTC is Date.prototype.toISOString()'s output.
	isoMillisUTC = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$`)
)

// CapWebhookReceiver is whether the operator declared a public receiver URL. It
// is declared rather than probed: the suite cannot make one.
const CapWebhookReceiver Capability = "webhook-receiver"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapWebhookReceiver,
		Stage: stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			if u := strings.TrimSpace(os.Getenv(WebhookReceiverURLEnv)); u != "" {
				p.Set(CapWebhookReceiver, capability{state: capOn, why: WebhookReceiverURLEnv + " declares " + u})
				return
			}
			p.Set(CapWebhookReceiver, capability{state: capAbsent, why: fmt.Sprintf(
				"%s is unset: a deployment can only POST to a URL it can reach, so the suite needs a public URL tunnelled to %s (default %s)",
				WebhookReceiverURLEnv, WebhookReceiverListenEnv, defaultWebhookListen)})
		},
	})

	register(Case{
		Name: "tools/outgoing-webhook-reaches-the-receiver-signed",
		Doc: "product deviation library-events-are-bridged-into-the-tools-fan-out — a login reaches a subscription to " +
			"identity.auth.login.success at all (the reference's track is its only path to a webhook); and, on the wire the " +
			"reference defines (src/tools/webhook-sender.ts:17-48), at least one POST arrives with X-Webhook-Event, a v4 " +
			"X-Webhook-Delivery, X-Webhook-Timestamp in toISOString form equal to the body's timestamp, the envelope " +
			"{event, version, timestamp, data, metadata} and X-Webhook-Signature: sha256=<hex HMAC-SHA256(secret, raw body)>",
		Needs: []Capability{CapAdmin, CapAdminSession, CapAdminCredential, CapWebhookReceiver},
		Run: func(t *testing.T, e *Env) {
			// The tools block is what fans the login out; see the file header
			// for why this is a request here and not a capability.
			if r := e.NewClient().POST(t, e.tools("/track/contract-probe"), body{}); r.Status == 404 {
				t.Skipf("the tools router is not mounted (%s answered 404), so nothing fans a login out to a webhook: "+
					"tools.enabled is off, or AWESOME_AUTH_CONTRACT_TOOLS_PATH is wrong", r.Target)
			}

			listen := strings.TrimSpace(os.Getenv(WebhookReceiverListenEnv))
			if listen == "" {
				listen = defaultWebhookListen
			}
			rcv := startWebhookReceiver(t, listen)

			var raw [16]byte
			if _, err := rand.Read(raw[:]); err != nil {
				t.Fatal(err)
			}
			secret := "contract-" + hex.EncodeToString(raw[:])

			admin := adminLogin(t, e)
			created := admin.POST(t, adminPath()+"/api/webhooks", body{
				"url":    strings.TrimSpace(os.Getenv(WebhookReceiverURLEnv)),
				"events": []string{"identity.auth.login.success"},
				"secret": secret,
			})
			if created.Status == 404 {
				t.Skipf("POST <admin>/api/webhooks answered 404: this deployment wires no webhook store "+
					"(stores.enable.webhooks), which is a configuration and not a fault\n  %s", created.where())
			}
			created.mustStatus(t, 200)
			hook, _ := created.obj(t)["webhook"].(map[string]any)
			id, _ := hook["id"].(string)
			if id == "" {
				t.Fatalf("POST <admin>/api/webhooks answered no webhook id\n  %s", created.where())
			}
			t.Cleanup(func() { admin.DELETE(t, adminPath()+"/api/webhooks/"+id) })

			acct := e.NewAccount(t)
			e.NewClient().POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, BearerStrategy()).mustStatus(t, 200)

			got, ok := rcv.await(func(r receivedWebhook) bool {
				return r.header.Get("X-Webhook-Event") == "identity.auth.login.success" && bytes.Contains(r.body, []byte(acct.Email))
			}, webhookArrivalTimeout)
			if !ok {
				t.Fatalf("no identity.auth.login.success delivery for %s reached %s within %s (%d other requests arrived).\n\n"+
					"Check the tunnel first. Then: with tools.outboundWebhooks.queueUrl set, the dead-letter queue says why a "+
					"delivery gave up; without it, a Lambda may freeze the delivery with the response "+
					"(outgoing-webhook-delivery-races-the-response).", acct.Email, os.Getenv(WebhookReceiverURLEnv), webhookArrivalTimeout, rcv.count())
			}
			if id := got.header.Get("X-Webhook-Delivery"); !uuidV4.MatchString(id) {
				t.Errorf("X-Webhook-Delivery = %q, want a lowercase v4 UUID as randomUUID() mints", id)
			}
			stamp := got.header.Get("X-Webhook-Timestamp")
			if !isoMillisUTC.MatchString(stamp) {
				t.Errorf("X-Webhook-Timestamp = %q, want toISOString's form: three fractional digits and a literal Z", stamp)
			}
			if ct := got.header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(got.body, &envelope); err != nil {
				t.Fatalf("the delivery body is not a JSON object: %v\n  %q", err, got.body)
			}
			for key := range envelope {
				switch key {
				case "event", "version", "timestamp", "data", "metadata":
				default:
					t.Errorf("the envelope carries %q, which the reference's {event, version, timestamp, data, metadata} does not", key)
				}
			}
			for _, key := range []string{"event", "version", "timestamp", "data"} {
				if _, ok := envelope[key]; !ok {
					t.Errorf("the envelope has no %q member", key)
				}
			}
			var event, timestamp string
			_ = json.Unmarshal(envelope["event"], &event)
			_ = json.Unmarshal(envelope["timestamp"], &timestamp)
			if event != got.header.Get("X-Webhook-Event") {
				t.Errorf("the body's event %q differs from X-Webhook-Event %q", event, got.header.Get("X-Webhook-Event"))
			}
			if timestamp != stamp {
				t.Errorf("the body's timestamp %q differs from X-Webhook-Timestamp %q; the reference sends the envelope's own", timestamp, stamp)
			}
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write(got.body)
			want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if !hmac.Equal([]byte(got.header.Get("X-Webhook-Signature")), []byte(want)) {
				t.Errorf("X-Webhook-Signature does not verify against the raw body with the secret this suite chose:\n got %s\nwant %s",
					got.header.Get("X-Webhook-Signature"), want)
			}
		},
	})
}

type receivedWebhook struct {
	header http.Header
	body   []byte
}

type webhookReceiver struct {
	mu       sync.Mutex
	received []receivedWebhook
	arrived  chan struct{}
}

func startWebhookReceiver(t *testing.T, listen string) *webhookReceiver {
	t.Helper()
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		t.Fatalf("cannot listen on %s for the webhook receiver (%s): %v", listen, WebhookReceiverListenEnv, err)
	}
	rcv := &webhookReceiver{arrived: make(chan struct{}, 64)}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			rcv.mu.Lock()
			rcv.received = append(rcv.received, receivedWebhook{header: r.Header.Clone(), body: b})
			rcv.mu.Unlock()
			select {
			case rcv.arrived <- struct{}{}:
			default:
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return rcv
}

func (r *webhookReceiver) await(match func(receivedWebhook) bool, within time.Duration) (receivedWebhook, bool) {
	deadline := time.After(within)
	for {
		r.mu.Lock()
		for _, got := range r.received {
			if match(got) {
				r.mu.Unlock()
				return got, true
			}
		}
		r.mu.Unlock()
		select {
		case <-r.arrived:
		case <-deadline:
			return receivedWebhook{}, false
		}
	}
}

func (r *webhookReceiver) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.received)
}

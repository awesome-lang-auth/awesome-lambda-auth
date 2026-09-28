package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
	"github.com/nik2208/awesome-go-auth/adapter/nethttp"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The tools surface: POST <tools>/track/{event}, POST <tools>/notify/{target},
// GET <tools>/telemetry and the router's own documentation pair — and behind
// them the event bus, which nothing in this product had built before this
// block.
//
// Every route comes from the imported adapter and nothing in this file mounts
// one. awesome-go-auth v0.11.0 put the whole router on HTTPConfig.Tools
// (ToolsOptions): with Enabled set, a facade supplied and an access decision
// made, all four adapters register (*Auth).ToolsHandler at ToolsOptions.Path —
// a *sibling* of the api prefix, "/tools" by default, for the reason the core's
// tools.go gives at length (the reference's createToolsRouter is a second
// router the host mounts beside the first, and the auth router's CSRF chain
// would refuse a server-to-server POST /track). What this file does is build
// that ToolsOptions out of the product's `tools` block, build the AuthTools
// facade the routes call, build the bus the facade and the core share, and
// decide four things the core deliberately left to the host. Each decision is
// argued below; the short list is: the bus is bridged, the stream is not
// mounted, the access posture is the document's, and the two transports later
// blocks bring are left as visible seams rather than filled with something
// that would work on a laptop and not here.
//
// ── the bus, and whether the library's own events reach the sinks ────────────
//
// auth.WithEventBus hands the core a bus, and from v0.11.0 the service layer
// publishes twenty-three identity.* events onto it. The facade's four sinks —
// the telemetry store, the bus, the SSE manager, the outgoing webhooks — are fed
// by AuthTools.Track and, by the core's default, by nothing else: the core's
// auth_tools.go argues at length that a facade which subscribed itself to the
// bus would deliver every *tracked* event twice, because Track publishes on the
// bus at step 2 and then broadcasts and fires webhooks at steps 3 and 4, and a
// self-subscription would hear step 2 and run 3 and 4 again with a second event
// id. So the core is silent by default and exposes AuthTools.Bridge as the one
// call that changes it.
//
// **This product bridges, and does not call Bridge.** The two halves of that
// sentence are one decision each.
//
// It bridges because it is a deployment. An operator configures an outgoing
// webhook on `identity.auth.login.success` through the admin API and expects
// logins to reach it; they enable the telemetry store and expect
// GET <tools>/telemetry to show logins; and the core's own deviation
// identity-events-are-raised-from-the-development-line says the events exist
// precisely so a deployment can act on them. Without a bridge every one of
// those expectations is met with silence that nothing reports — the core's
// "monitoring gap", which it names and prices as "a deployment can believe it
// is receiving login failures and not be". A product whose documented answer
// to that is "add one line to the source" is not a product.
//
// It does not call Bridge because Bridge is a wildcard subscription on the
// facade's *own* bus — the one Track publishes on at step 2 — and the hazard
// the core documents is therefore not confined to a host that tracks an
// identity.* name: it is every tracked event, whatever its name. The first
// version of this file called Bridge, and TestBridgeDeliversEachLoginOnce and
// the DynamoDB round trip both found each POST <tools>/track recorded twice —
// once by Track's own step 1, once by the bridge hearing Track's step 2 with a
// fresh event id. That is the core's comment made concrete, and it rules out
// Bridge for any deployment that mounts the track route, which is this one.
//
// So the product keeps two buses. The core is handed one (auth.WithEventBus),
// and the twenty-three identity.* publications land on it and nowhere else. The
// facade is built on another, private one, which only Track publishes on and
// which nothing subscribes to. Between them is one wildcard subscription on the
// core's bus that calls Track with the event's own name, payload and six
// identifiers — so a bridged event goes through exactly the fan-out a tracked
// one does, with the same id, the same frame shape and the same envelope, which
// is the property the core's Bridge exists to give. No loop is possible, because
// the only bus with a subscriber is the one Track never publishes on; and no
// event is fanned out twice, because the only path from the core's bus to the
// sinks is that one subscription. TestBridgeDeliversEachLoginOnce pins the
// property that matters — one login, exactly one delivery per matching webhook,
// exactly one telemetry row — and TestToolsRoutesComeFromTheAdapter pins that a
// tracked event is recorded once. Both fail the day either tree changes the
// arrangement.
//
// Two things the arrangement gives up, both stated. A subscriber to the core's
// bus — App.Events, for a host embedding this package — hears the library's
// events and not tracked ones; a subscriber to App.Tools.Events hears every
// event that was fanned out, tracked and bridged alike. And Track stamps the
// fan-out instant rather than the publication instant on the record, because
// TrackOptions carries no timestamp; the two are microseconds apart on one
// synchronous call chain.
//
// What the bridge costs: every identity.* event now writes one telemetry row
// (awaited, on the request goroutine — one DynamoDB PutItem per login, refresh,
// logout and the rest; docs/cost-model.md §2.6) and fires every matching
// outgoing webhook.
//
// The bridge's context is the process's, not the cold start's. main.go bounds
// New with startTimeout and cancels it the moment New returns; a bridge bound
// to that context would hand every telemetry write a cancelled context from the
// first request onwards. context.WithoutCancel keeps nothing of it but the
// values, which is what a lifetime that ends with the process wants.
//
// ── the stream is not mounted on this runtime ────────────────────────────────
//
// GET <tools>/stream is Server-Sent Events: a response that stays open and
// carries a frame whenever something happens. API Gateway — the REST and the
// HTTP API alike — buffers the integration response and enforces a 29-second
// integration timeout, so behind it the route would be a response that ends
// every 29 seconds with whatever was buffered, and EventSource, which is the
// client the reference wrote the route for, reconnects on a dropped connection
// automatically and forever. The deployment would therefore be paying for a
// held-open invocation per client per 29 seconds (docs/cost-model.md §3.1
// prices a connection-hour at USD 0.024 at 512 MB) to deliver frames late, in
// batches, with a reconnect storm as the steady state. That is not SSE and it
// is not a degraded SSE either; it is a spinner that bills.
//
// So DisableStream is set unconditionally, whatever tools.stream.enabled says,
// and the route answers 404 — which is the reference's own answer for a route
// the host did not mount and, more to the point, is the one status EventSource
// treats as terminal: the specification fails the connection on any status but
// 200 and does not reconnect. A client discovers the absence at once instead of
// by watching a spinner. The knob is reported by unwiredKnobs at every cold
// start so that nobody has to work this out from behaviour, and the transport
// that makes the route real — a Lambda Function URL with response streaming and
// an SseDistributor, mandatory there because every connection is its own
// execution environment — is D9c's, which turns this one field off. It is the
// registered deviation tools-stream-is-not-mounted-on-api-gateway.
//
// tools.sse.enabled is honoured as far as it can be: the facade is built with
// the in-process manager, so Notify's `sse` channel and Track's step 3 broadcast
// to whatever connections the manager holds, which on this runtime is none.
// That is stated in the cold-start log rather than refused, because the manager
// costs nothing and D9c makes it reach somebody. What *is* refused — RS-14 — is
// a distributor, because a document that names one has asked for cross-instance
// delivery and this build cannot provide it.
//
// ── the access posture ───────────────────────────────────────────────────────
//
// The core mounts nothing until the host has said who may reach the guarded
// routes (tools-router-requires-an-explicit-guard-decision), and this product
// says it from tools.auth — which a tools document has to write. An unset
// tools.auth under tools.enabled is refused by internal/config (RS-16), because
// the alternative is that silence resolves to one of the four postures, and the
// only one the reference would pick for it is the open door: "forgetting
// tightens rather than loosens" (internal/config/config.go) has no tighter
// reading of an absent guard than a refusal. toolsAccess therefore has no
// default branch that mounts anything.
//
// `session` is two middleware in one chain, each of which the reference's host
// gets from auth.middleware() and the core's bare mount does not supply:
//
//   - the double-submit check. The reference performs it INSIDE its auth
//     middleware (auth.middleware.ts:33-41), so a tools router guarded by
//     auth.middleware() answers 403 CSRF_INVALID to a cookie-authenticated POST
//     with no X-CSRF-Token. The core splits the two — nethttp's Middleware only
//     authenticates, and CSRFMiddleware scopes itself to paths under the api
//     prefix (csrf.go, csrfEnforced) — and mounts the tools handler bare, saying
//     in so many words that a cross-site form post "is the first thing a host's
//     authMiddleware is there to stop" (tools.go). This product is that host.
//     toolsDoubleSubmit reproduces the reference's condition exactly: csrf
//     enabled, an unsafe method, no bearer credential, an access-token cookie
//     present. It matters more here than under the api prefix, because the
//     tools body decoder ignores Content-Type, so without it a no-preflight
//     text/plain POST from any same-site page (any page at all under
//     cookies.sameSite: none) would carry a full JSON body on the victim's
//     cookie.
//   - the adapter's own Middleware — the same guard GET <prefix>/sessions sits
//     behind — which authenticates the token and puts the principal on the
//     context, where POST <tools>/track reads it as the fallback userId.
//
// And that is all `session` is, which is why it is NOT the ordinary posture
// here and NOT the SAM template's default. Who holds a session is the host's
// business in a library; this product has already decided it — POST
// <prefix>/register is always mounted (upstream register-route-is-always-mounted)
// — so under `session` "authenticated" means "anyone on the internet who filled
// in the form". What such a caller can then do is the reference's own shape and
// is reproduced, not narrowed: GET <tools>/telemetry is store-wide
// (tools_telemetry.go says so at length — ?userId=someone-else is honoured and
// no filter means everyone), and the bridge above writes every identity.* event
// into that store — the email an account was created with, both addresses of an
// email change, whatever was typed into the email field of a failed login, and
// the IP, user agent and session id of each; POST <tools>/track reads userId
// from the body first and the principal second (tools.router.ts:147), so a
// session attributes an event to any user and fires every matching outgoing
// webhook, signed in this deployment's name. Scoping the query to the caller
// and pinning the body's userId were both considered and rejected: each would
// be an auth semantic the reference does not have, silently changing what a
// client written against the reference gets back, and neither would close the
// door — the event name and the payload stay the caller's. So the posture is
// priced instead: in the config reference (§17.6), in a cold-start warning
// (logToolsSurface), and in the template, whose default is `apiKey`. `session`
// is for a deployment whose registration is closed or whose end users are the
// intended audience of their own login history.
//
// `apiKey` is the core's APIKeyMiddleware over the deployment's API-key store,
// for a caller that is a service rather than a person. Two things about it are
// the core's and are said out loud: it requires no scope — the schema has no
// vocabulary for one, so every active key in the store opens the whole tools
// surface, whatever it was minted for — and its refusal is a bare text/plain
// 401, not the reference's {error, code} envelope (registered:
// tools-api-key-refusal-is-the-cores-bare-401). `none` is the reference's
// default, reachable here by name (auth.ToolsPublic) and by nothing else, and
// the config reference prices it the way the core does: POST <tools>/track
// takes userId, tenantId and sessionId from the body and only falls back to
// the principal, so an anonymous caller attributes an event to any user, and
// Track fans that attribution out to the telemetry store, to that user's
// stream and to every matching outgoing webhook, which the deployment then
// POSTs to a third party in its own name and under its own signature. `admin`
// puts the routes behind the admin console's guard, which D8 builds; until it
// lands the posture is refused at cold start rather than silently degraded,
// and internal/config already refuses it without admin.enabled.
//
// ── the two seams left empty on purpose ──────────────────────────────────────
//
// WebhookSender is the default in-process HTTP deliverer. The core made
// WebhookDeliverer the transport seam so that a deployment can queue deliveries
// instead of sending them inline, and on this runtime it must: the emitter
// delivers on a detached goroutine and returns, and a Lambda freezes the
// execution environment the moment the response is written, so a delivery that
// has not completed by then completes — if the same environment is ever thawed
// — on some later invocation, and the retry schedule (one, two and four seconds
// between attempts) is almost never honoured. D9b replaces the deliverer with
// one that enqueues a signed, numbered WebhookAttempt on SQS and lets a worker
// reproduce the schedule from Retries() and RetryDelay(). Until then delivery
// is best-effort, the register says so
// (outgoing-webhook-delivery-races-the-response), and docs/cost-model.md
// records what it costs.
//
// ScriptRunner is nil. The core runs no inbound-webhook script in process and
// fails closed without a runner — 400, nothing tracked, and the provider
// redelivers — so RS-15 refuses tools.inboundWebhooks.enabled until D9d brings
// the runner: a Lambda of its own whose IAM role is the sandbox. The
// scriptTimeoutMs knob is mapped onto ScriptTimeout now so that D9d's change is
// one field.

// toolsWiring is what the tools block builds before the core exists: the bus
// the core will publish on, the facade the router will call, and the handle
// that stops the bridge. Nil when tools.enabled is off, and every consumer
// treats nil as "no tools block".
type toolsWiring struct {
	// bus is the core's: what auth.WithEventBus hands over and what the
	// service layer publishes on. The facade's bus is a different value, held
	// by the facade alone (tools.Events); see the file header for why the two
	// must not be one.
	bus   *auth.EventBus
	tools *auth.AuthTools

	// stopBridge cancels the bridge subscription. Nothing in the Lambda
	// entrypoint calls it — the bridge lives as long as the process — but a test
	// that builds several Apps in one process should not leave subscriptions
	// behind, and App.Close is where they go.
	stopBridge func()

	// The stores that were wired, by name, for the cold-start log.
	telemetry bool
	webhooks  bool
}

// telemetryStoreProvider, webhookStoreProvider and apiKeyStoreProvider are what
// this binary needs from a driver to back the three stores the tools block
// consumes, found structurally on the user store for the reasons
// settingsStoreProvider gives. The DynamoDB store exposes all three as
// accessors; the memory bundle grows them in this block so the development
// driver backs the same set as the production one.
type telemetryStoreProvider interface {
	Telemetry() auth.TelemetryStore
}

type webhookStoreProvider interface {
	Webhooks() auth.WebhookStore
}

type apiKeyStoreProvider interface {
	APIKeys() auth.APIKeyStore
}

// checkToolsSupport refuses, before any store is opened, the one tools posture
// this build cannot build: `admin`, whose guard is the admin console's and
// arrives with D8. internal/config has already refused the posture without
// admin.enabled; this is the refusal for the build that has the knob and not
// the console. When D8 lands, this function is where its guard's Protect is
// handed to toolsAccess and the refusal is deleted.
func checkToolsSupport(cfg *config.Config) error {
	if !cfg.Tools.Enabled {
		return nil
	}
	if cfg.Tools.Auth == config.ToolsAuthAdmin {
		return fmt.Errorf(
			"config: refusing to start: tools.auth is %q, but this build mounts no admin console and so has no admin guard to put the tools routes behind (it lands with D8) -- choose tools.auth: session or apiKey until then",
			config.ToolsAuthAdmin)
	}
	return nil
}

// newToolsWiring builds the bus and the facade, or returns nil when the block
// is off.
//
// It runs after the delivery transports and before the core, like newDelivery,
// because the facade wants the mail and SMS transports and the core wants the
// bus. It can refuse for a driver that lacks a store the document enabled,
// exactly as emailOptions refuses for one with no template store — a refusal
// that cannot happen on the two drivers this build ships, and stays because
// the next driver is the one it is for.
func newToolsWiring(ctx context.Context, cfg *config.Config, users auth.UserStore, deliver *delivery, client *http.Client, log *slog.Logger) (*toolsWiring, error) {
	if !cfg.Tools.Enabled {
		return nil, nil
	}

	opts := auth.AuthToolsOptions{
		WebhookVersion: cfg.Tools.OutboundWebhooks.PayloadVersion,
		// The default deliverer, over the client every outbound request of this
		// binary goes through, so a delivery carries the caller's correlation
		// id like the delivery webhook and the claims webhook do — for a
		// tracked event because the emitter keeps the request context's values
		// (context.WithoutCancel), and for a bridged one because the bridge
		// below puts the event's own provenance back on the context it hands
		// Track. D9b replaces this one field with a deliverer that enqueues;
		// see the file header.
		WebhookSender: &auth.WebhookSender{Deliverer: &auth.HTTPWebhookDeliverer{Client: client}},
		// Notify's email and SMS channels resolve the recipient through the
		// user store and send on the transports the credential routes send on.
		// Neither channel is reachable over HTTP: the reference's POST /notify
		// never reads `channels` (tools.router.ts:168-176) and the core
		// reproduces that, so over the wire every notification is SSE-only and
		// these two fields serve a library caller holding the facade. They are
		// wired anyway, because the facade is exported through App.Tools and a
		// host embedding this package is exactly such a caller.
		Users: users,
		Mail:  deliver.mail,
		SMS:   deliver.sms,
		// Every failure the facade swallows — a telemetry write, a webhook
		// lookup or delivery, a notification body — reaches the structured log
		// here. The core's default is the reference's silence.
		//
		// Through scrubbedWebhookError, and that is not optional. The core's
		// HTTP deliverer returns client.Do's error unchanged and the sender
		// wraps it with %w, so a failed delivery arrives here as a *url.Error
		// whose text is `Post "<the whole URL>": <cause>` — path and query
		// included, which is where a Slack- or Zapier-style receiver keeps its
		// capability token. The redaction list in logging.go works by attribute
		// key and this key is `error`, so nothing downstream would catch it,
		// and with the bridge on a receiver that is slow or down would have its
		// token written to CloudWatch once per login. delivery.go argues the
		// same leak for the two credential webhooks; this is the third path
		// into the same log. No configured value is passed because the facade
		// reports per failure and not per subscription: it is the *url.Error's
		// own URL that is cut down to its origin.
		OnError: func(err error) {
			log.Warn("tools fan-out", slog.String("error", scrubbedWebhookError(err, "").Error()))
		},
	}

	tw := &toolsWiring{bus: auth.NewEventBus()}

	if cfg.Stores.Enable.Telemetry {
		provider, ok := users.(telemetryStoreProvider)
		if !ok || provider.Telemetry() == nil {
			return nil, fmt.Errorf(
				"config: refusing to start: stores.enable.telemetry is on, but the %s driver does not provide a telemetry store in this build, so every tracked and bridged event would be dropped and GET %s/telemetry would answer 404 -- turn it off until the driver grows one",
				cfg.Stores.Driver, toolsPath(cfg))
		}
		opts.Telemetry = provider.Telemetry()
		tw.telemetry = true
	}

	if cfg.Stores.Enable.Webhooks {
		provider, ok := users.(webhookStoreProvider)
		if !ok || provider.Webhooks() == nil {
			return nil, fmt.Errorf(
				"config: refusing to start: stores.enable.webhooks is on, but the %s driver does not provide a webhook store in this build, so no outgoing webhook could ever match an event -- turn it off until the driver grows one",
				cfg.Stores.Driver)
		}
		opts.Webhooks = webhookDefaults{
			WebhookStore: provider.Webhooks(),
			maxRetries:   cfg.Tools.OutboundWebhooks.Defaults.MaxRetries,
			retryDelayMs: cfg.Tools.OutboundWebhooks.Defaults.RetryDelayMs,
		}
		tw.webhooks = true
	}

	if cfg.Tools.SSE.Enabled {
		opts.SSE = true
		opts.SSEOptions = []auth.SseOption{
			// The reference's "<= 0 disables the heartbeat" is the core's
			// WithSseHeartbeat(0); validate.go accepts any integer here.
			auth.WithSseHeartbeat(time.Duration(cfg.Tools.SSE.HeartbeatIntervalMs) * time.Millisecond),
			auth.WithSseDeduplicate(cfg.Tools.SSE.Deduplicate),
			// No WithSseDistributor. RS-14 has refused any document that named
			// one, and the in-process manager reaches the connections of this
			// execution environment alone — which, with the stream unmounted,
			// is none. D9c adds the distributor here.
		}
	}

	// The facade's context bounds the distributor subscription and nothing
	// else, and there is no distributor; the bridge's context is handed to
	// every sink on every event and must outlive the cold start. See the file
	// header for why neither may be the startTimeout context main.go passes.
	lifetime := context.WithoutCancel(ctx)

	// The facade's own bus, private to it: Track publishes here at step 2 and
	// nothing subscribes, which is what makes the subscription below unable to
	// hear its own output. The core's bus is tw.bus, a different value.
	tools, err := auth.NewAuthTools(lifetime, auth.NewEventBus(), opts)
	if err != nil {
		return nil, fmt.Errorf("tools: %w", err)
	}
	tw.tools = tools

	// The bridge: every event the core raises goes through Track, with its own
	// name, payload and identifiers, so a bridged event and a tracked one are
	// one kind of thing to every sink. Not tools.Bridge — see the file header.
	// The provenance is passed explicitly because Track's ctx fill-in reads a
	// request carrier this lifetime context does not have; PublishContext put
	// the values on the event itself when the service published it.
	//
	// And it is put back on the context as well, for the one reader that looks
	// there and nowhere else: correlatingTransport (logging.go) sets
	// X-Correlation-Id on an outbound request from the carrier on that
	// request's context, and the emitter builds each delivery from the context
	// Track was given. Without the carrier a bridged delivery would leave with
	// no correlation header while a tracked one carried it — two kinds of
	// delivery where the register promises one. The subscriber is handed the
	// event and no context of its own, so the carrier is rebuilt from the three
	// fields the event kept. TestBridgeDeliversEachLoginOnce asserts the header
	// on the bridged delivery.
	tw.stopBridge = tw.bus.Subscribe(auth.EventBusWildcard, func(ev auth.Event) {
		ctx := auth.ContextWithEventContext(lifetime, auth.EventContext{
			CorrelationID: ev.CorrelationID,
			IP:            ev.IP,
			UserAgent:     ev.UserAgent,
		})
		tools.Track(ctx, ev.Name, ev.Data, auth.TrackOptions{
			UserID:        ev.UserID,
			TenantID:      ev.TenantID,
			SessionID:     ev.SessionID,
			CorrelationID: ev.CorrelationID,
			IP:            ev.IP,
			UserAgent:     ev.UserAgent,
		})
	})
	return tw, nil
}

// webhookDefaults applies tools.outboundWebhooks.defaults to every subscription
// the store returns with no value of its own, so that a row saved without
// maxRetries or retryDelayMs is retried on the deployment's schedule rather than
// on the core's built-in one. The core's WebhookConfig.Retries and RetryDelay
// read a nil pointer as the reference's literals (3 and 1000 ms,
// webhook-sender.ts:18-19); this fills the pointer before they look, which is
// what the schema means by "per-webhook rows may override them" (§1.15). A row
// that carries its own value is left alone. With the schema defaults, which
// equal the core's, it is the identity.
//
// It decorates FindByEvent alone. The same store is also the InboundWebhookStore
// the inbound route consults, and that is handed over undecorated: retries are
// an outgoing concern and the inbound row's fields are not touched.
type webhookDefaults struct {
	auth.WebhookStore
	maxRetries   int
	retryDelayMs int
}

func (w webhookDefaults) FindByEvent(ctx context.Context, event, tenantID string) ([]auth.WebhookConfig, error) {
	configs, err := w.WebhookStore.FindByEvent(ctx, event, tenantID)
	if err != nil {
		return nil, err
	}
	for i := range configs {
		if configs[i].MaxRetries == nil {
			retries := w.maxRetries
			configs[i].MaxRetries = &retries
		}
		if configs[i].RetryDelayMs == nil {
			delay := w.retryDelayMs
			configs[i].RetryDelayMs = &delay
		}
	}
	return configs, nil
}

// toolsOptions fills the `tools` slot of coreOptionSets: the bus, and nothing
// else, because the facade and the router reach the core through HTTPConfig
// and not through an option. With the block off it contributes nothing and
// says so, the way settingsOptions does.
func toolsOptions(tw *toolsWiring, cfg *config.Config, log *slog.Logger) []auth.Option {
	if tw == nil {
		log.Info("tools surface not wired",
			slog.String("path", "tools.enabled"),
			slog.String("effect", "no event bus is built, so the auth core's identity.* events go nowhere, and every path under "+toolsPath(cfg)+" answers 404"))
		return nil
	}
	return []auth.Option{auth.WithEventBus(tw.bus)}
}

// toolsHTTPOptions builds HTTPConfig.Tools: the router's options, with the
// access decision resolved against the core that now exists.
//
// It takes the core and the base HTTPConfig because two of the four postures
// are middleware built from them — the adapter's own Middleware for `session`,
// which needs the core to authenticate against and the cookie conventions to
// read the token with. It cannot therefore live inside httpConfig, which is a
// pure function of the document, and is passed to mountAuthSurface beside the
// rate limiter for the same reason that one is.
func toolsHTTPOptions(cfg *config.Config, tw *toolsWiring, core *auth.Auth, base auth.HTTPConfig, users auth.UserStore) (auth.ToolsOptions, error) {
	if tw == nil {
		// Enabled false: the adapter registers nothing under the path. The zero
		// value already says so, and returning it rather than half-filling it
		// keeps ToolsMounted's three conditions readable from one field.
		return auth.ToolsOptions{}, nil
	}
	access, err := toolsAccess(cfg, core, base, users)
	if err != nil {
		return auth.ToolsOptions{}, err
	}

	opts := auth.ToolsOptions{
		Enabled:   true,
		Path:      cfg.Tools.BasePath,
		AuthTools: tw.tools,
		Access:    access,
		// The polarity flip: the core spells the four flags as Disable* so its
		// zero value is the reference's all-on default, and the schema spells
		// them as enabled because a document reads better that way.
		DisableTelemetry: !cfg.Tools.Telemetry.Enabled,
		DisableNotify:    !cfg.Tools.Notify.Enabled,
		// Unconditional. See the file header: behind API Gateway the stream is
		// a spinner that bills, and 404 is the one answer EventSource does not
		// retry. D9c sets this from tools.stream.enabled on a transport that
		// can carry it.
		DisableStream:  true,
		DisableWebhook: !cfg.Tools.InboundWebhooks.Enabled,
		// The router's own documentation pair, resolved the way docs.go
		// resolves the auth router's: `docs.swagger` is three-valued and
		// DocsOptions.Enabled is a bool. Same knob, same environment, so a
		// deployment that serves one pair serves both. BasePath is left empty,
		// which the core reads as the tools mount itself.
		Docs: auth.DocsOptions{Enabled: docsEnabled(cfg)},
		// GET <tools>/telemetry reads the same store Track writes; the core
		// allows a different one for a read replica, which this product has no
		// knob for. Nil when the store is off, which unmounts the query route.
		TelemetryStore: telemetryStoreOf(users, cfg),
		// The inbound route's store, handed over so that D9d's change is the
		// runner alone. With DisableWebhook set — which RS-15 guarantees on
		// this build — the field is read by nothing.
		InboundWebhooks: inboundWebhookStoreOf(users, cfg),
		ScriptRunner:    nil, // D9d. See the file header.
		ScriptTimeout:   time.Duration(cfg.Tools.InboundWebhooks.ScriptTimeoutMs) * time.Millisecond,
		// WebhookMaxBytes at the core's default (express.json's 100 KB): the
		// schema has no knob for it.
	}
	return opts, nil
}

// telemetryStoreOf returns the store the query route reads, which is the store
// the facade writes: the same value, found the same way, or nil when
// stores.enable.telemetry is off.
func telemetryStoreOf(users auth.UserStore, cfg *config.Config) auth.TelemetryStore {
	if !cfg.Stores.Enable.Telemetry {
		return nil
	}
	if provider, ok := users.(telemetryStoreProvider); ok {
		return provider.Telemetry()
	}
	return nil
}

// inboundWebhookStoreOf returns the webhook store narrowed to the inbound
// route's one method, or nil when the store is off or cannot answer it.
func inboundWebhookStoreOf(users auth.UserStore, cfg *config.Config) auth.InboundWebhookStore {
	if !cfg.Stores.Enable.Webhooks {
		return nil
	}
	provider, ok := users.(webhookStoreProvider)
	if !ok {
		return nil
	}
	inbound, ok := provider.Webhooks().(auth.InboundWebhookStore)
	if !ok {
		return nil
	}
	return inbound
}

// toolsAccess resolves tools.auth onto the core's access decision. Every
// branch returns a non-nil *ToolsAccess or an error: the nil that means "not
// configured" to the core is exactly the state this product refuses to be in,
// because validate.go has already established that the knob holds one of the
// four spellings and each of them is a decision.
func toolsAccess(cfg *config.Config, core *auth.Auth, base auth.HTTPConfig, users auth.UserStore) (*auth.ToolsAccess, error) {
	switch cfg.Tools.Auth {
	case config.ToolsAuthSession:
		// Two middleware, outermost first; the file header argues each.
		//
		// The double-submit check, where the reference has it: ahead of token
		// verification, for a cookie caller only (auth.middleware.ts:33-41).
		//
		// The adapter's own guard: the access token from the bearer header or
		// the cookie, verified through Auth.Authenticate, the principal put on
		// the context where POST /track reads it as the fallback userId. Built
		// from the same resolved configuration the adapter mounts with, so the
		// cookie it reads is the cookie the login route set.
		//
		// Nothing else: the routes behind the guard are the reference's, and
		// what a session may do with them is priced (header, §17.6), not
		// narrowed.
		authenticate := nethttp.NewWithConfig(core, base).Middleware()
		csrf := toolsDoubleSubmit(cfg.Security.CSRF.Enabled)
		return auth.ToolsProtected(func(next http.Handler) http.Handler {
			return csrf(authenticate(next))
		}), nil

	case config.ToolsAuthAPIKey:
		// The core's API-key guard: X-Api-Key or "Authorization: ApiKey …",
		// verified against the store by prefix and bcrypt, with the record's
		// own IP allowlist and expiry. No scopes are required, because the
		// schema has no vocabulary for them — which means that EVERY active key
		// in the store passes, including one an administrator minted with a
		// narrow scope for some other purpose: nil is "no requirement" to the
		// core's hasScopes, not "no scope". Today the tools guard is the store's
		// only consumer in this product, so every key is a tools key by
		// construction; the config reference says so (§17.6) so that it stays a
		// stated fact on the day D8 gives the store a second consumer. The
		// refusal it writes is the core's bare 401 and is registered
		// (tools-api-key-refusal-is-the-cores-bare-401). The store is
		// guaranteed by checkStoreRequirements and driverStores; the assertion
		// is the refusal for a driver that lacks it.
		provider, ok := users.(apiKeyStoreProvider)
		if !ok || provider.APIKeys() == nil {
			return nil, fmt.Errorf(
				"config: refusing to start: tools.auth is %q, but the %s driver does not provide an API-key store in this build, so no key could ever be verified and every tools call would answer 401",
				config.ToolsAuthAPIKey, cfg.Stores.Driver)
		}
		return auth.ToolsProtected(auth.APIKeyMiddleware(provider.APIKeys(), nil)), nil

	case config.ToolsAuthAdmin:
		// Unreachable: checkToolsSupport refused it before any store was
		// opened. Kept as a branch so that D8's guard has a named place to go.
		return nil, fmt.Errorf("config: refusing to start: tools.auth %q has no guard in this build", config.ToolsAuthAdmin)

	case config.ToolsAuthNone:
		// The reference's default, and here only ever the literal: the
		// document wrote `none`. collectWarnings has already warned about it at
		// load time and logToolsSurface repeats the price.
		return auth.ToolsPublic(), nil

	default:
		// The empty string, or a spelling validate.go does not know. Both are
		// refused by internal/config before this function can run — an unset
		// tools.auth under tools.enabled is RS-16 there — so this branch
		// is the second lock on the same door and not a code path. It returns
		// an error rather than ToolsPublic because a default branch that
		// mounts the open door is precisely how silence becomes a posture: the
		// core's tools.go exists to prevent "a configuration that silently
		// degrades from guarded to open", and the product's own rule is that
		// forgetting tightens. TestToolsAccessRefusesAnUnsetPosture pins it.
		return nil, fmt.Errorf(
			"config: refusing to start: tools.enabled is on and tools.auth is %q, which names no access posture -- write tools.auth: session, apiKey or admin, or tools.auth: none to get the reference's unguarded routes by name",
			cfg.Tools.Auth)
	}
}

// toolsDoubleSubmit is the CSRF half of the reference's auth middleware, for
// the tools mount, which the core's CSRFMiddleware does not cover.
//
// The condition is the reference's, clause for clause
// (auth.middleware.ts:33-41): csrf enabled, the method is not GET, HEAD or
// OPTIONS, the credential did not come from an Authorization: Bearer header,
// and there is an access-token cookie to have come from instead. The last
// clause is the reference's ordering made explicit — its middleware answers
// "No access token provided" before it ever reaches the CSRF branch, so a
// caller with no credential at all is the authenticating guard's to refuse,
// with that guard's own literal, and is passed through here. A bearer caller
// is exempt because a cross-site page cannot set the header; a declared
// X-Auth-Strategy is not a credential and exempts nothing, which is the
// core's own reading (csrf.go, usingBearerCredential).
//
// The refusal is the core's HTTPErrCSRFInvalid, which is the reference's
// 403 {"error":"CSRF token validation failed","code":"CSRF_INVALID"}, written
// through the same writer every route under the api prefix uses. The cookie is
// read through auth.CookieValue, so the __Host- and __Secure- spellings resolve
// as they do everywhere else, and under the core's default names: httpConfig
// sets neither CSRF.CookieName nor CSRF.HeaderName, so resolve() fills in
// exactly these two constants for the routes under the prefix.
//
// It distributes nothing. The CSRF cookie is set by the auth router's
// middleware on any request under the api prefix — a browser that holds an
// access-token cookie got it from POST <prefix>/login, which set both — and a
// tools response that set cookies would break the contract case that a bearer
// call sets none.
//
// With csrf off it is the identity, as the core's is: RS-3 refuses that in
// production, and outside production it is the operator's stated choice.
func toolsDoubleSubmit(enabled bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}
			if auth.BearerToken(r.Header.Get("Authorization")) != "" ||
				auth.CookieValue(r, auth.AccessTokenCookieName) == "" {
				next.ServeHTTP(w, r)
				return
			}
			cookie := auth.CookieValue(r, auth.CSRFTokenCookieName)
			header := strings.TrimSpace(r.Header.Get(auth.CSRFHeaderName))
			if cookie == "" || header == "" ||
				subtle.ConstantTimeCompare([]byte(cookie), []byte(header)) != 1 {
				auth.WriteHTTPError(w, auth.HTTPErrCSRFInvalid)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// toolsPath is the mount the adapter will use, resolved the way the core
// resolves it, so a log line and a refusal name the path a client would hit.
func toolsPath(cfg *config.Config) string {
	return auth.HTTPConfig{Tools: auth.ToolsOptions{Path: cfg.Tools.BasePath}}.ToolsPath()
}

// logToolsSurface announces what the block resolved to, so an operator can tell
// from the cold-start log which tools routes exist, behind what, fed by which
// stores — and which two things this runtime does not do yet.
func logToolsSurface(cfg *config.Config, tw *toolsWiring, log *slog.Logger) {
	if tw == nil {
		// toolsOptions has already said the block is off, at the point the
		// core was built.
		return
	}
	mount := toolsPath(cfg)

	// Never empty here: internal/config refuses an unset tools.auth under
	// tools.enabled and toolsAccess refuses it again, so the posture logged is
	// the posture the document wrote.
	posture := cfg.Tools.Auth
	log.Info("tools surface mounted",
		slog.String("mount", mount),
		slog.String("auth", posture),
		slog.Bool("telemetryStore", tw.telemetry),
		slog.Bool("webhookStore", tw.webhooks),
		slog.Bool("sseManager", cfg.Tools.SSE.Enabled),
		slog.Bool("track", cfg.Tools.Telemetry.Enabled),
		slog.Bool("notify", cfg.Tools.Notify.Enabled),
		slog.Bool("telemetryQuery", cfg.Tools.Telemetry.Enabled && tw.telemetry),
		slog.Bool("docs", docsEnabled(cfg)),
		slog.String("bridge", "on: every identity.* event the auth core raises is persisted to the telemetry store and delivered to every matching outgoing webhook"),
		slog.String("stream", "not mounted on this runtime: GET "+mount+"/stream answers 404 whatever tools.stream.enabled says, until D9c (deviation tools-stream-is-not-mounted-on-api-gateway)"),
		slog.String("outgoingWebhooks", "delivered in process on a detached goroutine, which a Lambda freezes with the response: best-effort until D9b (deviation outgoing-webhook-delivery-races-the-response)"))

	// What each guarded posture still costs, said where the operator reads what
	// came up rather than only in the config reference. The session line is a
	// warning, like the one for `none`, because the price is of the same kind
	// and only one registration form away: POST <prefix>/register is always
	// mounted, so "any signed-in user" is anyone. The apiKey line is not: a key
	// is minted by an administrator, and what it opens is the posture working
	// as documented.
	switch posture {
	case config.ToolsAuthSession:
		// The attribute is not called "csrf": that key is on the redaction
		// list (logging.go) and the sentence would be written as [REDACTED].
		log.Warn("the tools routes answer any signed-in user, and anyone can sign up",
			slog.String("path", "tools.auth"),
			slog.String("problem", "POST "+httpConfig(cfg).Prefix()+"/register is always mounted, so any self-registered user holds a session; a session may GET "+mount+"/telemetry with no filter and read every user's rows -- the bridge writes every identity.* event there, emails, IP addresses, user agents and session ids included -- may POST "+mount+"/track under any event name with any userId in the body, which fires every matching outgoing webhook signed in this deployment's name, and may POST "+mount+"/notify to any topic"),
			slog.String("remedy", "set tools.auth: apiKey (the SAM template's default) unless registration is closed or end users are meant to read each other's login history; see docs/config-reference.md §17.6"),
			slog.String("cookieCaller", csrfPostureOf(cfg)))
	case config.ToolsAuthAPIKey:
		log.Info("the tools routes answer any active API key",
			slog.String("path", "tools.auth"),
			slog.String("effect", "no scope is required, so every active key in the API-key store opens track, notify and the store-wide telemetry query, whatever it was minted for"),
			slog.String("refusal", "the core's text/plain 401, not the reference's {error, code} envelope (deviation tools-api-key-refusal-is-the-cores-bare-401)"))
	}
	if posture == config.ToolsAuthNone {
		log.Warn("the tools routes are unguarded",
			slog.String("path", "tools.auth"),
			slog.String("problem", "POST "+mount+"/track attributes an event to any user named in the body and fans it out to that user's stream and to every matching outgoing webhook, signed in this deployment's name; POST "+mount+"/notify broadcasts to any topic; GET "+mount+"/telemetry reads every event"),
			slog.String("remedy", "set tools.auth to session or apiKey unless the routes are deliberately public, for example behind a private network path"))
	}
	if cfg.Tools.SSE.Enabled {
		log.Info("the SSE manager reaches no connection on this runtime",
			slog.String("path", "tools.sse.enabled"),
			slog.String("effect", "the manager is built and Track and Notify broadcast into it, but the stream is not mounted and there is no distributor, so nothing is listening until D9c"))
	}
}

// csrfPostureOf is the sentence the cold-start log carries about a cookie
// caller under the session posture, in the two states security.csrf.enabled has.
func csrfPostureOf(cfg *config.Config) string {
	if cfg.Security.CSRF.Enabled {
		return "a cookie-authenticated POST needs the X-CSRF-Token double-submit, as under the api prefix; a bearer caller does not"
	}
	return "security.csrf.enabled is off, so a cookie-authenticated POST is accepted with no double-submit: any page the browser sends the session cookie from can drive track and notify"
}

// toolsKnobGaps reports the knobs around the tools block this build validates
// and that change nothing as the document stands.
//
// Two kinds. The stream and the SSE manager are runtime gaps — the core exposes
// the field, API Gateway cannot carry the response — and both close with D9c.
// The three store flags are the other kind: driverStores lists telemetry,
// webhooks and apiKeys as supported from this block on, because the tools block
// is what consumes them, and "supported" is a statement about the driver and
// not about the document. A flag switched on with its one consumer switched off
// therefore validates and is read by nothing — the state the comment on
// driverStores says that map exists to refuse. It is reported here rather than
// refused there because it is harmless and it is how a document is staged: an
// operator who enables the store one deploy before the block has not made an
// error, and D8 gives all three a second consumer, at which point these rows go.
func toolsKnobGaps(cfg *config.Config) []knobGap {
	var gaps []knobGap
	inert := func(flag string, on bool, consumer, remedy string) {
		if on {
			gaps = append(gaps, knobGap{
				Path:    "stores.enable." + flag,
				Problem: "the store is switched on and nothing in this build reads it: its only consumer is " + consumer,
				Remedy:  remedy,
			})
		}
	}
	if !cfg.Tools.Enabled {
		const remedy = "set tools.enabled: true to use it, or leave it set for the admin console (D8); until then it costs nothing and does nothing"
		inert("apiKeys", cfg.Stores.Enable.APIKeys, "the tools guard under tools.auth: apiKey, and tools.enabled is off", remedy)
		inert("telemetry", cfg.Stores.Enable.Telemetry, "the tools block, and tools.enabled is off", remedy)
		inert("webhooks", cfg.Stores.Enable.Webhooks, "the tools block, and tools.enabled is off", remedy)
		return gaps
	}
	if cfg.Tools.Auth != config.ToolsAuthAPIKey {
		inert("apiKeys", cfg.Stores.Enable.APIKeys,
			fmt.Sprintf("the tools guard under tools.auth: %s, and tools.auth is %q", config.ToolsAuthAPIKey, cfg.Tools.Auth),
			"set tools.auth: "+config.ToolsAuthAPIKey+" to put the tools routes behind it, or leave it set for the admin console (D8)")
	}
	mount := toolsPath(cfg)
	if cfg.Tools.Stream.Enabled {
		gaps = append(gaps, knobGap{
			Path: "tools.stream.enabled",
			Problem: "GET " + mount + "/stream is not mounted on this runtime and answers 404: API Gateway buffers the response and cuts it at 29 seconds, " +
				"which would turn a Server-Sent Events stream into a reconnect loop that bills a held-open invocation per client (deviation tools-stream-is-not-mounted-on-api-gateway)",
			Remedy: "leave it set; the stream lands on a Lambda Function URL with response streaming in D9c, and this knob becomes live then",
		})
	}
	if cfg.Tools.SSE.Enabled {
		gaps = append(gaps, knobGap{
			Path:    "tools.sse.enabled",
			Problem: "the SSE manager is built, but with the stream unmounted and no distributor it holds no connection, so every broadcast reaches nobody",
			Remedy:  "leave it set if the same document is deployed to another port in the family, or for D9c; nothing here is lost, and nothing here is delivered either",
		})
	}
	return gaps
}

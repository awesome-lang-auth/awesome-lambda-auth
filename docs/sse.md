# Server-Sent Events

`GET <tools>/stream` — the tools router's event stream — on this product: where
it is served, who can open it, what a client receives, and what it is promised
across a reconnect. The promise is the part that differs from the reference,
and it is registered as a deviation because it is a guarantee the reference
does not give (`sse-resume-replays-from-the-event-log`, `sse-event-ids-are-ulids`;
[deviations.md](deviations.md)). Configuration is
[config-reference.md](config-reference.md) §17.3; cost is
[cost-model.md](cost-model.md) §3.1; the item the log keeps is
[spec/data-model.md](spec/data-model.md) §1.5, "The SSE event log".

## 1. Where the stream is

Not on the auth function. API Gateway buffers a response and cuts it at 29
seconds, so behind it `GET <tools>/stream` answers `404`
(`tools-stream-is-not-mounted-on-api-gateway`). The stream is served by the
**SSE function**: the same artifact and the same configuration as the auth
function, started with a response-streaming entry point
(`AWESOME_AUTH_ENTRYPOINT=stream`) behind a Lambda **Function URL**. That
function answers `GET` on `<tools>/stream` and `404` to everything else —
`HEAD` and `OPTIONS` on the stream's own path included — from its outermost
handler, before the CORS layer, the access log or any route.

A client opens it at:

| CloudFront (`EnableCloudFront`) | URL |
|---|---|
| on | `https://<distribution><tools>/stream` — the same host as the auth routes on the distribution, which is what the family's clients assume when they build `<apiPrefix>/tools/stream` (set `ToolsBasePath` to `<apiPrefix>/tools` for them) |
| off | `https://<function-url-host><tools>/stream` — the `SseStreamUrl` stack output. That host is never a page's origin, and never the host the auth cookies were set for |

The two functions are joined by the **event log**: with
`tools.sse.distributor.type: dynamodb` the auth function's SSE manager writes
every broadcast — every tracked, bridged and notified event — to the table, and
the SSE function reads it for the connection it holds.

## 2. Who can open it — authentication, topology and topics

The route is the core's, and so is everything in front of it:

- `?token=<access token>` is copied into `Authorization: Bearer` before the
  guard (the reference's `extractSseToken`, `tools.router.ts:185-190`), so an
  `EventSource`, which cannot set a header, can authenticate. The copy
  **replaces** any `Authorization` header the request carried — the core does
  what the reference does (`tools_stream.go`, `ToolsSseTokenMiddleware`) — so
  a client that sends `Authorization: ApiKey …` must not also send `?token=`.
  A token in a URL is a token in logs and history; the core's `tools_stream.go`
  says what that costs, and this product's access log records the path only.
- The guard is the one `tools.auth` selects, exactly as on the auth function.
  The `apiKey` guard reads `X-Api-Key` or `Authorization: ApiKey …` and nothing
  else, so neither of an `EventSource`'s two credentials — `?token=`, which
  becomes `Bearer`, and the access-token cookie — passes it.
- The topics are decided by the server: `global`, `tenant:<tid>` and
  `user:<uid>` from the principal, intersected with `?topics=` when one is
  given (`StreamTopics`).

What that adds up to, by client and deployment. "Same origin" means the page is
served from the host the stream is opened on, which only CloudFront makes
possible; the access-token cookie is host-only (`__Host-`), so it reaches the
stream only where the stream is on the host that set it — the distribution.

| client | `tools.auth: session` | `tools.auth: apiKey` (the template's default) | `tools.auth: none` (not offered by the template) |
|---|---|---|---|
| browser `EventSource`, page on the same origin as the stream (CloudFront on) | yes: the cookie, or `?token=` | **no** | yes |
| browser `EventSource`, page on another origin, tools mount under the api prefix (`ToolsBasePath=<apiPrefix>/tools`) with the page's origin in `AllowedOrigins` | `?token=` only; the cookie does not reach the stream's host | **no** | yes |
| browser `EventSource`, page on another origin, tools mount beside the api prefix (`ToolsBasePath=/tools`, the default) | **no**: the mount is outside the CORS layer, as the reference's tools router is, so the response carries no `Access-Control-Allow-Origin` and the browser discards it | **no** | **no**, for the same reason |
| a service client (not a browser) | `Authorization: Bearer`, or `?token=` | `X-Api-Key` or `Authorization: ApiKey …`, **without** `?token=` | yes |

So a browser needs `session` (or `none`), and either CloudFront with the page
on the distribution, or the tools mount under the api prefix with the page's
origin allowed. With CloudFront off and the default mount, **no browser page on
any origin can use the stream**. The failure is not free either: the
specification treats a CORS failure as a network error, which an `EventSource`
re-establishes rather than fails, and each attempt is a `200` stream the
function cannot tell was discarded. `apiKey` is for non-browser clients.

The family's Angular client (`ng-awesome-node-auth`, `auth.service.ts`
`getToolsStream`) opens a relative, cookie-only
`` `${apiPrefix}/tools/stream` `` with `withCredentials`, so it works only with
CloudFront on, `ToolsBasePath=<apiPrefix>/tools`, `ToolsAuth=session` and the
page served from the distribution — and see §5 for what it does at a segment
end.

## 3. What a client receives

Every frame the reference writes, byte for byte: the `connected` frame first,
events as `id:` / `event:` / `data:` with the payload under `rawData`, and
`: heartbeat` every 30 seconds (`tools.sse.heartbeatIntervalMs`). An event
published to several topics — every tracked and bridged event is published to
`global` and `user:<id>` — is framed as the core frames it in process: once,
under the first of its topics in broadcast order (`global`, then `tenant:`,
then `user:`), whatever order `?topics=` lists them in, and once per topic
with `tools.sse.deduplicate: false`.

What is added:

1. **When the cursor could not be honoured as given**, one SSE comment line
   after the `connected` frame — discarded by every parser, there for the
   operator and for a client that wants to know:
   - `: replay truncated: events older than the retention are no longer held; resuming from the oldest one kept`
   - `: last event id not recognised; resuming from now`
2. **Always, one id-only frame** after the `connected` frame (and the comment):
   `id: <ULID>` and a blank line. It names the connection's starting cursor. It
   dispatches no event — the `EventSource` parser sets its last event ID
   *before* it discards a frame with no data — so no handler ever sees it; what
   it does is give a client that hears nothing for a whole segment a cursor to
   reconnect with, instead of the `connected` frame's UUID, which nothing can
   place. A raw parser that dispatches empty frames will see it as an event
   with no data and no type.
3. **When the replay limit cuts a replay** (§4), after the last replayed event:
   `: replay truncated: the replay reached <n> events and the rest was skipped; resuming from now`
   and an id-only frame naming the point the stream continues from, so the
   client's cursor moves past what was skipped.

Event ids are **ULIDs** (26 characters of Crockford base32, time-ordered), not
the reference's UUIDs, in the `id:` line and in the `id` inside `data:`. Treat
them as opaque; they sort by time, which is the whole reason. One consequence
is visible: on a tracked or bridged event, `rawData` is the telemetry record,
which keeps its own UUID, so the frame's `id` **no longer equals
`rawData.id`** as it does in the reference. A client that matches frames
against `GET <tools>/telemetry` rows matches on `rawData.id`.

## 4. The resume guarantee

A connection that presents a cursor — the `Last-Event-ID` header, which
`EventSource` sends on every reconnect, or `?lastEventId=` for a first
connection that wants one (the header wins, because `EventSource` reuses the
URL) — receives:

- **the events logged after the cursor on the topics it holds, oldest first,
  then the live stream.** The cursor's own event is never sent again.
- **at-least-once, and the window below the cursor.** When the cursor is an
  event's id, the first read also reaches three seconds below it — at most 32
  events a topic — because the reconnect at a segment end is exactly where an
  event can be lost otherwise: one whose write, from another execution
  environment, became visible below the cursor after the client had moved past
  it. That event is delivered on the reconnect. Anything else in the window may
  be delivered again, including an event raised in the three seconds before the
  client's first connection. A cursor that is a floor — the id-only frame's
  value, which names no event — has nothing below it and looks nowhere.
- **ordered by ULID**, per topic and across the topics of the connection. One
  publisher's events keep its order (the ULID clock is monotonic within a
  process). Two publishers' events are ordered by their clocks, which on Lambda
  agree to milliseconds.
- **late rather than never, within a bound.** Inside a connection, an event
  whose write becomes visible after a later one has been delivered — a slower
  `PutItem` from another execution environment, or an eventually-consistent
  read — is delivered when it becomes visible, out of order, provided that is
  within three seconds of the topic's newest event and among its last 32
  events. Past that it is not delivered on this connection, though it is in the
  log and a later cursor older than it would replay it.
- **within the retention.** `tools.sse.eventLogRetentionSeconds`, a day by
  default, is both the log's TTL and the replay horizon. A cursor older than
  that — the all-zero ULID among them — replays from the oldest event still
  held, after the first truncation comment.
- **up to the replay limit.** `tools.sse.replayLimit`, 100 events by default,
  bounds one resume. Past it the stream writes the cut's comment and id-only
  frame (§3) and continues live; the rest of the gap is skipped. The limit is
  what bounds what a cursor costs, because any caller the guard admits can
  write one.

A cursor that is not a well-formed ULID — the `connected` frame's UUID,
garbage — or one more than a minute in the future is answered with the "not
recognised" comment and a start from now. A well-formed ULID inside the
retention is taken at its word whoever minted it: nothing in a ULID says which
log wrote it, and the replay limit bounds what a foreign one costs. **A client
with no cursor starts from now**, which is the reference's only behaviour.

### What is not promised

- Exactly-once. Deduplicate on the id if it matters.
- **An event that never reached the log.** An event larger than 16 KiB, or
  whose `PutItem` failed or was throttled — the `global` partition takes a
  thousand write units a second, and a burst of large notifies can fill it —
  is not logged: the core's fallback for a failed publish is local delivery,
  and the auth function holds no connection, so it reaches no stream, live or
  on replay. The auth function logs `sse event not logged` for each one; it
  still reaches the telemetry store and the outgoing webhooks.
- Delivery of an event published to a topic no stream can hold. `session:<sid>`
  and `custom:<name>` topics are not written to the log at all: `StreamTopics`
  never grants them, so nobody could read them.
- The topic of a multi-topic event whose copies become visible in two different
  polls: the copy framed is the one read first.
- More than one connection per process. The SSE function holds one connection
  per execution environment, which is what a Function URL gives it; a host that
  serves the stream role from a long-lived server with several concurrent
  connections would deliver each connection's replay to all of them.

## 5. Segments

A Lambda invocation lives at most fifteen minutes (the SSE function's
`SseTimeout`, 900 s by default and at most). Five seconds before its end the
request context is cancelled, the stream returns, and the response ends
cleanly. A specification-conformant `EventSource` then fires an `error` event,
waits its retry delay — about three seconds in browsers — and reconnects with
`Last-Event-ID`, and the replay covers the gap. So a connection is a sequence
of segments.

**A client that treats the first `error` event as the end loses the stream at
the first segment end.** The family's Angular service does:
`getToolsStream` maps `onerror` to `subscriber.error(err)`, and the
Observable's teardown calls `es.close()` (`ng-awesome-node-auth`
`auth.service.ts:388-390`), so the reconnect never happens. Against the
reference that path runs only on a real failure; here it runs about fifteen
minutes after every connect. The client needs a change — ignore `error` while
`readyState` is `CONNECTING` — and until then its stream on this product lasts
one segment.

Past `SseReservedConcurrency` a new connection is refused `429` by Lambda. A
native `EventSource` does not reconnect after any status but `200`, so a
refused listener stays disconnected until the application recreates the
source; polyfills may retry. The same slots serve refusals: requests with no
credential, or with a wrong one, occupy a slot for the few milliseconds of
their refusal, so a flood of them can hold every slot and lock listeners out
with `429` (`config-reference.md` §17.3.3).

Behind CloudFront the origin read timeout is sixty seconds, so a quiet stream
needs its heartbeat: at the default thirty seconds it is kept open. A heartbeat
of zero or of sixty seconds or more is warned about at the SSE function's cold
start.

A client that falls more than a queue behind — the core's
`sse-slow-consumer-is-disconnected` — is disconnected, and resumes from its
last id like any other reconnect.

## 6. What the log holds, and who can read it

Every tracked and every bridged `identity.*` event is published to `global`
with the core's tracked record as its payload: the email the event carries, the
IP address, the user agent, the session id, the correlation id, the user id.
The log keeps it verbatim for the retention — a day by default, up to a week —
and the table's point-in-time recovery keeps it in backups for 35 days.

Every connection holds `global`. So every stream the guard admits watches
every user's logins live, with those fields, and can page back through the
retention with a hand-written cursor, `tools.sse.replayLimit` events a
connection. Under `tools.auth: session` that is **any self-registered user**;
under `none`, anyone on the internet. The SAM template's default, `apiKey`,
limits it to key holders. `config-reference.md` §17.6 prices each posture.

## 7. What it costs, in one line

A held connection is billed for as long as it is open, at the SSE function's
memory size — USD 0.006 an hour at the default 128 MB — whether or not anything
is sent; the poll adds a few percent on a quiet stream, and on a busy `global`
the reads of the events a listener is sent can pass the compute
(`cost-model.md` §3.1 has the formula). `SseReservedConcurrency`, 20 by
default, caps the number of simultaneous connections, and so the compute; it
does not cap the reads, and it does not cap refused requests, which share its
slots.

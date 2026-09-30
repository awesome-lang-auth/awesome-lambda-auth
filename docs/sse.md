# Server-Sent Events

`GET <tools>/stream` — the tools router's event stream — on this product: where
it is served, what a client receives, and what it is promised across a
reconnect. The promise is the part that differs from the reference, and it is
registered as a deviation because it is a guarantee the reference does not
give (`sse-resume-replays-from-the-event-log`, `sse-event-ids-are-ulids`;
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
function answers `GET` (and `HEAD`, `OPTIONS`) on `<tools>/stream` and `404` to
everything else.

A client opens it at:

| CloudFront (`EnableCloudFront`) | URL |
|---|---|
| on | `https://<distribution><tools>/stream` — same origin as the auth routes, which is what the family's clients assume when they build `<apiPrefix>/tools/stream` (set `ToolsBasePath` to `<apiPrefix>/tools` for them) |
| off | `https://<function-url-host><tools>/stream` — the `SseStreamUrl` stack output |

The two functions are joined by the **event log**: with
`tools.sse.distributor.type: dynamodb` the auth function's SSE manager writes
every broadcast — every tracked, bridged and notified event — to the table, and
the SSE function reads it for the connection it holds.

## 2. Authentication and topics — the reference's, unchanged

The route is the core's, and so is everything in front of it:

- `?token=<access token>` is copied into `Authorization: Bearer` before the
  guard (the reference's `extractSseToken`, `tools.router.ts:185-190`), so an
  `EventSource`, which cannot set a header, can authenticate. A token in a URL
  is a token in logs and history; the core's `tools_stream.go` says what that
  costs. The access-token cookie works too, and needs no `?token=` at all.
- The guard is the one `tools.auth` selects, exactly as on the auth function.
- The topics are decided by the server: `global`, `tenant:<tid>` and
  `user:<uid>` from the principal, intersected with `?topics=` when one is
  given (`StreamTopics`).

## 3. What a client receives

Every frame the reference writes, byte for byte: the `connected` frame first,
events as `id:` / `event:` / `data:` with the payload under `rawData`, and
`: heartbeat` every 30 seconds (`tools.sse.heartbeatIntervalMs`).

Two things are added, both after the `connected` frame and before anything
else:

1. **When the cursor could not be honoured as given**, one SSE comment line —
   discarded by every parser, there for the operator and for a client that
   wants to know:
   - `: replay truncated: events older than the retention are no longer held; resuming from the oldest one kept`
   - `: last event id not recognised; resuming from now`
2. **Always, one id-only frame**: `id: <ULID>` and a blank line. It names the
   connection's starting cursor. It dispatches no event — the `EventSource`
   parser sets its last event ID *before* it discards a frame with no data —
   so no handler ever sees it; what it does is give a client that hears
   nothing for a whole segment a cursor to reconnect with, instead of the
   `connected` frame's UUID, which nothing can place. A raw parser that
   dispatches empty frames will see it as an event with no data and no type.

Event ids are **ULIDs** (26 characters of Crockford base32, time-ordered), not
the reference's UUIDs, in the `id:` line and in the `id` inside `data:`. Treat
them as opaque; they sort by time, which is the whole reason.

## 4. The resume guarantee

A connection that presents a cursor — the `Last-Event-ID` header, which
`EventSource` sends on every reconnect, or `?lastEventId=` for a first
connection that wants one (the header wins, because `EventSource` reuses the
URL) — receives:

- **every event logged after the cursor on the topics it holds, oldest first,
  then the live stream.** The replay is exactly `SK > E#<cursor>`: nothing at
  or before the cursor is sent again.
- **at-least-once.** A reconnect never loses an event raised during the gap,
  provided the event is within the retention. An event can arrive twice: after
  a late delivery (below) the last id a client holds is older than events it
  already has, and a reconnect in that state replays them again.
- **ordered by ULID**, per topic and across the topics of the connection. One
  publisher's events keep its order (the ULID clock is monotonic within a
  process). Two publishers' events are ordered by their clocks, which on Lambda
  agree to milliseconds.
- **late rather than never.** An event whose write becomes visible after a
  later one has been delivered — a slower `PutItem` from another execution
  environment, or an eventually-consistent read — is delivered when it becomes
  visible, out of order, provided that is within three seconds of the newest
  event delivered. The one window where that is not covered is a reconnect in
  the same three seconds as such a write; the event is then in the log, and a
  later cursor older than it would replay it.
- **within the retention.** `tools.sse.eventLogRetentionSeconds`, a day by
  default, is both the log's TTL and the replay horizon. A cursor older than
  that replays from the oldest event still held, after the truncation comment.

A cursor this deployment did not mint — the `connected` frame's UUID, a value
from another deployment, garbage, a time more than a minute in the future — is
answered with the "not recognised" comment and a start from now. **A client
with no cursor starts from now**, which is the reference's only behaviour.

### What is not promised

- Exactly-once. Deduplicate on the id if it matters.
- Delivery of an event published to a topic no stream can hold. `session:<sid>`
  and `custom:<name>` topics are not written to the log at all: `StreamTopics`
  never grants them, so nobody could read them.
- More than one connection per process. The SSE function holds one connection
  per execution environment, which is what a Function URL gives it; a host that
  serves the stream role from a long-lived server with several concurrent
  connections would deliver each connection's replay to all of them.

## 5. Segments

A Lambda invocation lives at most fifteen minutes (the SSE function's
`SseTimeout`, 900 s by default and at most). Five seconds before its end the
request context is cancelled, the stream returns, and the response ends
cleanly. `EventSource` reconnects — after its own retry delay, about three
seconds in browsers — with `Last-Event-ID`, and the replay covers the gap. So a
connection is a sequence of segments, and the resume guarantee is what makes
that invisible.

Behind CloudFront the origin read timeout is sixty seconds, so a quiet stream
needs its heartbeat: at the default thirty seconds it is kept open. A heartbeat
of zero or of sixty seconds or more is warned about at the SSE function's cold
start.

A client that falls more than a queue behind — the core's
`sse-slow-consumer-is-disconnected` — is disconnected, and resumes from its
last id like any other reconnect.

## 6. What it costs, in one line

A held connection is billed for as long as it is open, at the SSE function's
memory size — USD 0.006 an hour at the default 128 MB — whether or not anything
is sent; the poll adds a few percent (`cost-model.md` §3.1). The number of
simultaneous connections is capped by `SseReservedConcurrency`, 20 by default,
which is also the cap on that bill.

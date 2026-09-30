# Cost model

What this stack costs, per month at rest and per request under load, with the
arithmetic shown. It exists because serverless cost is not observable by looking
at the thing: every resource here is either free when idle or billed per
operation, so the bill is a function of code paths, and the only way to know what
a path costs is to count what it does.

**How to read the numbers.** Prices are eu-west-1 at the time of writing and are
order-of-magnitude, not quotes — check the pricing pages before budgeting on
them. Latency and memory figures are measured, from the table in
[infra/sam/README.md](../infra/sam/README.md#measured-on-a-real-deployment): one
account, one region, one afternoon, arm64 at 512 MB. Operation counts are read
off the source and cited; where a count is a floor rather than an exact figure,
it says so.

Unit prices used throughout:

| | price |
|---|---|
| Lambda, arm64 | USD 0.0000133334 per GB-second + USD 0.20 per million requests |
| API Gateway HTTP API | USD 1.00 per million requests |
| DynamoDB on-demand | USD 1.25 per million write units, USD 0.25 per million read units |
| DynamoDB read units | 1 RRU per strongly consistent read up to 4 KB, 0.5 eventually consistent |
| DynamoDB write units | 1 WCU per 1 KB; **a transactional write is billed at 2 WCU per 1 KB per item** |
| CloudWatch Logs | USD 0.50 per GB ingested, USD 0.03 per GB-month stored |
| CloudWatch alarms | USD 0.10 per standard-resolution alarm metric per month, first 10 free |
| KMS asymmetric | USD 1.00 per key-month, USD 0.03 per 10 000 signatures |
| Secrets Manager | USD 0.40 per secret-month |

At 512 MB the Lambda duration charge is **USD 0.0000000066667 per millisecond**
(0.5 GB × 0.0000133334). That number does most of the work below.

---

## 1. Standing cost — what an idle stack costs per month

| Resource | USD / month | Why |
|---|---|---|
| `JwtSigningSecrets` | 0.40 | Both HS256 keys in one secret, so cold start makes one fetch |
| `JwtRefreshSecretSeed` | 0.40 | Generated the second key; still has to exist (README, "why two secret resources") |
| DynamoDB table, empty | ~0.00 | On-demand has no hourly charge. Storage ~0.25–0.31 /GB-month, PITR about the same again |
| DynamoDB stream, unconsumed | 0.00 | Enabled from day one; nothing at rest |
| Lambda, HTTP API | 0.00 | Purely per-request |
| CloudFront, if enabled | 0.00 | No hourly or monthly charge; the two policies are free |
| SSE function, `EnableSse=true` only (D9c) | 0.00 | Per connection-hour only (§3.1); its URL, permissions and CloudFront behaviour are free, and its alarm is the tenth metric (§3.3) |
| CloudWatch Logs storage | ~0.00 | At 14-day retention and this traffic, a few MB |
| **The nine alarms** | **0.00** | Nine alarm metrics enabled by default, against a free allowance of ten; each optional function adds its own, gated on its switch and counted in §3.3 |
| **SNS topic + subscription** | **0.00** | No charge at rest; first 1 000 email notifications a month are free |
| **The budget** | **0.00** | First two budgets per account are free; this is the second |
| **Cost anomaly detection** | **0.00** | Free |
| S3 artifact bucket | cents | A few MB per deployed version |
| KMS key, `EnableIdp=true` only | 1.00 | Billed whether or not it signs, **including its 7-day deletion window** |
| Admin uploads bucket, `EnableAdminUploads=true` only | cents | S3 Standard storage for a handful of images, USD 0.023 per GB-month; an empty bucket is free. Requests are §2.6 |
| Script runner, `EnableInboundWebhooks=true` only | 0.00 | A function, a role and a log group cost nothing at rest; its one alarm is counted with the other optional functions' in §3.3 |

**Total: USD 0.80 a month, or USD 1.80 with the identity provider on.** The
observability block adds **nothing** to that in an account with fewer than ten
other alarms, and **USD 0.90 a month** in one that has already spent the free
allowance — nine alarm metrics at USD 0.10; the optional functions' alarms are
counted in §3.3.

Two things are worth saying plainly about this table. The whole standing bill is
Secrets Manager and KMS, which are the two resources that exist to keep a signing
key out of reach; and **none of it is the risk**. A stack that costs USD 0.80 a
month at rest can cost USD 500 in an afternoon, and everything from §3 on is
about that gap.

---

## 2. Per-request cost of the paths that have one

### 2.1 The platform floor

Every request through the HTTP API, whatever it does:

```
API Gateway  1.00 / million
Lambda req   0.20 / million
             ────────────────
             1.20 / million, before the function does anything at all
```

Plus duration, plus logs. The access log writes one line per request and this
binary's own lines add to it; at roughly 600 bytes for the pair that is
**USD 0.30 per million requests of log ingestion**, which is a quarter of the
platform floor and is worth remembering before adding a field.

The `X-Correlation-Id` this product now logs adds about 30 bytes to each of those
two lines when a caller sends one — USD 0.03 per million requests. It is bounded
at 128 bytes for exactly this reason (`maxCorrelationIDBytes`, cmd/auth/logging.go):
a caller may send up to API Gateway's ~10 KB header limit, and an unbounded id
would be USD 5 per million requests of somebody else's log bill.

### 2.2 `POST /auth/login` — the expensive one, and not for the reason you would guess

Measured duration 301 ms at 512 MB, which is bcrypt and not the platform. Store
operations, counted off `internal/store/dynamodb`:

| operation | source | units |
|---|---|---|
| email pointer read, strongly consistent | `users.go` `GetUserByEmail` | 1 RRU |
| profile read, strongly consistent | `users.go` `GetUserByID` | 1 RRU |
| session + directory entry + refresh pointer, **one transaction** | `sessions.go` `CreateSession` | 3 items × 2 = 6 WCU |
| GSI1 entries for the session item and the directory entry | `sessions.go` `sessionItem`, `sessionIndexItem` | ≥ 2 WCU |
| rate-limiter counter, conditional update | `rate_limit.go` | 1 WCU |

**≈ 2 RRU and ≥ 9 WCU.** Per million logins:

```
API Gateway               1.00
Lambda requests           0.20
Lambda duration           2.01   (301 ms × 0.0000000066667 × 1e6)
DynamoDB writes          11.25   (9e6 WCU)
DynamoDB reads            0.50   (2e6 RRU)
CloudWatch Logs           0.30
                        ───────
                        ≈ 15.26 per million, or USD 0.0000153 a login
```

The finding is where the money is: **DynamoDB is three quarters of the cost of a
login, and six of its nine write units are one transaction.** Not bcrypt, which
is the thing that shows up in latency graphs, and not API Gateway. The
transaction is bought deliberately — a session whose directory entry or refresh
pointer could be missing is a session that is invisible or unrotatable — and this
is what it costs. Raising `MemorySize` to 1024 roughly halves the 301 ms for
about the same GB-ms bill, so it moves latency and not this table.

### 2.3 The rate limiter — 1 WCU per limited request, allowed **or** refused

D5's limiter is one conditional `UpdateItem` against an item well under 1 KB, and
DynamoDB **bills a conditional write whose condition fails**, so a refusal costs
the same write as an acceptance (`internal/store/dynamodb/rate_limit.go`).

That is the whole reason the in-process pre-filter exists: an execution
environment that has already seen the budget exhausted for a key refuses locally
and spends nothing. It is a saving, never the limit.

The consequence for an incident: a credential-stuffing run against `/login` is
billed at **USD 1.25 per million attempts in limiter writes alone**, plus the
platform floor, whether or not a single attempt succeeds. It is also why
`MaxWriteRequestUnits` is capped at 200 — the run becomes a DynamoDB throttle
before it becomes a bill — and why two of the nine alarms watch write capacity.

### 2.4 The hosted UI — two strongly consistent reads per page

D7 puts the settings store on the page-render path for the first time
(`cmd/auth/ui.go`). Every SSR page **and** every `GET <prefix>/ui/config` reads
the settings singleton and the templates partition, both strongly consistent
(`settings.go` `getSettingsItem`, `templates.go`), so:

**2 RRU per rendered page and per config fetch** = USD 0.50 per million, on top
of the platform floor. A login page that is loaded, then submits, then redirects
is three requests and about USD 0.0000048 of DynamoDB before the login itself.

### 2.5 The identity provider — `POST /token`

`kms:Sign` on an RSA-2048 key is USD 0.03 per 10 000, **≈ USD 3.00 per million
tokens signed**, and it is on `/token` and nowhere else: `/login` and `/refresh`
sign HS256 in process. `kms:GetPublicKey` is called once per execution
environment, not once per token. With the key's USD 1.00 a month, a million OIDC
tokens is about USD 4.00 — see the README's KMS table for the full breakdown.

### 2.6 Uploaded assets — one `GetObject` per logo fetch, misses included

D8 puts an S3 bucket behind `ui.uploadDir` (`internal/integration/aws/s3_uploads.go`),
and the read side is the part with a per-request cost: the hosted UI serves
`<prefix>/ui/assets/uploads/<name>` through the core's `UploadFS`, whose only
operation is `Open`, so **every request for an uploaded asset is one `GetObject`
— and a miss is a `GetObject` that answers 404**, billed the same. The write
side is an administrator's occasional click.

S3 Standard in eu-west-1, order of magnitude:

| operation | price | which route |
|---|---|---|
| `GetObject` | USD 0.0004 per 1 000 | every page view that fetches the logo or background, through the function |
| `PutObject` | USD 0.005 per 1 000 | `POST <admin>/api/upload/logo` and `/bg-image` |
| `ListObjectsV2` | USD 0.005 per 1 000 | `GET <admin>/api/upload/files` |
| `HeadObject` + `DeleteObject` | USD 0.0004 + free | `DELETE <admin>/api/upload/{name}` |
| storage | USD 0.023 per GB-month | a handful of images — cents |

A million page views that each fetch one logo are **USD 0.40 of S3** on top of
the platform floor, plus the function's own duration for the proxied bytes.
Per million requests that is a little more than the log-ingestion line and
about a thirtieth of a login's DynamoDB — worth knowing, not worth designing
around. There is no standing charge: the bucket costs nothing when empty and
the IAM statement nothing at all.

What was deliberately *not* done about it: caching the object per execution
environment, which would trade the `GetObject` for an upload that does not
appear until the next cold start, and setting an edge cache in front of the
path, which the CloudFront block refuses for every response from this origin
([infra/sam/README.md](../infra/sam/README.md), "The distribution is a front
door, not a cache"). Nor does a browser absorb it: the core answers an uploaded
asset with the reference's `Cache-Control: public, max-age=0`, so every view
revalidates, and a revalidation is an `Open` — a `GetObject` — whether or not
the bytes are sent again. The store therefore records no `Cache-Control` on the
object; nothing on this path would ever serve it.

### 2.7 The admin console — a profile read per guarded request, and an offset that is paid for

Administrator traffic, so none of this is a line on a bill; it is here because
the shape is not the obvious one. Counted off the core's `admin.go` and
`internal/store/dynamodb`:

| what | operations | units |
|---|---|---|
| every guarded request, any policy but `open`, non-root token | `GetUserByID`, strongly consistent | 1 RRU |
| …under `first-user`, additionally | `ListUsers(1, 0)`: one GSI1 Query page + one `BatchGetItem` of one item | 0.5 + 1 RRU |
| …under `rbac:` / `permission:`, additionally | the role assignments of one user, and for a permission the role definitions they name | 1 RRU and up |
| `GET <admin>/api/users`, one page of *n* | GSI1 Query over `offset + n` three-attribute entries, then `BatchGetItem` of *n* profiles, strongly consistent | ~0.5 RRU per 4 KB of entries + *n* RRU |
| `POST <admin>/users/{id}/promote` | the limiter's conditional write (§2.3) + one conditional `UpdateItem` on the profile | 2 WCU |

**The offset is index-only but it is not free**: page 10 of the users tab reads
the nine pages of index entries before it (`paging.go` `pagedIndexQuery`), which
is why the store caps `limit + offset`. A search filter is worse by
construction — the core reads 500 users and filters in process, as the reference
does — and costs ~500 RRU a keystroke-settled query. At administrator volumes
that is fractions of a cent a day.

The one-off `migrate backfill-users` sweep is a `Scan` of the whole table —
0.5 RRU per 4 KB scanned, every item type included, not only profiles — plus
1 WCU for the profile and 1 for its new GSI1 entry per user it fixes. A table
of a million items of ~1 KB is about USD 0.03 of reads; a hundred thousand
pre-D6 users about USD 0.25 of writes. It runs once.

### 2.8 The tools block — one telemetry write per identity event, and a webhook that races the freeze

D9a hands the auth core an event bus and bridges every `identity.*` event it
raises into the tools fan-out (`cmd/auth/tools.go`;
`library-events-are-bridged-into-the-tools-fan-out`). Two things now cost
money that cost nothing before, both gated on `tools.enabled`, which defaults
to off.

**Every identity event is a telemetry `PutItem`, awaited on the request
goroutine.** A login raises `identity.auth.login.success` and, because the
core issues a session with it, `identity.session.created`; a failed login
raises one event; a refresh, a logout, a registration, a password change, an
account deletion each raise one or two. Each is one item on the day-bucketed
`TEL#<tenant>#<day>` partition (`internal/store/dynamodb/telemetry.go`),
written with a TTL of `TelemetryRetention` — 90 days by default — and well
under 1 KB unless the payload is large:

| operation | source | units |
|---|---|---|
| telemetry row per `identity.*` event | `telemetry.go` `Record` | **1 WCU per event** |
| outgoing-webhook lookup per event | `webhooks.go` `FindByEvent` | 1 RRU per event, when `stores.enable.webhooks` is on |

So the login of §2.2 becomes **≈ 3 RRU and ≥ 11 WCU** with the tools block on
— two events, each a write and a subscription lookup — which is
**USD 2.50 more per million logins in DynamoDB writes** and USD 0.25 in reads,
on top of the USD 15.26 there. It is awaited, so it is also on the latency
path: about a millisecond against DynamoDB Local, single-digit milliseconds in
a region, per event. The write is a plain `PutItem` and not a transaction, so
it is billed once, not twice.

`POST <tools>/track/{eventName}` is the same row again, on demand, from
whoever the posture lets in — which is why `tools.auth: none` is priced in
`docs/config-reference.md` §17.6 as a door rather than a knob: an anonymous
caller can write a 300 KB row (`MaxTelemetryBytes`) per request, at 300 WCU a
time, under any `userId` they like.

**Retention is storage, and storage is the one DynamoDB line that is not per
operation.** At 90 days and 500 bytes a row, a million identity events a month
is about 1.5 GB resident, or ~USD 0.40 a month; a stack doing a million logins
a month should expect that on top of the write bill. The TTL delete itself is
free.

**Outgoing webhooks are an HTTP call the deployment makes on a detached
goroutine, and on Lambda that goroutine races the freeze.** The core's emitter
delivers fire-and-forget and returns, the response is written, and the
execution environment is frozen the moment it is — so a delivery that has not
completed by then completes, if ever, on that environment's next invocation
(`outgoing-webhook-delivery-races-the-response`). The cost shape until D9b:

- A receiver that answers inside the request's own lifetime costs the
  deployment **one outbound request per matching subscription per event**, and
  the duration of that request is added to the invocation's — a 200 ms
  receiver is 200 ms of GB-seconds, ~USD 1.33 per million events at 512 MB.
- A receiver that does not answer in time costs nothing further **because the
  retry never runs**: the 1 s / 2 s / 4 s schedule sleeps on a goroutine the
  freeze suspends. What is lost is the delivery, not money.
- The bound on the first attempt is `DefaultWebhookTimeout`, 10 seconds, which
  is also the bound on how long a slow receiver can hold the invocation open —
  but only while the response is not yet written, and the route writes it
  without waiting. In practice the receiver gets whatever fraction of a second
  the response took to serialise.

D9b moves the attempt onto SQS when `EnableWebhookQueue` is on (§3.3): a
delivery then costs about **USD 4.60 per million attempts**, most of it the
idempotency ledger's two DynamoDB writes, and is actually delivered, with the
schedule honoured and a dead-letter queue for the ones that never were. With
the queue off — the default — everything above stands.

**What the block does not cost.** No new resource, no new parameter with a
standing charge, no IAM statement: the three stores are partitions of the one
table and the actions are the ones the function already holds. The SSE manager
costs nothing in this function either way: without `EnableSse` it holds no
connection on this runtime, and with it (D9c) every broadcast is a write to the
event log, which §3.1 prices with the SSE function that holds the connections.

---

## 3. The SSE function, and what is still coming

This section was written before D9c chose a transport, so that the numbers
would decide it rather than follow it. §3.1 is now what D9c deployed; §3.2 is
the trade it made; §3.3 is what the remaining functions cost.

### 3.1 The SSE function: a connection is GB-seconds for its whole lifetime

Lambda bills for the duration of an invocation. A response-streaming invocation
is alive for as long as the connection is, so **the connection is the unit of
cost and the messages are noise**:

| memory | USD per connection-hour | USD per 1 000 connections per day |
|---|---|---|
| 512 MB | 0.0240 | 576 |
| 256 MB | 0.0120 | 288 |
| **128 MB — what D9c deploys** | **0.0060** | **144** |

(0.125 GB × USD 0.0000133334 × 3 600 s. The four invocations an hour that a
fifteen-minute segment costs add USD 0.0000008.)

**What D9c decided, and why each number is that number.**

1. **Its own function at 128 MB** (`SseMemorySize`). The auth router is at
   512 MB because login is CPU-bound on bcrypt; an idle connection needs none
   of that CPU and would pay four times over for it. The SSE function is the
   same artifact with a second entry point (`cmd/auth/stream.go`), so it
   cold-starts the whole composition — measured at ~207 ms of `Init Duration`
   at 512 MB (infra/sam/README.md) with 26–38 MB of memory used — and at a
   quarter of the CPU that init is expected to take well under a second:
   paid once per connection segment, at connect, and not measured yet on a
   real deployment.
2. **A ceiling of 20 simultaneous connections** (`SseReservedConcurrency`).
   One connection holds one execution environment, so the reservation is the
   listener count and the cap on this line of the bill — the compute: **USD
   0.12 an hour, USD 2.88 a day, about USD 88 a month** with every slot held
   around the clock. It is not a cap on the reads below, which grow with the
   events a listener is sent, nor on refused requests, which it bounds in rate
   only. It also keeps listeners out of the account pool, so a crowd of
   streams cannot throttle a login. `SseConcurrencyAlarm` fires at 15 held for
   fifteen minutes (§4).
3. **Fifteen-minute segments** (`SseTimeout`, 900). Lambda's cap, so a
   connection is a sequence of segments and the client reconnects, and the
   resume guarantee (`docs/sse.md`) is what makes that lose nothing. A client
   that vanishes without closing is billed until its segment ends — Lambda
   does not end an invocation because its client went away — so the worst
   case of an abandoned tab is fifteen minutes, USD 0.0015. A shorter timeout
   trades that for more reconnects, each one an invocation and a resume
   (priced below).

**The poll, which is not noise any more.** The earlier version of this section
priced a strongly consistent read every 30 seconds and found it an
eight-hundredth of the compute. The poll D9c built is one Query per subscribed
topic per interval, and the interval is a second, because a second is the
latency an event on a live stream is allowed:

| poll | per connection-hour, 2 topics (`global`, `user:<u>`) | 3 topics (a tenant as well) | against 128 MB compute |
|---|---|---|---|
| every 1 s, events arriving | 3 600 RRU, USD 0.0009 | 5 400 RRU, USD 0.00135 | 15–23 % |
| every 5 s, after a minute of silence | 720 RRU, USD 0.00018 | 1 080 RRU, USD 0.00027 | 3–5 % |

Each Query is **eventually consistent, at DynamoDB's floor of 0.5 RRU** when
nothing new is returned, which is most polls on a quiet topic. A strongly
consistent poll would cost twice as much and close only half the race the
look-back exists for. **These are counted, not measured** — the 0.5 RRU floor
is DynamoDB's documented minimum for a Query — and the check after the first
deploy is `ConsumedReadCapacityUnits` on the table against the number of
connections held. The back-off (`tools.sse.pollIntervalMs` then five seconds
after sixty of silence, snapping back on the next event) is what keeps an idle
listener, which is most listeners, at the bottom row: a minute is long enough
that an active conversation never backs off, and four seconds of added latency
on the first event after a quiet minute is the whole price.

**On a busy topic the table above is not the bill; the events are.** A Query
is charged on the size of what it reads, 0.5 RRU per 4 KB eventually
consistent, so per connection:

    RRU per second ≈ Σ over held topics of 0.5 × ⌈(events read per second × item size) / 4 KB⌉ per Query
    events read per second ≈ events delivered + look-back re-reads

The events delivered are the irreducible part — a listener is sent what the
topic carries, and every connection holds `global`, which carries every
identity event. The look-back — the re-read that makes an eventually consistent
cursor safe (data-model.md §1.5) — is bounded twice: three seconds behind the
topic's newest event **and** at most 32 events, and a poll that is catching up
after a full page skips it. So it adds at most one page per paced poll, not
three seconds of events. Worked through for a busy `global`, **100 identity
events a second of ~1 KB**: the connection delivers 100 KB/s (about 12.5 RRU/s
in four pages), and its one paced poll a second re-reads at most 32 KB more (4
RRU/s) — about **16.5 RRU/s, ~59 000 RRU an hour, USD 0.015 per
connection-hour**, two and a half times the connection's compute. Twenty such
listeners are USD 0.30 an hour, about USD 215 a month, against the USD 88 of
their compute. Without the count bound the same topic would have re-read 300
events on every poll; with it, three quarters of that bill is the delivery
itself. At an ordinary auth workload — a few events a second — the reads stay
at the table above.

**A resume, and what a cursor can cost.** A reconnect with a cursor reads the
replay once and then polls as above. The replay is bounded by
`tools.sse.replayLimit` (100 events by default), and a resume from an event's
id adds one keys-only Query per topic for the look-back below it — at most 33
items, still charged on their size — and re-reads those ≤ 32 on its first poll:

    RRU per resume ≲ 0.5 × ⌈(replayLimit + 2 × 33 × topics) × item size / 4 KB⌉

At the defaults, two topics and ~1 KB items that is ≲ 30 RRU, **USD 0.0000075
a resume**; at the 16 KiB item cap, ≲ 470 RRU, USD 0.00012. The bound matters
because the cursor is the client's to write — the all-zero ULID, or any ULID
dated to the horizon, is a valid one — and without the limit each such
connection would page through the whole retention of `global`. With it, the
worst a credentialed caller does by reconnecting on all twenty slots once a
second is ~20 × 30 RRU/s, about USD 0.55 an hour at 1 KB items (USD 8.50 at
the cap), on top of the invocations.

**The publishing half, in the auth function.** With `EnableSse`, every
broadcast is a `PutItem` per topic a stream can hold — `global` and
`user:<u>`, and `tenant:<t>` when there is one; the `session:<sid>` copy every
identity event is also fanned to is not written, since no stream can hold it
(data-model.md §1.5). Each item is under 1 KB for an ordinary event:

| what | units | USD per million |
|---|---|---|
| one identity event, single-tenant | 2 WCU | 2.50 per million events |
| one login (two events, §2.8) | 4 WCU | **5.00 more per million logins**, on top of §2.2 and §2.8 |
| storage at the default 24 h retention | ~1 KB per topic-copy, resident a day | a million events a month is ~70 MB resident, ~USD 0.02 a month |

The writes are awaited on the request goroutine, as the telemetry row is, so
they are on a login's latency too: two single-digit-millisecond `PutItem`s.
The TTL delete is free. A caller-shaped event is the exception to "under 1 KB":
`POST <tools>/notify` and `POST <tools>/track` log whatever payload they are
handed, up to the 16 KiB item cap — 16 WCU a copy, three copies for a track,
**~USD 0.00006 a request at the cap** — and `SSE#global`'s partition takes a
thousand WCU a second, so about sixty such requests a second from one
credential holder fill it, after which logins' publishes to `global` are
throttled and those events reach no stream (docs/sse.md §4). An event over the
cap is not written at all.

**Refused requests.** The Function URL is `AuthType: NONE`
(docs/config-reference.md §17.3.3), so every request that reaches it is an
invocation, and a refused one costs the request charge, a few milliseconds of
128 MB and its log lines:

| refused request | USD per million |
|---|---|
| the path gate's `404` — no line of the product's own, Lambda's `START`/`END`/`REPORT` only | ~0.38 |
| the stream's guard refusal (`401`/`403`), one access-log line | ~0.51 |
| under `apiKey`, a real key prefix with a wrong secret: bcrypt at the key's cost, ~1 s at 128 MB | ~2.20 |

The reservation bounds the **rate**, not the total: twenty slots at ~5 ms is
about 4 000 refusals a second, **USD 5.50–7.30 an hour** sustained. The same
slots are the listeners', so such a flood also refuses every listener `429`.
A legitimate `apiKey` connect pays the same bcrypt once per segment, about USD
0.000002. The mitigations are CloudFront in front, or `EnableSse` off
(config-reference §17.3.3).

**What it adds at rest: nothing.** The function, its URL, its two permissions,
its log group and the CloudFront behaviour have no standing charge, and all of
them exist only with `EnableSse`. Its alarm is the tenth metric (§3.3).

### 3.2 What the alternatives cost, so the trade is explicit

Same workload — 1 000 listeners connected for a day, a handful of events each:

| transport | USD / day | ratio | what it costs in wire terms |
|---|---|---|---|
| Lambda response streaming, 512 MB | ~576 | 1× | Nothing. `text/event-stream` exactly as the reference serves it |
| Lambda response streaming, 128 MB | ~144 | 1/4 | Nothing, if the function is split out |
| HTTP polling every 30 s | ~5 | 1/115 | A different client contract; no server push |
| API Gateway WebSocket | ~0.4 | 1/1500 | A different protocol entirely — not SSE |

(WebSocket at USD 0.25 per million connection-minutes plus USD 1.00 per million
messages: 1 000 × 1 440 minutes is 1.44 million connection-minutes. Polling at
30 s is 2.88 million requests a day through API Gateway, Lambda and one read
each.)

**The trade this table states is that byte-level wire compatibility with the
reference's SSE costs about three orders of magnitude on idle connections.** That
may well be the right price — wire compatibility is the product's whole premise
and this stack's traffic is nowhere near a thousand listeners — but it should be
paid knowingly, with a per-deployment ceiling on concurrent streams, and that is
D9c's decision to record rather than this document's to make, and D9c recorded it:
128 MB and a ceiling of twenty (§3.1).

### 3.3 The other functions coming

Each one brings **a log group that must be declared explicitly or it will never
expire** — see §5 — and alarms. It would bring four alarm metrics (errors,
throttles, duration, concurrency) at USD 0.10 a month past the free ten if it
took the auth function's set; the webhook worker and the script runner take one
each. The template counts the alarms **enabled by default** against the free
ten, so an optional function's alarms are gated on its own switch and priced
here instead (`infra/sam/template_test.go`, `offByDefaultAlarmGates`): **nine
alarms by default**, and one more for each optional function switched on —
`WebhookDeadLetterAlarm` with `EnableWebhookQueue`, `ScriptRunnerDurationAlarm`
with `EnableInboundWebhooks`. **All-on total: 11 alarm metrics**, one past the
free ten: USD 0.10 a month in an account with no other alarms, USD 1.10 in one
whose allowance is already spent. `TestTheAlarmSetStaysInsideTheFreeAllowance`
asserts that sentence against the template, and fails unless the all-on total
is the number written here.

| | shape of its cost |
|---|---|
| webhook worker | **Landed (D9b)**, below |
| script runner | **Landed (D9d)**, below. Per run, and the run is **caller-initiated** — the inbound route is unauthenticated — so the exposure is a stranger's rate times a script that loops, capped by a reservation |
| migrate job | One-off, bounded by the size of the directory being migrated; reads dominate |
| SSE function | **Landed (D9c)**, priced in §3.1. One alarm, not four: `SseConcurrencyAlarm`, gated on `EnableSse` as well as `EnableAlarms`, so **nine alarms by default, ten with SSE** — free in an account with no others — **and eleven with SSE and the webhook queue (D9b) both on**, USD 0.10 a month for the eleventh past the free ten. Errors and duration say nothing about a held stream (every invocation runs to its timeout by design), and throttles move only once the reservation is refusing, which the concurrency alarm, set below it, reports first |

#### The webhook queue and its worker (D9b)

Everything here exists only with `EnableWebhookQueue` (and `EnableTools`)
`"true"`; the default adds no resource and costs nothing. Unit prices beyond
the table at the top: **SQS standard, USD 0.40 per million requests after the
first million a month** (a request is one API call of up to 64 KB; a batch of
ten is one request). Lambda at 128 MB is **USD 0.0000016667 per second**.

**At rest.**

| resource | USD / month | why |
|---|---|---|
| `WebhookQueue`, `WebhookDLQ` | 0.00 | SQS has no hourly or per-queue charge; SSE-SQS encryption is free |
| `WebhookWorkerFunction` | 0.00 | per invocation only |
| `WebhookWorkerLogGroup` | ~0.00 | 14-day retention, a line or two per delivery |
| the event source's empty receives | 0.00 / ~0.26 | Lambda long-polls the queue continuously; at 20-second long polls and the handful of pollers AWS runs for an idle source, that is in the order of 650 000 empty `ReceiveMessage` calls a month — inside the free million, USD ~0.26 in an account that has spent it. An estimate, not a measurement: check the queue's `NumberOfEmptyReceives` after a day |
| `WebhookDeadLetterAlarm` | 0.00 / 0.10 | one alarm metric, gated on the queue's switch — counted with the other optional functions' at the top of this section |

**Per delivery attempt**, a receiver answering in about 200 ms:

| operation | source | USD per million attempts |
|---|---|---|
| `SendMessage` from the auth function | `sqs.go`, `SQSWebhookDeliverer` | 0.40 |
| the auth function waiting for it (~20 ms at 512 MB) | `webhook_queue.go`, the flush | 0.13 |
| receive + delete by the event source, batched up to ten | Lambda SQS event source | ≤ 0.80, down to 0.08 when batches fill |
| one worker invocation (a batch shares one) | `cmd/webhook-worker` | ≤ 0.20 |
| worker duration, ~250 ms at 128 MB | the POST plus the ledger | 0.42 |
| ledger claim + settle, 1 WCU each | `webhook_deliveries.go`, data-model.md §1.9 | **2.50** |
| worker log, ~300 bytes | `worker.go` | 0.15 |
| **total** | | **≈ USD 4.60 per million attempts**, of which the ledger is more than half |

A failed attempt adds one `ChangeMessageVisibility` (USD 0.40 per million) and
is billed again on the retry; a delivery with the default three retries against
a dead receiver is four attempts, one DLQ `SendMessage` and nothing after. A
duplicate receive — rare; SQS standard queues deliver at least once — costs one
failed conditional write (1 WCU) and one invocation's share, and makes no
request. A receiver that hangs costs its 10-second timeout at 128 MB, USD
0.0000167 an attempt, which is why the worker is at the smallest memory size:
the work is waiting, not computing.

**Concurrency bounds the rate, not the total.** `WebhookWorkerMaxConcurrency`
(default 5) bounds how many worker environments drain the queue at once, so a
burst of a hundred thousand logins is a backlog that drains five batches at a
time rather than a hundred thousand concurrent POSTs at every receiver. It
does not bound the bill: every message enqueued is eventually received,
claimed, settled, POSTed and deleted, so every per-attempt line above scales
with **arrivals**, not with the drain. What concurrency does cap is the
worker's *duration*: five environments busy for their whole 30-second timeout,
around the clock, are 5 × 2 592 000 s × USD 0.0000016667 ≈ **USD 21.60 a
month**, the most worker duration the default can bill in a month whatever
arrives (a raised `WebhookWorkerMaxConcurrency` scales it linearly); the
queue, ledger and invocation lines have no such ceiling.

**Who fills the queue.** Anything that raises an event a subscription
matches, and two of those need no credential at all:

- `identity.auth.login.failed` is published for every refused login, an
  unauthenticated request (the core's `login_2fa.go`). A subscription to it
  turns a password-spraying run into one queued delivery per guess, and a
  receiver that refuses them into four attempts each.
- `POST <tools>/track/{event}` fires every matching subscription with a
  caller-chosen payload under `tools.auth: none` (anyone) and `session` (any
  self-registered user, config reference §17.6). The template's default,
  `apiKey`, closes it.

§2.8's "costs nothing further because the retry never runs" stops being true
with the queue on: every such event now gets its full schedule — up to four
attempts with the defaults, each up to a 10-second hang at 128 MB against a
receiver that does not answer. And the per-request SQS price assumes a
message under 64 KB, SQS's billing unit: a `track` payload near the
~190 KiB envelope budget is **three** billed requests per `SendMessage`,
receive and DLQ hand-off. A payload over the budget costs no SQS request —
the enqueue is refused before it is sent — and, since the refusal is
permanent, the auth function no longer waits out its two-second flush bound
for it (about USD 0.33 per million requests for a 50 ms request, against
USD 17 per million had it waited the bound at 512 MB).

**A backlog is free to hold, for fourteen days.** Messages wait on the
queue at no charge up to `WebhookQueue`'s retention. A failing message near
it is dead-lettered as `expiring` (config reference §17.4); one never
received within it — a backlog deeper than the worker drains in fourteen
days, or a worker that cannot start — is deleted by SQS **silently**, with
no redrive and no alarm. An alarm on the queue's
`ApproximateAgeOfOldestMessage` would catch that and would be one more alarm
metric, USD 0.10 a month past the free ten; it is left out.

**The alarm budget (rule 10 of the block).** The worker adds one alarm, not
four: `WebhookDeadLetterAlarm` on the dead-letter queue's depth, because a
webhook that gave up is exactly the event nothing else reports, and every other
failure of the worker either ends in that queue (a crash loop is redriven into
it) or only delays a delivery (the message waits). It is gated on the queue's
switch as well as `EnableAlarms`, so a stack without the queue does not have it
and `template_test.go`'s default count is unchanged; the totals are at the top
of this section. The worker's errors, throttles, duration and concurrency
would be four more metrics, USD 0.40 a month past the allowance, and are left
unalarmed on purpose; the Lambda console shows them for free.

#### The script runner (D9d), `EnableInboundWebhooks=true`

**At rest: USD 0.00.** A Lambda function, an IAM role, an empty log group and a
reserved-concurrency setting cost nothing until invoked — a reservation only
carves environments out of the account's unreserved pool. Its one alarm,
`ScriptRunnerDurationAlarm`, is gated on the runner's switch and counted with
the other optional functions' at the top of this section. With the switch off
none of it exists.

**Per inbound webhook whose row has a script**, on top of the webhook request's
own platform floor (§2.1), at arm64 prices (USD 0.0000133334 per GB-second,
USD 0.20 per million requests; the durations are estimates from the engine's
tests, not measurements — this block deployed nothing):

```
runner invocation          0.20 / million
runner duration, 256 MB    0.07 / million at ~20 ms (a fresh goja runtime + a mapping script)
auth function waiting      0.20 / million at ~30 ms of a 512 MB function held on the Invoke
runner log line, ~250 B    0.13 / million
                           ─────────────
                           ~0.60 / million runs
```

The auth function **waits** on the runner — the Invoke is synchronous, because
the core's route must answer the provider with the script's outcome — so every
millisecond of a script is billed twice: once at 256 MB in the runner and once
at 512 MB in the auth function holding the call. A row with no script costs
nothing here: the runner is not invoked.

**Who decides how many runs there are: anyone.** The run is
**caller-initiated**, not operator-initiated. `POST <tools>/webhook/{provider}`
has no guard and checks no provider signature, in the reference and here, so
whoever can reach it and names a provider whose row has a script — and provider
names are guessable: `stripe`, `github` — runs that script, with a body they
wrote, at a rate they choose. Each in-flight run holds two execution
environments, the runner's and the auth function's waiting on it, both from the
account's unreserved pool unless something reserves them. What bounds it:

- **`ScriptRunnerReservedConcurrency`, 5 by default — the hard cap.** At most
  that many runs are in flight account-wide; a run over it is throttled, the
  auth function answers `400` at once and the provider redelivers later. It is
  the only bound on the spend, and it bounds the auth environments held on the
  runner too, since each waits only as long as its run. An empty value reserves
  nothing and leaves the runner drawing on the account's pool, uncapped.
- **The `rateLimit` block, per address and provider.** With `rateLimit.enabled`
  (the default) the route shares `rateLimit.max` per `rateLimit.windowSeconds` —
  ten a minute — per client address and provider, and answers the registered
  `429` beyond it before the runner is invoked (`rate-limited-routes-answer-429`).
  It stops one address from keeping the cap full; it does not stop many. A
  legitimate provider sending more than that from one address in one window is
  refused and redelivers — late, not lost.
- **In front of both**, the levers this template does not pull: API Gateway
  route throttling, or a WAF rule on the path.

The ceiling at the default reservation, sustained for a day, is therefore:

```
a script the body drives to the 5 s deadline   5 runs in flight × (5 s at 256 MB + 5 s at 512 MB)
                                                ≈ 0.00005 USD per run, 1 run/s  ≈ USD 4.50 / day
a fast script, ~20 ms                           5 in flight ÷ 20 ms ≈ 250 runs/s × 0.60 / million
                                                ≈ USD 13 / day, plus each request's API Gateway floor (§2.1)
```

— a bound someone chose and wrote down, rather than the account's whole
concurrency pool times the same arithmetic.

**The exposure is a script that loops**, or awaits something slow. It runs to
the deadline (`scriptTimeoutMs`, 5000 ms), is interrupted, and the webhook is
refused `400` — so the provider redelivers it and the same deadline is billed
again:

```
runner, 5 s at 256 MB           0.0000167  per delivery
auth function, 5 s at 512 MB    0.0000333  per delivery
                                ─────────
                                ~0.00005   per delivery   (USD 50 per million)
```

A provider sending 10 000 events a day into a looping script is about
**USD 0.50 a day** before its redeliveries, and every redelivery multiplies it
— which is the incident `ScriptRunnerDurationAlarm` exists for: it fires at
80 % of the deadline, on one five-minute period, because a provider's own
redeliveries arrive minutes to hours apart and "twice running" would rarely be
true of them. A stranger's requests are not so spaced, and they are the
reservation's to cap.

**A raised deadline.** Every second added to `InboundScriptTimeoutMs` adds a
second to the looping case, on both functions: 28 000 ms, the template's
maximum, makes it five to six times worse. The maximum is 28 000 and not the
configuration's 30 000 because the auth function waits on the run: its own
`Timeout` tops out at 29 s, and it keeps a second after the Invoke to track and
answer. Past the auth function's remaining time the invoker cuts the run short
(`internal/integration/aws`, `WithInvocationDeadline`), so a deadline longer
than `Timeout` bills `Timeout` less a second on both functions and answers the
core's `400`, never Lambda killing the auth function mid-Invoke.
`infra/sam/script_runner_test.go` relates `Timeout`, `ScriptRunnerTimeout` and
the alarm threshold to the deadline at the defaults and at the maxima;
CloudFormation cannot relate the values a deployment picks.

---

## 4. What the incidents cost, which is the point

Steady state is USD 0.80 a month. These are the departures from it, each with the
alarm that catches it and roughly what an unnoticed hour costs.

| incident | per unnoticed hour | caught by |
|---|---|---|
| 20 SSE connections held open at 128 MB — the default reservation, full (D9c) | **~0.12** of compute, and no more of it: past the reservation new listeners are refused `429`, which a native `EventSource` does not retry, so they stay disconnected until the page recreates the source; on a busy `global` add ~0.015 a connection in reads (§3.1) | `SseConcurrencyAlarm`, ≥ 15 for 15 min |
| A flood of refused requests on the SSE function's public URL (D9c) | **~5.50–7.30** at the ~4 000 a second twenty slots allow, and every listener refused `429` while it lasts | `SseConcurrencyAlarm`, once the flood has held the slots for 15 min |
| 1 000 SSE connections held open at 512 MB, had the stream no function and no reservation of its own | ~24 | `ConcurrentExecutions` ≥ 50 for 5 min — the auth function's alarm, which is why the stream is not in that function |
| Function timing out at 10 s instead of answering in 300 ms | ~33× the duration bill for the same traffic | `Duration` ≥ 8 000 ms twice running |
| Recursive invocation at 50 concurrent, 10 s each | **~24**, plus DynamoDB per iteration | `ConcurrentExecutions`, then `Throttles` |
| Credential stuffing at 100/s | ~0.45 in limiter writes, ~0.43 in platform | `ConsumedWriteCapacityUnits`, then `WriteThrottleEvents` |
| A loop logging per iteration at 25 MiB/hour | ~0.01, and growing with the loop | `IncomingBytes` ≥ 25 MiB/hour |
| A log group with no expiry | 0.03 per GB-month, **forever** | the convention in §5, enforced by a test |

The row that matters most is the first, and the reason is in the second column of
§3.1: none of it shows up in request counts, error rates or latency. A stack
burning USD 576 a day on held-open connections looks *perfectly healthy* on every
dashboard except concurrency.

It is also why the concurrency and duration alarms are not redundant with the
spend alarms below. CloudWatch's billing metrics refresh roughly every six hours
and Cost Explorer is about a day behind; `ConcurrentExecutions` is a minute
behind. **For this product the fastest spend alarm is not a spend alarm.**

---

## 5. What observability itself costs

| | USD / month |
|---|---|
| Nine alarm metrics enabled by default, standard resolution | 0.00 (free ten) / 0.90 beyond |
| The optional functions' alarms, one each (§3.3: the dead-letter alarm with `EnableWebhookQueue`, the script runner's duration alarm with `EnableInboundWebhooks`) | 0.10 each past the free ten; all on, 11 metrics — 0.10 in an account with no other alarms |
| SNS topic, one email subscription | 0.00 (first 1 000 notifications free; 2.00 per 100 000 after) |
| One budget | 0.00 (second of two free per account) |
| Cost anomaly detection | 0.00 |
| Log storage at 14 days | pennies at this traffic |
| Log ingestion | 0.30 per million requests — see §2.1 |

**Log retention is structural, not a habit.** Every function this stack declares
gets an explicit `AWS::Logs::LogGroup` named `/aws/lambda/<FunctionName>`, with
`RetentionInDays: !Ref LogRetentionDays` (default 14), and the function
`DependsOn` it. A log group Lambda creates for itself has **no expiry at all**,
and nothing about that looks wrong until the storage line does.

`infra/sam/template_test.go` enforces it: it reads the template, finds every
function, and fails if any lacks a matching group, the retention reference, or
the ordering. It also fails if the alarms **enabled by default** grow past ten
(an optional function's alarms are gated on its own switch and priced in
§3.3), which is a deliberate tripwire — the eleventh alarm costs money and should be a decision
somebody makes rather than one that happens.

---

## 6. Budgets, alarms and credit — three corrections worth writing down

### 6.1 A budget is an alert. It is not a cap. Nothing at AWS is.

AWS Budgets notify; they do not stop services. If spend continues past a budget,
it continues. The account's AWS-provided **"My Zero-Spend Budget" is an alert, not
a cap**, and if promotional credit ran out with spend continuing, the charges
would fall to the payment method on file regardless of what any budget said.

The only hard stops available to this stack are:

- `ReservedConcurrentExecutions` on the function — refuses invocations past a
  number, indiscriminately, real users included;
- `MaxReadRequestUnits` / `MaxWriteRequestUnits` on the table — refuses reads and
  writes past a rate.

Both are off or generous by default, because both cause outages when they bind.
That is the honest shape of the problem: the mechanisms that bound spend are the
mechanisms that refuse service.

### 6.2 A zero-spend budget cannot see spend that credit is covering

AWS's zero-spend budget alerts above USD 0.01 of *actual* cost, and actual cost is
computed **with credits included** — a credit is a negative line that nets the
charge to zero. So an account burning USD 40 a month against a promotional grant
shows USD 0.00 to that budget, and it stays silent for the whole period in which
the money is being spent. It fires the month the credit runs out, which is the
month it stops being useful.

This is why the stack's optional budget sets `CostTypes.IncludeCredit: false`. It
measures **gross consumption**, which is a different number from the console
budget's and the exact number a "stop when cumulative consumption approaches N"
rule is written against. Two budgets measuring the same thing would be noise;
these two measure different things, and the second is the one that can speak.

Set it with `BudgetLimitUsd` (0, the default, creates nothing) and
`BudgetTimeUnit` — `ANNUALLY` by default, because the question a credit-covered
deployment has to answer is cumulative and a monthly budget resets before it can
ever answer it.

### 6.3 No public API reports a promotional credit balance

It cannot be read. It can only be **inferred**: the grant, minus consumption to
date. Consumption is the half that is measurable, and Cost Explorer is where it
comes from — grouped by `RECORD_TYPE`, so that `Usage` (what was consumed) and
`Credit` (what was applied against it) are separate lines:

```sh
aws ce get-cost-and-usage --region us-east-1 \
  --time-period Start=<grant start>,End=<tomorrow> \
  --granularity MONTHLY --metrics UnblendedCost \
  --group-by Type=DIMENSION,Key=RECORD_TYPE
```

Sum the `Usage` amounts for consumption to date; the credit applied is the
negated sum of the `Credit` amounts. Remaining credit is the grant minus the
first number — **an arithmetic result, never a reading**, and it is wrong the
moment the grant amount is misremembered. The operator-side `credit.sh` in this
run's tooling (outside this repository) does exactly this and prints both totals
plus the per-month breakdown; `aws budgets describe-budgets` shows what budgets
exist alongside it.

Two consequences for anyone automating against this:

- The Free Tier API (`aws freetier get-free-tier-usage`) reports free-tier usage,
  not credit. It is not an answer to this question.
- Cost Explorer is roughly a day behind, and a cost-anomaly notification can be
  up to 24 hours behind the spend it describes. Everything in §4 is faster, which
  is the argument for alarming on resources rather than on money.

---

## 7. Checking it against reality

Nothing above replaces looking. The numbers to pull, in the order they answer
questions:

1. `ConcurrentExecutions` and `Duration` for the function — the two that move
   first and the two that cost most.
2. `ConsumedWriteCapacityUnits` on the table — the biggest line in §2.2, and the
   one a traffic change moves proportionally.
3. `IncomingBytes` on the log group — the line that grows when code changes
   rather than when traffic does.
4. Cost Explorer grouped by `SERVICE`, monthly — the arbiter, a day late.

If (1) to (3) disagree with (4), (4) is right and this document is wrong; the
prices here are public-page figures and the operation counts are read off source
that changes.

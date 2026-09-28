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
| CloudWatch Logs storage | ~0.00 | At 14-day retention and this traffic, a few MB |
| **The nine alarms** | **0.00** | Nine alarm metrics against a free allowance of ten |
| **SNS topic + subscription** | **0.00** | No charge at rest; first 1 000 email notifications a month are free |
| **The budget** | **0.00** | First two budgets per account are free; this is the second |
| **Cost anomaly detection** | **0.00** | Free |
| S3 artifact bucket | cents | A few MB per deployed version |
| KMS key, `EnableIdp=true` only | 1.00 | Billed whether or not it signs, **including its 7-day deletion window** |
| Admin uploads bucket, `EnableAdminUploads=true` only | cents | S3 Standard storage for a handful of images, USD 0.023 per GB-month; an empty bucket is free. Requests are §2.6 |

**Total: USD 0.80 a month, or USD 1.80 with the identity provider on.** The
observability block adds **nothing** to that in an account with fewer than ten
other alarms, and **USD 0.90 a month** in one that has already spent the free
allowance — nine alarm metrics at USD 0.10.

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

---

## 3. What is coming, and what shape it costs

The block that adds SSE (D9c) needs these numbers **before** it chooses a
transport, not after — which is why this section exists in a document written
before that block starts.

### 3.1 An SSE connection is GB-seconds for its whole lifetime

Lambda bills for the duration of an invocation. A response-streaming invocation
is alive for as long as the connection is, so **the connection is the unit of
cost and the messages are noise**:

| memory | USD per connection-hour | USD per 1 000 connections per day |
|---|---|---|
| 512 MB | **0.0240** | **576** |
| 256 MB | 0.0120 | 288 |
| 128 MB | 0.0060 | 144 |

The polling half of it barely registers. A DynamoDB read per poll at the
reference's 30-second heartbeat interval (`sse-manager.ts`, `heartbeatIntervalMs`
defaults to 30 000) is 120 strongly consistent reads an hour, or
**USD 0.00003 per connection-hour** — about one eight-hundredth of the
GB-seconds at 512 MB. Even at a one-second poll it is USD 0.0009, still
twenty-five times smaller.

Three consequences that are decisions, not observations:

1. **The SSE function must be its own function with its own `MemorySize`.** The
   auth router is at 512 MB because login is CPU-bound on bcrypt; an idle
   connection needs none of that CPU and pays four times over for it. Splitting
   them is worth 4× on the dominant line.
2. **Concurrency is the ceiling before money is.** One connection holds one
   execution environment, so an account's default 1 000 concurrent executions is
   1 000 simultaneous listeners — and the thousand-and-first login is throttled
   by the listeners. This is why `ConcurrentExecutions` is alarmed and why
   `ReservedConcurrentExecutions` exists as a parameter.
3. **Lambda caps an invocation at 15 minutes**, so a connection is a sequence of
   segments and the client reconnects. That is a wire question as much as a cost
   one: the reference has no `Last-Event-ID` resume to inherit
   ([serverless-gap-analysis.md](spec/serverless-gap-analysis.md) §1.5), so
   whatever D9c does about the gap between segments is net-new surface.

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
D9c's decision to record rather than this document's to make.

### 3.3 The other functions coming

Each one adds four alarm metrics (errors, throttles, duration, concurrency) at
USD 0.10 a month past the free ten, **and a log group that must be declared
explicitly or it will never expire** — see §5.

| | shape of its cost |
|---|---|
| webhook worker | Per delivery: one invocation, one outbound request, retries billed again. SQS is USD 0.40 per million requests after the free million a month |
| script runner | Per run, and the run is operator-initiated, so the exposure is a script that loops |
| migrate job | One-off, bounded by the size of the directory being migrated; reads dominate |

---

## 4. What the incidents cost, which is the point

Steady state is USD 0.80 a month. These are the departures from it, each with the
alarm that catches it and roughly what an unnoticed hour costs.

| incident | per unnoticed hour | caught by |
|---|---|---|
| 1 000 SSE connections held open at 512 MB | **~24** | `ConcurrentExecutions` ≥ 50 for 5 min |
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
| Nine alarm metrics, standard resolution | 0.00 (free ten) / 0.90 beyond |
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
the ordering. It also fails if the alarm set grows past ten, which is a
deliberate tripwire — the eleventh alarm costs money and should be a decision
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

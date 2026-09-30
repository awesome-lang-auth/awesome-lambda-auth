# Inbound webhooks and the script runner

`POST <tools>/webhook/{provider}` is how a third party — a billing provider,
an identity provider, a CRM — tells this deployment that something happened.
The route looks up the webhook row stored for `{provider}`, runs the row's
`jsScript` against the request body, and tracks whatever event the script
declares, exactly as the reference does (`tools.router.ts:250-326`). What is
different here is **where the script runs**, and this page is about that.

| | |
|---|---|
| Switch (SAM) | `EnableTools=true` and `EnableInboundWebhooks=true` |
| Switch (document) | `tools.enabled`, `tools.inboundWebhooks.enabled`, `tools.inboundWebhooks.scriptRunnerFunction` |
| Deadline | `tools.inboundWebhooks.scriptTimeoutMs` (SAM `InboundScriptTimeoutMs`), 5000 ms |
| Where scripts run | `cmd/script-runner`, a Lambda of its own |
| What a script can reach | what that Lambda's role grants: **its own log group, nothing else** |
| Register entries | `inbound-webhooks-are-refused-without-a-runner`, `inbound-webhook-scripts-run-on-goja`, `admin-actions-list-omits-the-runner-manifest` ([deviations.md](deviations.md)); upstream `inbound-webhook-script-runs-out-of-process` |
| Cost | [cost-model.md](cost-model.md) §3.3 |

## 1. The sandbox is the role

A webhook script is JavaScript an administrator typed into the admin console.
The reference runs it with `node:vm` inside the API process — the process that
holds the signing keys, the session store and the password hashes — and its
own documentation now says `node:vm` is not a security boundary (reference
1.10.5, issue #10). The repository owner decided on 2026-09-12 that this
product does not do that: **no JavaScript engine is linked into the auth
function, ever**. `cmd/auth`'s `TestTheAuthBinaryLinksNoJavaScriptEngine`
reads the auth binary's import graph and fails if goja, any other JavaScript
engine, a WebAssembly runtime or the runner's own engine package is in it.

The auth core resolves the policy and nothing else — the intersection of the
settings' `enabledWebhookActions` with the row's `allowedActions` — and hands
five values across its `InboundScriptRunner` seam: the provider, the webhook
id, the script, the raw body and that resolved list. Never the webhook's
secret, the settings store, the request headers, or anything callable. The
auth function sends them, with a synchronous `lambda:InvokeFunction`, to
`ScriptRunnerFunction`, and the script runs **there**.

What bounds a script is therefore not the engine but `ScriptRunnerRole`:

```
logs:CreateLogStream, logs:PutLogEvents  on  the runner's own log group
```

and nothing else — no table, no secret, no KMS key, no other function.
`infra/sam/script_runner_test.go` pins the role action by action. The engine
only promises the smaller thing, that a script has no **primitive** to reach
anything with: there is no `require`, no `fetch`, no `process`, no
`setTimeout`, no `Buffer` (`internal/scriptrunner`,
`TestTheScriptHasNoPrimitiveToReachAnything`). The function is outside any
VPC, so Go code in an action could open a socket; a script cannot, because it
has nothing to open one with.

## 2. The result protocol

A script sees four variables — the reference's four — and nothing of the host:

| Variable | What it is |
|---|---|
| `body` | the request body, parsed by the engine's own `JSON.parse`. An empty body is `{}`; a body that is not a JSON object or array was refused `400` before the runner was called |
| `actions` | the callable actions (§4). **Empty on this build** |
| `result` | `null`; the script assigns `{event, data?, userId?, tenantId?}` to it |
| `console` | `log`, `warn`, `error` — one JSON record per call in the runner's log group, at the matching level, carrying `provider`, `webhookId`, `method` and the space-joined `message`; silent when `DeploymentEnvironment` is `production` (the reference's `NODE_ENV` rule, where it writes `[webhook:<provider>]` lines to stderr instead) |

It is wrapped in the reference's exact wrapper, `(async () => { <script> })()`,
so `await` works at the top level — and a script that ends in a `//` comment
swallows the closing `})()` and fails to compile, here as there.

The runner **awaits** the script — every `await`, to the end — and then reads
`result`, **even if the script threw** (the reference's check sits after its
catch), and maps it:

| The script… | The runner answers | The route answers | The provider… |
|---|---|---|---|
| left `result` with a string `event` | a result | `200 {"ok":true}`, and the event is tracked | is done |
| left `result` null, not an object, or with no string `event` | no result | `200 {"ok":true}`, nothing tracked | is done |
| **threw** (a syntax error, a `ReferenceError`, a rejected `await`, recursion past ~10 000 frames) | no result, and the error is logged — unless it assigned a `result` with a string `event` before throwing, which is tracked as in the first row | `200 {"ok":true}` | is done |
| left a `result` that cannot be read — a getter that throws, a `data` with a cycle or a `BigInt` | **a failed run** | `400 {"error":"Webhook processing failed"}` | **redelivers** |
| awaits a promise nothing can ever settle | no result, at once | `200 {"ok":true}` | is done |
| ran past its deadline | **a failed run** | `400 {"error":"Webhook processing failed"}` | **redelivers** |
| — (the runner was unreachable, throttled, crashed, or not permitted) | — | `400` | **redelivers** |

The split between "threw" and "failed run" is the whole contract. A script
that throws is the script's own bug: acknowledging it is what the reference
does, and a redelivery would only throw again. A run that could not be
completed is the deployment's problem: refusing it keeps the provider's
redelivery, and the webhook arrives again once the problem is fixed.

A `result` the runner cannot read is on the "failed run" side, because it is
in the reference too: there `result` is read and its `data` handed to `track`
inside the route's outer `try` (`tools.router.ts:253`, `:304-320`), whose
`catch` answers `400` — not inside the script's own `try`, which has already
ended. The detail goes to the runner's log; the error the auth function logs
is fixed text, since a script's exception message can quote the body.

Two type rules come from the core's result type: `data` is kept only when it is
a JSON object (an array or a string is dropped, not wrapped), and `userId` and
`tenantId` only when they are strings.

**The await is this product's, not the reference's.** The reference's code
means to await the script — it keeps the promise, attaches a `.catch` and
awaits it (`tools.router.ts:289-298`), and its own documented example is
`await actions['billing.cancelSubscription'](…); result = {…}` — but it tests
the promise with `instanceof Promise`, and a promise made inside a `node:vm`
context belongs to that context's realm, so the test is `false`, the await is
skipped and `result` is read before the script's first `await` has settled.
(Verified in Node 24; identical in 1.9.0 and 1.10.8.) So a script ported from
the reference behaves differently here in three cases, all registered as
`inbound-webhook-scripts-are-awaited`:

- a `result` assigned **after** an `await` is tracked here, and nothing there;
- a `result` assigned before an `await` that never settles is tracked there,
  and is no result here;
- a rejected `await` is a logged, acknowledged throw here, and an unhandled
  rejection there.

This product awaits because that is what the reference's code says it does
and the only way a script that calls an action can act on the outcome. The
reference's fix is one line (`util.types.isPromise(returnValue)`, or a
thenable check).

Remember what `userId` and `tenantId` mean on the record: a principal named by
a request **nothing authenticated**. The route has no guard and checks no
provider signature, in the reference and here; whoever can reach
`POST <tools>/webhook/{provider}` can run the stored script for any provider
name they guess.

## 3. The deadline

`tools.inboundWebhooks.scriptTimeoutMs` (default 5000, the reference's number)
bounds the **whole** run — parsing, the script, every `await`, reading the
result. The reference's `{ timeout: 5_000 }` bounds only the part before the
first `await`; the rest there has no bound at all.

It is enforced three times, on purpose: the auth function stops waiting at the
deadline; it tells the runner the same instant less 250 ms so the runner stops
the script first and says why; and the runner's own `Timeout`
(`ScriptRunnerTimeout`, the deadline in seconds plus one) is the backstop.
**Raise `ScriptRunnerTimeout` with `InboundScriptTimeoutMs`**; the template
test pins the defaults together.

A run that reaches the deadline is refused and redelivered, where the
reference's synchronous timeout would have been caught and acknowledged. So a
script that loops costs a full deadline on **every** delivery and every
redelivery, which is why `ScriptRunnerDurationAlarm` exists.

## 4. Actions

An action is how a script *does* something — suspends a user, deprovisions a
tenant. In the reference it is a method decorated with `@webhookAction` that
runs with the API process's credentials. Here it is an entry in the runner's
manifest (`internal/scriptrunner/manifest.go`, `Shipped()`), and it runs with
the runner role's credentials. **The manifest ships empty**: every action call
on this build is a `TypeError`, reported as a script that threw.

A script can call an action only when all of these hold — the reference's
`buildContext` rule, with the first half resolved by the core and the second by
the runner, and never widened by either:

1. its id is in the settings' `enabledWebhookActions` (the global switch),
2. and in the row's `allowedActions`,
3. and in the runner's manifest,
4. and every id in its `dependsOn` is in (1) ∩ (2).

With no settings store, (1) is empty and nothing is callable.

### Adding an action

Two edits, in one change, and both are the point:

1. **The manifest.** An `Action` in `Shipped()`: its `ID`, the display
   metadata, `DependsOn`, the `IAM` it needs written out, and `Fn`, which
   receives the script's arguments and returns the value the script's `await`
   sees (an error rejects it). `Fn` runs synchronously and must honour its
   `ctx`'s deadline — the engine cannot interrupt Go code. Make it
   **idempotent**, keyed on something in the provider's body: a refused run is
   redelivered and runs again, and a run the auth function gave up on may
   already have acted.
2. **The role.** The same IAM, granted to `ScriptRunnerRole` in
   `infra/sam/template.yaml` — the narrowest resource that works — and
   `script_runner_test.go`'s expected action list updated to say so.

An action added without step 2 fails with `AccessDenied` the first time a
script calls it. That is the sandbox working.

Then enable it: its id into `runtimeSettings.enabledWebhookActions` (or
`PUT <admin>/api/settings`), and into the row's `allowedActions`
(`PATCH <admin>/api/webhooks/{id}`). The console's action list,
`GET <admin>/api/actions`, stays empty whatever the manifest holds: the
imported core answers `[]` and has no seam to be told otherwise
(`admin-actions-list-omits-the-runner-manifest`; the fix is upstream).

## 5. Writing a script, and porting one

Rows are written through the admin console: `POST <admin>/api/webhooks`
creates one (with `"events": []` it receives no outgoing deliveries), and
`PATCH <admin>/api/webhooks/{id}` sets `provider`, `jsScript` and
`allowedActions` — the create route does not read those three, in the
reference or here. A deactivated row's script **still runs**
(`isActive` is not consulted by the inbound route, in either tree); clear the
script to stop it.

The engine is [goja](https://github.com/dop251/goja), not V8. Chosen over a
Node.js runner because it keeps one language, one pinned build image and
byte-reproducible artifacts in a Go repository; what that costs a script
written against the reference:

- **There**: `async`/`await`, arrow functions, template literals,
  destructuring, spread, optional chaining, `??`, classes and private fields,
  regular-expression lookbehind, `JSON`, `Math`, `Date`, `Map`/`Set`,
  `BigInt` (`TestTheLanguageAScriptUsesIsThere`).
- **Not there**: `Intl` — `toLocaleString` formats without locale data, and
  `new Intl.NumberFormat(...)` is a `ReferenceError` — `WebAssembly`,
  `SharedArrayBuffer`/`Atomics`. Neither tree has `require`, `fetch`,
  `process`, timers or `Buffer` inside the sandbox.
- **Different**: the script is awaited (§2 — the reference means to and does
  not); the deadline (§3); a promise that can never settle is answered at
  once; `console.info` does not exist, there or here.

## 6. Operating it

- **The cold start** logs `inbound webhooks mounted` with the runner's name
  and the deadline, or `inbound webhooks not mounted`.
- **The runner's log group** (`/aws/lambda/<stack>-script-runner`) has one
  line per run — provider, webhook id, outcome, reason, duration — and one per
  script exception, console line (outside production) and failed action. The
  runner itself never writes the body; what a script puts in its own console
  lines or exception messages is the script's doing.
- **`ScriptRunnerDurationAlarm`** fires when a run takes 80 % of the deadline:
  find the provider in that log group and fix or clear its script.
- **A provider dashboard full of 400s** is a failed run: the auth function's
  log has an `auth core` line reading `auth: tools inbound webhook
  "<provider>": …` with the reason — the runner unreachable or not permitted,
  the deadline, a crash.
- **RS-15** refuses a document that mounts the route with no runner named:
  set `tools.inboundWebhooks.scriptRunnerFunction`, or
  `tools.inboundWebhooks.enabled: false`.

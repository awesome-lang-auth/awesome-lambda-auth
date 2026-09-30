package contract

import (
	"fmt"
	"testing"
	"time"
)

// The inbound webhook, black-box: POST <tools>/webhook/{provider} running a
// stored row's jsScript and tracking what it declares (tools.router.ts:250-326).
//
// On the reference the script runs in an in-process node:vm; on this product
// it runs in a Lambda of its own, the script runner (D9d), whose IAM role is
// the sandbox — the wire is the same, which is what this case is for.
//
// # Why the case is opt-in
//
// A script is stored data, not configuration: the suite has to write a
// webhook row with a jsScript before it can POST anything that runs one, and
// the only client-facing way to write a row is the admin console's
// <admin>/api/webhooks. The suite cannot mint an administrator (see
// cases_admin_test.go), so the case needs the credential the operator
// declares for the admin cases and skips without it. And a row with a script
// is a standing capability on the deployment — anyone who can reach the
// unguarded route can run it — so the case removes the row it wrote, and the
// script it stores does nothing but echo the body it is given.
//
// Two departures from the brief's literal shape, both for a shared stack. The
// provider is unique per run rather than "contract", so two runs, or a run
// beside an operator's own "contract" row, never select each other's script
// (the store answers the lowest id for a provider). And the telemetry rows are
// matched on a nonce in the body rather than counted, because the event name
// is a fixed identity.* name that real traffic on the deployment may also
// carry.

// CapToolsInboundWebhooks is POST <tools>/webhook/{provider}: mounted by the
// reference whenever a webhook store answering findByProvider or an onWebhook
// callback exists (:250), and by this product with tools.inboundWebhooks
// enabled and a script runner named. Probed anonymously, because the route has
// no guard on either tree (:251), with a provider no row can name: the answer
// is the route's own 200 {"ok":true}, or 404 when it is not mounted.
const CapToolsInboundWebhooks Capability = "tools-inbound-webhooks"

func init() {
	registerCapability(capabilityDecl{
		Name:  CapToolsInboundWebhooks,
		Stage: stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			provider := fmt.Sprintf("contract-probe-%d", time.Now().UnixNano())
			r := p.Env.NewClient().POST(t, p.Env.tools("/webhook/"+provider), body{})
			switch r.Status {
			case 200:
				p.Set(CapToolsInboundWebhooks, capability{state: capOn, why: fmt.Sprintf("%s answered 200 for a provider with no row", r.Target)})
			case 404:
				p.Set(CapToolsInboundWebhooks, capability{state: capAbsent, why: fmt.Sprintf(
					"%s answered 404 — the inbound route is not mounted (tools.inboundWebhooks.enabled is off, or no script runner is named)", r.Target)})
			default:
				p.Set(CapToolsInboundWebhooks, capability{state: capBroken, why: fmt.Sprintf(
					"%s answered %d %s to a provider with no row; the reference acknowledges it with 200 {\"ok\":true} (:322)", r.Target, r.Status, r.snippet())})
			}
		},
	})
}

func init() {
	register(
		Case{
			Name: "tools/inbound-webhook-script-result-is-tracked",
			Doc: "reference tools.router.ts:250-322 — a webhook row whose jsScript assigns result = {event, data: body} is run by POST " +
				"<tools>/webhook/{provider}, which answers 200 {\"ok\":true}, and the declared event is on GET <tools>/telemetry with the " +
				"body as its data. Opt-in: the row is written through <admin>/api/webhooks (create, then PATCH provider and jsScript, the " +
				"two members the create route does not read, admin.router.ts:1393), so it needs the operator's declared administrator",
			Needs: []Capability{CapTools, CapToolsTelemetry, CapToolsInboundWebhooks, CapAdmin, CapAdminSession, CapAdminCredential},
			Run: func(t *testing.T, e *Env) {
				admin := adminLogin(t, e)
				webhooks := adminPath() + "/api/webhooks"

				// events [] subscribes the row to nothing, so it never
				// becomes an outgoing delivery to the unused URL.
				created := admin.POST(t, webhooks, body{"url": "https://contract.invalid/unused", "events": []string{}})
				created.mustStatus(t, 200)
				row, _ := created.obj(t)["webhook"].(map[string]any)
				id, _ := row["id"].(string)
				if id == "" {
					t.Fatalf("POST %s answered no webhook.id: %s", webhooks, created.where())
				}
				t.Cleanup(func() { admin.DELETE(t, webhooks+"/"+id) })

				nonce := fmt.Sprintf("n%d", time.Now().UnixNano())
				provider := "contract-" + nonce
				const event = "identity.tenant.user.removed"
				admin.PATCH(t, webhooks+"/"+id, body{
					"provider": provider,
					"jsScript": "result = {event: '" + event + "', data: body}",
				}).mustStatus(t, 200)

				r := e.NewClient().POST(t, e.tools("/webhook/"+provider), body{"nonce": nonce, "kind": "contract"})
				r.mustStatus(t, 200)
				if m := r.obj(t); m["ok"] != true || len(m) != 1 {
					t.Errorf("body = %v, want exactly {\"ok\":true} (:322)\n  %s", m, r.where())
				}

				_, _, token := e.LoginBearer(t)
				deadline := time.Now().Add(10 * time.Second)
				for {
					_, rows := telemetryRows(t, e, token, "event="+event)
					for _, row := range rows {
						if data, _ := row["data"].(map[string]any); data["nonce"] == nonce {
							if data["kind"] != "contract" {
								t.Errorf("the tracked data = %v, want the body the script was handed", data)
							}
							return
						}
					}
					if time.Now().After(deadline) {
						t.Fatalf("no %s row with nonce %s on GET %s after 10 s: the script's result was not tracked", event, nonce, e.tools("/telemetry")[1:])
					}
					time.Sleep(250 * time.Millisecond)
				}
			},
		},
	)
}

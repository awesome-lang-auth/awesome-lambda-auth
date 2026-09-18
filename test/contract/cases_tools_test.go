package contract

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The tools router, black-box: POST <tools>/track/{eventName}, POST
// <tools>/notify/{target}, GET <tools>/telemetry and the router's own
// documentation pair.
//
// The reference mounts createToolsRouter beside its auth router, wherever the
// host puts it (tools.router.ts:114); its own pins are tests/tools.test.ts. The
// mount is Env.ToolsPath, "/tools" by default, and every path here goes through
// Env.tools so the suite never assumes the router sits under the api prefix.
//
// Every guarded call is made with a bearer login rather than the cookie
// session, and that is a statement about the wire, not a convenience: the
// tools router carries none of the auth router's middleware — no CSRF
// double-submit in particular — so a bearer caller with no cookie jar at all
// is the honest shape of a server-to-server client, which is who this router
// is for.
//
// What is deliberately *not* here: the stream. GET <tools>/stream on this
// product is the registered deviation tools-stream-is-not-mounted-on-api-gateway
// and answers 404 in every configuration; against the reference it is a
// long-lived text/event-stream. A case that had to hold a connection open would
// flake on one and skip on the other, so the route is pinned in
// cmd/auth/tools_test.go instead, where the absence is the assertion.

// trackedEventName is unique per run so a deployment that keeps telemetry
// never answers a query with another run's rows.
func trackedEventName(prefix string) string {
	return fmt.Sprintf("contract.%s.%d", prefix, time.Now().UnixNano())
}

// telemetryRows fetches GET <tools>/telemetry with the given query and decodes
// the reference's {"data":[...]} envelope (tools.router.ts:244).
func telemetryRows(t *testing.T, e *Env, token, query string) (*Resp, []map[string]any) {
	t.Helper()
	r := e.NewClient().GET(t, e.tools("/telemetry?"+query), Bearer(token))
	r.mustStatus(t, 200)
	var envelope struct {
		Data []map[string]any `json:"data"`
	}
	if err := json.Unmarshal(r.Body, &envelope); err != nil {
		t.Fatalf("telemetry body is not the {data:[...]} envelope (%v)\n  %s", err, r.where())
	}
	if envelope.Data == nil {
		t.Fatalf("telemetry data is null; the reference answers an array, empty or not\n  %s", r.where())
	}
	return r, envelope.Data
}

// awaitTelemetry polls the query until it returns at least want rows or the
// deadline passes. The telemetry write is awaited by the route before it
// answers (auth-tools.ts:216-219), so against an in-process store one poll is
// enough; against a deployed store read through a different execution
// environment the write is durable but the read may lag, and a bound is the
// honest way to say so.
func awaitTelemetry(t *testing.T, e *Env, token, query string, want int) []map[string]any {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		_, rows := telemetryRows(t, e, token, query)
		if len(rows) >= want || time.Now().After(deadline) {
			return rows
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func init() {
	register(
		Case{
			Name:  "tools/track-answers-202-ok",
			Doc:   "reference tools.router.ts:140-160, pinned at tests/tools.test.ts — POST <tools>/track/{eventName} with a JSON body is 202 with exactly {\"ok\":true}; the fan-out's outcome is never reported, because track is awaited and the 202 is written regardless of what the sinks did",
			Needs: []Capability{CapTools},
			Run: func(t *testing.T, e *Env) {
				_, _, token := e.LoginBearer(t)
				r := e.NewClient().POST(t, e.tools("/track/"+trackedEventName("ok")),
					body{"data": map[string]any{"amount": 12, "currency": "EUR"}}, Bearer(token))
				r.mustStatus(t, 202)
				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("Content-Type = %q, want application/json\n  %s", ct, r.where())
				}
				m := r.obj(t)
				if m["ok"] != true || len(m) != 1 {
					t.Errorf("body = %v, want exactly {\"ok\":true}\n  %s", m, r.where())
				}
				// The router carries no CSRF middleware and this is a bearer
				// caller, so nothing here may set a cookie.
				if len(r.SetCookie) != 0 {
					t.Errorf("track set cookies %v on a bearer call; the tools router carries no cookie-setting middleware\n  %s", r.SetCookie, r.where())
				}
			},
		},

		Case{
			Name:  "tools/tracked-event-is-visible-on-telemetry",
			Doc:   "reference auth-tools.ts:216-219 and tools.router.ts:226-245 — a tracked event is persisted before the 202 is written, and GET <tools>/telemetry?event=<name> then returns it in the {\"data\":[...]} envelope, as a record keyed event/data/userId/timestamp with the caller as userId when the body named none (tools.router.ts:147)",
			Needs: []Capability{CapTools, CapToolsTelemetry},
			Run: func(t *testing.T, e *Env) {
				c, _, token := e.LoginBearer(t)
				me := c.GET(t, "/me", Bearer(token)).mustStatus(t, 200).str(t, "id")

				name := trackedEventName("visible")
				e.NewClient().POST(t, e.tools("/track/"+name), body{"data": map[string]any{"k": "v"}}, Bearer(token)).mustStatus(t, 202)

				rows := awaitTelemetry(t, e, token, "event="+name, 1)
				if len(rows) != 1 {
					t.Fatalf("telemetry holds %d row(s) for %s, want exactly one: a tracked event is persisted exactly once", len(rows), name)
				}
				row := rows[0]
				if row["event"] != name {
					t.Errorf("row event = %v, want %q", row["event"], name)
				}
				if row["userId"] != me {
					t.Errorf("row userId = %v, want the caller %q: with no userId in the body the route attributes the event to the principal", row["userId"], me)
				}
				data, _ := row["data"].(map[string]any)
				if data["k"] != "v" {
					t.Errorf("row data = %v, want the tracked payload under `data`", row["data"])
				}
				if _, ok := row["timestamp"].(string); !ok {
					t.Errorf("row timestamp = %v, want an ISO 8601 string", row["timestamp"])
				}
				if _, ok := row["success"]; ok {
					t.Errorf("row carries `success`, which the reference's telemetry record does not have\n  %v", row)
				}
			},
		},

		Case{
			Name:  "tools/telemetry-filters-by-user",
			Doc:   "reference tools.router.ts:234-243 — GET <tools>/telemetry?event=<name>&userId=<id> returns only that user's rows for the event; two users tracking the same name are told apart by the filter",
			Needs: []Capability{CapTools, CapToolsTelemetry},
			Run: func(t *testing.T, e *Env) {
				a, _, tokenA := e.LoginBearer(t)
				b, _, tokenB := e.LoginBearer(t)
				idA := a.GET(t, "/me", Bearer(tokenA)).mustStatus(t, 200).str(t, "id")
				idB := b.GET(t, "/me", Bearer(tokenB)).mustStatus(t, 200).str(t, "id")

				name := trackedEventName("filter")
				e.NewClient().POST(t, e.tools("/track/"+name), body{}, Bearer(tokenA)).mustStatus(t, 202)
				e.NewClient().POST(t, e.tools("/track/"+name), body{}, Bearer(tokenB)).mustStatus(t, 202)

				// Both are there first, so a filter that returned one row
				// could not be passing because only one was ever written.
				both := awaitTelemetry(t, e, tokenA, "event="+name, 2)
				if len(both) != 2 {
					t.Fatalf("telemetry holds %d row(s) for %s across both users, want 2", len(both), name)
				}
				onlyA := awaitTelemetry(t, e, tokenA, "event="+name+"&userId="+idA, 1)
				if len(onlyA) != 1 || onlyA[0]["userId"] != idA {
					t.Errorf("filtered by userId=%s: %v, want exactly that user's one row", idA, onlyA)
				}
				for _, row := range onlyA {
					if row["userId"] == idB {
						t.Errorf("the userId filter leaked another user's row: %v", row)
					}
				}
			},
		},

		Case{
			Name:  "tools/notify-answers-202-ok",
			Doc:   "reference tools.router.ts:165-179 — POST <tools>/notify/{target} is 202 {\"ok\":true} whether or not anything holds the topic: notify is not awaited and a broadcast to nobody is not an error",
			Needs: []Capability{CapTools},
			Run: func(t *testing.T, e *Env) {
				_, _, token := e.LoginBearer(t)
				r := e.NewClient().POST(t, e.tools("/notify/user:nobody-is-listening"),
					body{"data": "hello", "type": "greeting"}, Bearer(token))
				r.mustStatus(t, 202)
				m := r.obj(t)
				if m["ok"] != true || len(m) != 1 {
					t.Errorf("body = %v, want exactly {\"ok\":true}\n  %s", m, r.where())
				}
			},
		},

		Case{
			Name:  "tools/wrongly-typed-body-is-400",
			Doc:   "core deviation tools-request-bodies-are-typed — a track body whose member has the wrong type ({\"userId\":5}) is 400 with the tools router's bare {\"error\":\"Invalid request body\"} envelope and nothing else, rather than a 202 that recorded something other than what was sent",
			Needs: []Capability{CapTools},
			Run: func(t *testing.T, e *Env) {
				_, _, token := e.LoginBearer(t)
				r := e.NewClient().POST(t, e.tools("/track/"+trackedEventName("typed")), body{"userId": 5}, Bearer(token))
				r.mustStatus(t, 400)
				m := r.obj(t)
				if m["error"] != "Invalid request body" {
					t.Errorf("error = %v, want %q\n  %s", m["error"], "Invalid request body", r.where())
				}
				if len(m) != 1 {
					t.Errorf("the tools envelope is a bare {error}, got %d keys: %v\n  %s", len(m), keysOf(m), r.where())
				}
			},
		},

		Case{
			Name:  "tools/guarded-routes-refuse-a-bare-caller",
			Doc:   "reference tools.router.ts:135, :141, :166, :227 — track, notify and the telemetry query sit behind the host's auth middleware, so a caller presenting nothing is refused (401 or 403, the middleware's own status) and never answers 202",
			Needs: []Capability{CapTools},
			Run: func(t *testing.T, e *Env) {
				for _, path := range []string{"/track/" + trackedEventName("bare"), "/notify/user:nobody"} {
					r := e.NewClient().POST(t, e.tools(path), body{})
					r.mustStatusIn(t, 401, 403)
				}
				r := e.NewClient().GET(t, e.tools("/telemetry"))
				// 404 is the query route not being mounted at all (no store);
				// with it mounted, the guard answers before the store does.
				r.mustStatusIn(t, 401, 403, 404)
			},
		},

		Case{
			Name:  "tools/openapi-document-is-served-anonymously",
			Doc:   "reference tools.router.ts:332-345 — GET <tools>/openapi.json is 200 application/json with an OpenAPI 3.0.3 document, served with no credential, whose path items sit under the tools base and include the track route",
			Needs: []Capability{CapToolsDocs},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, e.tools("/openapi.json"))
				r.mustStatus(t, 200)
				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Errorf("Content-Type = %q, want application/json\n  %s", ct, r.where())
				}
				var document struct {
					OpenAPI string                     `json:"openapi"`
					Paths   map[string]json.RawMessage `json:"paths"`
				}
				if err := json.Unmarshal(r.Body, &document); err != nil {
					t.Fatalf("the served document is not JSON (%v)\n  %s", err, r.where())
				}
				if document.OpenAPI != "3.0.3" {
					t.Errorf("openapi = %q, want %q\n  %s", document.OpenAPI, "3.0.3", r.where())
				}
				base := ""
				for path := range document.Paths {
					if strings.HasSuffix(path, "/track/{eventName}") {
						base = strings.TrimSuffix(path, "/track/{eventName}")
					}
				}
				if base == "" {
					t.Fatalf("no path item ends in /track/{eventName}, so the document does not describe the tools router: %v\n  %s",
						sortedPaths(document.Paths), r.where())
				}
				for _, path := range sortedPaths(document.Paths) {
					if !strings.HasPrefix(path, base+"/") {
						t.Errorf("path item %q is not under the documented base %q\n  %s", path, base, r.where())
					}
				}
			},
		},

		Case{
			Name:  "tools/swagger-page-points-at-the-document-beside-it",
			Doc:   "reference tools.router.ts:347-352 — GET <tools>/docs is 200 text/html; charset=utf-8 carrying the Swagger UI page, served with no credential, and the spec url it hands SwaggerUIBundle is a document this same deployment serves",
			Needs: []Capability{CapToolsDocs},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, e.tools("/docs"))
				r.mustStatus(t, 200)
				if ct := r.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
					t.Errorf("Content-Type = %q, want %q\n  %s", ct, "text/html; charset=utf-8", r.where())
				}
				page := string(r.Body)
				if !strings.Contains(page, "swagger-ui") {
					t.Fatalf("the page does not look like a Swagger UI shell\n  %s", r.where())
				}
				match := swaggerSpecURL.FindStringSubmatch(page)
				if match == nil {
					t.Fatalf("the page names no spec url, so it has nothing to render\n  %s", r.where())
				}
				spec := e.NewClient().GET(t, "!"+toolsSpecPathOf(t, e, match[1]))
				spec.mustStatus(t, 200)
				if !spec.hasKey(t, "openapi") {
					t.Errorf("the url the page fetches does not serve an OpenAPI document\n  %s", spec.where())
				}
			},
		},
	)
}

// toolsSpecPathOf is specPathOf for the tools page, whose relative default
// resolves against the tools mount rather than the api prefix.
func toolsSpecPathOf(t *testing.T, e *Env, raw string) string {
	t.Helper()
	path := specPathOf(t, e, raw)
	if strings.HasPrefix(path, e.Prefix+"/") && !strings.HasPrefix(raw, "/") && !strings.Contains(raw, "://") {
		return e.ToolsPath + "/" + strings.TrimPrefix(raw, "./")
	}
	return path
}

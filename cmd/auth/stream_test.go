package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
	ddbstore "github.com/nik2208/awesome-lambda-auth/internal/store/dynamodb"
)

// The SSE function (D9c), driven end to end: the auth function publishes, the
// SSE function streams, both built by New from the same document over one
// DynamoDB Local table — the deployed arrangement with the network taken out.
// The stream is read through lambdahttp's streaming adapter, which is what the
// Lambda runtime drives, and the route behind it is the core's own: the token
// middleware, the guard, StreamTopics and SseManager.Serve.
//
// Every wait is bounded and none is a heartbeat: the heartbeat stays at its
// 30-second default and no assertion depends on one.

// sseEnv is a tools document with the event log as the distributor.
func sseEnv(table, endpoint string, kv ...string) map[string]string {
	return with(toolsEnv(
		"AWESOME_AUTH_STORES_DRIVER", config.StoreDriverDynamoDB,
		"AWESOME_AUTH_STORES_CONNECTION_TABLE_NAME", table,
		"AWESOME_AUTH_STORES_CONNECTION_REGION", "us-east-1",
		"AWESOME_AUTH_STORES_CONNECTION_ENDPOINT", endpoint,
		"AWESOME_AUTH_SSE_ENABLED", "true",
		"AWESOME_AUTH_TOOLS_SSE_DISTRIBUTOR_TYPE", config.DistributorDynamoDB,
		"AWESOME_AUTH_TOOLS_SSE_POLL_INTERVAL_MS", "100",
	), kv...)
}

// sseTable opens a fresh DynamoDB Local table and returns a factory over one
// store on it, shared by the two Apps as the one table is shared by the two
// functions.
func sseTable(t *testing.T) (StoreFactory, string, string) {
	t.Helper()
	endpoint, ok := localDynamoDBEndpoint()
	if !ok {
		t.Skip("DYNAMODB_ENDPOINT is not set; start DynamoDB Local and set it to run the SSE function end to end")
	}
	// Not parallel, for the reason TestDynamoDBBackedRoutesFindEveryStore
	// gives: the SDK reads its credentials from the environment.
	t.Setenv("AWS_ACCESS_KEY_ID", "local")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "local")
	t.Setenv("AWS_REGION", "us-east-1")

	ctx := context.Background()
	table := "authtest_cmd_sse_" + randomSuffix(t)
	client, err := awsintegration.NewDynamoDBClient(ctx, awsintegration.DynamoDBOptions{Region: "us-east-1", Endpoint: endpoint})
	if err != nil {
		t.Skipf("cannot build a DynamoDB client for %s (dynamodb local): %v", endpoint, err)
	}
	if err := ddbstore.CreateTable(ctx, client, table); err != nil {
		t.Skipf("cannot create %s at %s (%v); start DynamoDB Local with: docker run -d --name ddblocal -p 8000:8000 amazon/dynamodb-local", table, endpoint, err)
	}
	store, err := ddbstore.New(client, ddbstore.Options{TableName: table, Logger: discardLogger()})
	if err != nil {
		t.Fatalf("ddbstore.New: %v", err)
	}
	factory := func(context.Context, *config.Config, *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
		return store, store, nil
	}
	return factory, table, endpoint
}

func newSseApp(t *testing.T, env map[string]string, factory StoreFactory) *App {
	t.Helper()
	app, err := New(context.Background(), Options{Getenv: envFunc(env), Logger: discardLogger(), Stores: factory})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(app.Close)
	return app
}

// sseFrame is one parsed block of the stream: the fields and the comment lines.
type sseFrame struct {
	id, event, data string
	hasID           bool
	comments        []string
}

// openStream opens GET <path> on the SSE function and returns a channel of
// frames and the function that ends the connection.
func openStream(t *testing.T, app *App, rawQuery string, headers map[string]string) (*events.LambdaFunctionURLStreamingResponse, <-chan sseFrame, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	evt := &events.LambdaFunctionURLRequest{RawPath: "/tools/stream", RawQueryString: rawQuery, Headers: headers}
	evt.RequestContext.HTTP.Method = http.MethodGet
	evt.RequestContext.HTTP.Path = "/tools/stream"
	evt.RequestContext.HTTP.SourceIP = "198.51.100.7"
	evt.RequestContext.DomainName = "sse.lambda-url.eu-west-1.on.aws"
	resp, err := app.StreamHandler()(ctx, evt)
	if err != nil {
		cancel()
		t.Fatalf("stream handler: %v", err)
	}
	frames := make(chan sseFrame, 64)
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer close(frames)
		readFrames(resp.Body, frames)
	}()
	stop := func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Errorf("the stream did not end after its context was cancelled")
		}
	}
	t.Cleanup(stop)
	return resp, frames, stop
}

func readFrames(body io.Reader, out chan<- sseFrame) {
	r := bufio.NewReader(body)
	var f sseFrame
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSuffix(line, "\n")
		switch {
		case line == "":
			out <- f
			f = sseFrame{}
		case strings.HasPrefix(line, ":"):
			f.comments = append(f.comments, line)
		case strings.HasPrefix(line, "id: "):
			f.id, f.hasID = strings.TrimPrefix(line, "id: "), true
		case strings.HasPrefix(line, "event: "):
			f.event = strings.TrimPrefix(line, "event: ")
		case strings.HasPrefix(line, "data: "):
			f.data = strings.TrimPrefix(line, "data: ")
		}
	}
}

func nextFrame(t *testing.T, frames <-chan sseFrame, what string) sseFrame {
	t.Helper()
	select {
	case f, ok := <-frames:
		if !ok {
			t.Fatalf("the stream ended before %s", what)
		}
		return f
	case <-time.After(15 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
	return sseFrame{}
}

// nextEvent skips heartbeats and returns the next frame with an event line.
func nextEvent(t *testing.T, frames <-chan sseFrame, what string) sseFrame {
	t.Helper()
	for {
		f := nextFrame(t, frames, what)
		if f.event != "" {
			return f
		}
	}
}

// subjectOf reads the user id out of an access token's payload.
func subjectOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Sub == "" {
		t.Fatalf("token payload %s: %v", raw, err)
	}
	return claims.Sub
}

func notify(t *testing.T, app *App, token, target, eventType string, data any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"type": eventType, "data": data})
	headers := jsonHeaders("authorization", "Bearer "+token)
	resp := invoke(t, app, http.MethodPost, "/tools/notify/"+target, headers, nil, string(body))
	if resp.StatusCode/100 != 2 {
		t.Fatalf("notify %s = %d (body %s)", target, resp.StatusCode, resp.Body)
	}
}

// TestTheSSEFunctionStreamsWhatTheAuthFunctionPublishes is the block end to
// end: ?token= reaches the guard, the connected frame and the cursor frame
// arrive, an event published by the other function arrives as the reference's
// frame, a cancelled context ends the stream, and a reconnect with the
// captured id replays what it missed and not what it had.
func TestTheSSEFunctionStreamsWhatTheAuthFunctionPublishes(t *testing.T) {
	factory, table, endpoint := sseTable(t)
	authApp := newSseApp(t, sseEnv(table, endpoint), factory)
	streamApp := newSseApp(t, sseEnv(table, endpoint, EntrypointEnv, entrypointStream), factory)
	if !streamApp.Streams() || authApp.Streams() {
		t.Fatalf("Streams() = %v / %v, want the stream role on the SSE function alone", streamApp.Streams(), authApp.Streams())
	}

	token := registerAndToken(t, authApp, "sse-"+randomSuffix(t)+"@example.test").accessToken
	uid := subjectOf(t, token)

	// ?token= alone — no Authorization header, no cookie — so the only way the
	// guard can admit this is the core's token middleware having run first.
	resp, frames, stop := openStream(t, streamApp, "token="+token, nil)
	if resp.StatusCode != http.StatusOK || resp.Headers["Content-Type"] != "text/event-stream" {
		t.Fatalf("stream prelude = %d %v", resp.StatusCode, resp.Headers)
	}
	connected := nextFrame(t, frames, "the connected frame")
	if connected.event != "connected" {
		t.Fatalf("first frame = %+v, want connected", connected)
	}
	var payload struct {
		RawData struct {
			Topics []string `json:"topics"`
		} `json:"rawData"`
	}
	if err := json.Unmarshal([]byte(connected.data), &payload); err != nil {
		t.Fatalf("connected data %q: %v", connected.data, err)
	}
	if got, want := strings.Join(payload.RawData.Topics, ","), "global,user:"+uid; got != want {
		t.Errorf("connected topics = %s, want %s: the token middleware ran after the guard, or StreamTopics changed", got, want)
	}
	cursor := nextFrame(t, frames, "the cursor frame")
	if !cursor.hasID || cursor.event != "" || cursor.data != "" || len(cursor.id) != 26 {
		t.Fatalf("second frame = %+v, want an id-only frame carrying a ULID", cursor)
	}

	notify(t, authApp, token, "user:"+uid, "order.shipped", map[string]any{"order": 7, "note": "<b>&</b>"})
	first := nextEvent(t, frames, "the published event")
	if first.event != "order.shipped" || len(first.id) != 26 {
		t.Fatalf("event frame = %+v, want order.shipped with a ULID id", first)
	}
	var frame map[string]any
	if err := json.Unmarshal([]byte(first.data), &frame); err != nil {
		t.Fatalf("event data %q: %v", first.data, err)
	}
	if _, ok := frame["data"]; ok {
		t.Errorf("the frame carries a `data` key: the payload belongs under rawData (sse.go, sseFrame): %s", first.data)
	}
	if raw, _ := frame["rawData"].(map[string]any); raw["note"] != "<b>&</b>" {
		t.Errorf("rawData = %v", frame["rawData"])
	}
	if frame["id"] != first.id {
		t.Errorf("data.id %v differs from the id line %s", frame["id"], first.id)
	}
	if !strings.Contains(first.data, `"note":"<b>&</b>"`) {
		t.Errorf("the payload was HTML-escaped on its way through the log: %s", first.data)
	}
	stop()

	// Disconnected: this one is missed, and must be replayed.
	notify(t, authApp, token, "user:"+uid, "order.delivered", map[string]any{"order": 7})

	_, frames, stop = openStream(t, streamApp, "token="+token, map[string]string{"last-event-id": first.id})
	if f := nextFrame(t, frames, "the connected frame on resume"); f.event != "connected" {
		t.Fatalf("first frame on resume = %+v", f)
	}
	if f := nextFrame(t, frames, "the cursor frame on resume"); f.id != first.id || len(f.comments) != 0 {
		t.Errorf("cursor frame on resume = %+v, want the client's own cursor and no comment", f)
	}
	replayed := nextEvent(t, frames, "the replayed event")
	if replayed.event != "order.delivered" {
		t.Fatalf("replayed %q, want the event raised while disconnected and not the one before the cursor", replayed.event)
	}
	if replayed.id <= first.id {
		t.Errorf("replayed id %s does not sort after the cursor %s", replayed.id, first.id)
	}
	stop()
}

// TestTheSSEFunctionAnswersTheStreamAlone: the Function URL is a second front
// door, and it opens onto one route.
func TestTheSSEFunctionAnswersTheStreamAlone(t *testing.T) {
	factory, table, endpoint := sseTable(t)
	streamApp := newSseApp(t, sseEnv(table, endpoint, EntrypointEnv, entrypointStream), factory)

	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/auth/login"},
		{http.MethodPost, "/auth/register"},
		{http.MethodGet, "/healthz"},
		{http.MethodPost, "/tools/track/x"},
		{http.MethodPost, "/tools/notify/global"},
		{http.MethodGet, "/tools/telemetry"},
		{http.MethodPost, "/tools/stream"},
		{http.MethodGet, "/tools/stream/"},
	} {
		rec := httptest.NewRecorder()
		streamApp.Handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}")))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s %s on the SSE function = %d, want 404", tc.method, tc.path, rec.Code)
		}
	}
	// And the stream itself is guarded: no credential, no stream.
	rec := httptest.NewRecorder()
	streamApp.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/tools/stream", nil))
	if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
		t.Errorf("GET /tools/stream with no credential = %d, want the guard's refusal", rec.Code)
	}
}

// TestTheStreamHookFollowsTheTopicsTheCoreGrants: the hook computes the topics
// it follows itself, because the core's parse of ?topics= is unexported; the
// two must agree on every shape the reference's parse distinguishes.
func TestTheStreamHookFollowsTheTopicsTheCoreGrants(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		values []string
		want   []string
	}{
		{"absent", nil, nil},
		{"one list", []string{" global , user:u1,,"}, []string{"global", "user:u1"}},
		{"empty", []string{""}, []string{}},
		{"repeated", []string{"global", "user:u1"}, nil},
	} {
		got := streamRequestedTopics(tc.values)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") || (got == nil) != (tc.want == nil) {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	// And through StreamTopics the two shapes the core cares about: no
	// request is the whole authorised list, an empty one is too.
	if got := auth.StreamTopics("u1", "", streamRequestedTopics([]string{""})); strings.Join(got, ",") != "global,user:u1" {
		t.Errorf("an empty ?topics= resolved to %v", got)
	}
}

// TestTheStreamRoleRefusesWhatCannotStream: an SSE function that could serve
// nothing refuses the cold start rather than bill an invocation per retry.
func TestTheStreamRoleRefusesWhatCannotStream(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"an unknown entry point", with(baseEnv(), EntrypointEnv, "websocket"), "entry points"},
		{"no tools block", with(baseEnv(), EntrypointEnv, entrypointStream), "tools.enabled is off"},
		{"no SSE manager", toolsEnv(EntrypointEnv, entrypointStream), "tools.sse.enabled is off"},
		{"no event log", toolsEnv(EntrypointEnv, entrypointStream, "AWESOME_AUTH_SSE_ENABLED", "true"), "event log"},
	} {
		_, err := New(context.Background(), Options{Getenv: envFunc(tc.env), Logger: discardLogger(), Stores: memoryStores})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: New = %v, want a refusal mentioning %q", tc.name, err, tc.want)
		}
	}
}

// TestTheResumePreludeFollowsTheConnectedFrame pins the bytes the hook adds,
// and that it adds them to an event stream only.
func TestTheResumePreludeFollowsTheConnectedFrame(t *testing.T) {
	t.Parallel()
	const floor = "01J8Z6R4Q0000000000000000A"
	cases := []struct {
		resume ddbstore.SseResume
		want   string
	}{
		{ddbstore.SseResume{Floor: floor}, "id: " + floor + "\n\n"},
		{ddbstore.SseResume{Floor: floor, Replay: true, Truncated: true}, sseTruncatedComment + "id: " + floor + "\n\n"},
		{ddbstore.SseResume{Floor: floor, Unrecognised: true}, sseUnrecognisedComment + "id: " + floor + "\n\n"},
	}
	for _, tc := range cases {
		rec := httptest.NewRecorder()
		w := &resumeWriter{ResponseWriter: rec, prelude: resumePrelude(tc.resume)}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("id: x\nevent: connected\ndata: {}\n\n"))
		_, _ = w.Write([]byte(": heartbeat\n\n"))
		if got, want := rec.Body.String(), "id: x\nevent: connected\ndata: {}\n\n"+tc.want+": heartbeat\n\n"; got != want {
			t.Errorf("stream = %q, want %q", got, want)
		}
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("the writer hides Flush: %v", err)
		}
	}
	rec := httptest.NewRecorder()
	w := &resumeWriter{ResponseWriter: rec, prelude: resumePrelude(cases[0].resume)}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"error":"SSE not enabled"}`))
	if strings.Contains(rec.Body.String(), "id:") {
		t.Errorf("the prelude was appended to a response that is not a stream: %q", rec.Body.String())
	}
}

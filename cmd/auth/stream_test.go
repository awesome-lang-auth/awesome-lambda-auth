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
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
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
	return sseTableWith(t, nil)
}

// sseTableWith is sseTable with the store's DynamoDB client wrapped, so a test
// can observe what the composition reads.
func sseTableWith(t *testing.T, wrap func(ddbstore.API) ddbstore.API) (StoreFactory, string, string) {
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
	var api ddbstore.API = client
	if wrap != nil {
		api = wrap(client)
	}
	store, err := ddbstore.New(api, ddbstore.Options{TableName: table, Logger: discardLogger()})
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
	// The resume looks below the cursor (the late-visible event's window), so
	// what it delivers first may be events older than the cursor — here the
	// registration's own, published moments before the first connection —
	// which at-least-once permits. The cursor's own event is never among
	// them, and the missed event arrives after them.
	for {
		replayed := nextEvent(t, frames, "the replayed event")
		if replayed.event == "order.shipped" {
			t.Fatalf("the resume replayed the cursor's own event (%s), which the client holds", replayed.id)
		}
		if replayed.event == "order.delivered" {
			if replayed.id <= first.id {
				t.Errorf("replayed id %s does not sort after the cursor %s", replayed.id, first.id)
			}
			break
		}
		if replayed.id >= first.id {
			t.Fatalf("before the missed event the resume delivered %q with id %s, which is not below the cursor %s", replayed.event, replayed.id, first.id)
		}
	}
	stop()
}

// sseQueryCounter counts the Queries that read an SSE event partition: the
// observable trace of the event log being followed.
type sseQueryCounter struct {
	ddbstore.API
	mu sync.Mutex
	n  int
}

func (c *sseQueryCounter) Query(ctx context.Context, in *awsddb.QueryInput, optFns ...func(*awsddb.Options)) (*awsddb.QueryOutput, error) {
	if pk, ok := in.ExpressionAttributeValues[":pk"].(*ddbtypes.AttributeValueMemberS); ok && strings.HasPrefix(pk.Value, "SSE#") {
		c.mu.Lock()
		c.n++
		c.mu.Unlock()
	}
	return c.API.Query(ctx, in, optFns...)
}

func (c *sseQueryCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// TestTheSSEFunctionAnswersTheStreamAlone: the Function URL is a second front
// door, and it opens onto one route and one method, from its outermost
// handler — so no CORS preflight is answered for anything, the stream's own
// path included, and a refused request never follows the event log.
func TestTheSSEFunctionAnswersTheStreamAlone(t *testing.T) {
	const origin = "https://app.example.test"
	for _, posture := range []struct {
		name string
		kv   []string
	}{
		{"session", nil},
		{"apiKey", []string{"AWESOME_AUTH_TOOLS_AUTH", "apiKey", "AWESOME_AUTH_STORES_ENABLE_API_KEYS", "true"}},
		// The tools mount under the api prefix is inside the CORS layer
		// (corsExemptMounts), which is the geometry where a gate that ran
		// after it would answer a preflight on the stream's own path.
		{"session, tools under the prefix", []string{"AWESOME_AUTH_TOOLS_BASE_PATH", "/auth/tools"}},
	} {
		t.Run(posture.name, func(t *testing.T) {
			counter := &sseQueryCounter{}
			factory, table, endpoint := sseTableWith(t, func(api ddbstore.API) ddbstore.API { counter.API = api; return counter })
			kv := append([]string{EntrypointEnv, entrypointStream, "AWESOME_AUTH_CORS_ORIGINS", origin}, posture.kv...)
			streamApp := newSseApp(t, sseEnv(table, endpoint, kv...), factory)
			tools := toolsPath(streamApp.Config)

			for _, tc := range []struct{ method, path string }{
				{http.MethodPost, "/auth/login"},
				{http.MethodOptions, "/auth/login"},
				{http.MethodPost, "/auth/register"},
				{http.MethodGet, "/healthz"},
				{http.MethodPost, tools + "/track/x"},
				{http.MethodPost, tools + "/notify/global"},
				{http.MethodGet, tools + "/telemetry"},
				{http.MethodPost, tools + "/stream"},
				{http.MethodHead, tools + "/stream"},
				{http.MethodOptions, tools + "/stream"},
				{http.MethodGet, tools + "/stream/"},
			} {
				rec := httptest.NewRecorder()
				req := httptest.NewRequest(tc.method, tc.path, strings.NewReader("{}"))
				req.Header.Set("Origin", origin)
				req.Header.Set("Access-Control-Request-Method", http.MethodPost)
				streamApp.Handler.ServeHTTP(rec, req)
				if rec.Code != http.StatusNotFound {
					t.Errorf("%s %s on the SSE function = %d, want 404", tc.method, tc.path, rec.Code)
				}
				if v := rec.Header().Get("Access-Control-Allow-Origin"); v != "" {
					t.Errorf("%s %s on the SSE function carries Access-Control-Allow-Origin %q: the CORS layer ran before the gate", tc.method, tc.path, v)
				}
			}
			// And the stream itself is guarded: no credential, no stream —
			// and no read of the event log, because the hook that follows it
			// sits inside the guard.
			rec := httptest.NewRecorder()
			streamApp.Handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tools+"/stream", nil))
			if rec.Code != http.StatusUnauthorized && rec.Code != http.StatusForbidden {
				t.Errorf("GET %s/stream with no credential = %d, want the guard's refusal", tools, rec.Code)
			}
			if n := counter.count(); n != 0 {
				t.Errorf("%d event-log Queries for requests the SSE function refused: the hook ran outside the guard", n)
			}

			// The control: an admitted stream does read the log, so the zero
			// above is the guard's doing and not a counter that sees nothing.
			if posture.name != "session" {
				return
			}
			authApp := newSseApp(t, sseEnv(table, endpoint, "AWESOME_AUTH_CORS_ORIGINS", origin), factory)
			token := registerAndToken(t, authApp, "sse-gate-"+randomSuffix(t)+"@example.test").accessToken
			_, frames, stop := openStream(t, streamApp, "token="+token, nil)
			if f := nextFrame(t, frames, "the connected frame"); f.event != "connected" {
				t.Fatalf("first frame = %+v", f)
			}
			deadline := time.Now().Add(10 * time.Second)
			for counter.count() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if counter.count() == 0 {
				t.Error("an admitted stream read nothing from the event log: the counter cannot see the reads it guards against")
			}
			stop()
		})
	}
}

// connectedTopics reads rawData.topics off a connected frame: the topics the
// core's own handler granted the connection.
func connectedTopics(t *testing.T, f sseFrame) []string {
	t.Helper()
	var payload struct {
		RawData struct {
			Topics []string `json:"topics"`
		} `json:"rawData"`
	}
	if f.event != "connected" {
		t.Fatalf("frame = %+v, want connected", f)
	}
	if err := json.Unmarshal([]byte(f.data), &payload); err != nil {
		t.Fatalf("connected data %q: %v", f.data, err)
	}
	return payload.RawData.Topics
}

// TestTheStreamHookFollowsTheTopicsTheCoreGrants: the hook computes the topics
// it follows itself, because the core's parse of ?topics= is unexported. So the
// stream is opened end to end with every shape the reference's parse
// distinguishes, and for each the topics the hook followed — StreamTopics over
// streamRequestedTopics, exactly the hook's expression — must equal the
// connected frame's rawData.topics, which is the core's answer, and an event
// notified to each held topic must arrive.
func TestTheStreamHookFollowsTheTopicsTheCoreGrants(t *testing.T) {
	factory, table, endpoint := sseTable(t)
	authApp := newSseApp(t, sseEnv(table, endpoint), factory)
	streamApp := newSseApp(t, sseEnv(table, endpoint, EntrypointEnv, entrypointStream), factory)
	token := registerAndToken(t, authApp, "sse-topics-"+randomSuffix(t)+"@example.test").accessToken
	uid := subjectOf(t, token)

	for _, tc := range []struct {
		name  string
		query url.Values
	}{
		{"absent", url.Values{}},
		{"one list", url.Values{"topics": {" global , user:" + uid + ",,"}}},
		{"reordered", url.Values{"topics": {"user:" + uid + ",global"}}},
		{"empty", url.Values{"topics": {""}}},
		{"repeated", url.Values{"topics": {"global", "user:" + uid}}},
		{"one not authorised", url.Values{"topics": {"user:somebody-else,global"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{"token": {token}}
			for k, v := range tc.query {
				q[k] = v
			}
			_, frames, stop := openStream(t, streamApp, q.Encode(), nil)
			defer stop()
			granted := connectedTopics(t, nextFrame(t, frames, "the connected frame"))
			followed := auth.StreamTopics(uid, "", streamRequestedTopics(tc.query[auth.ToolsStreamTopicsParam]))
			if strings.Join(followed, ",") != strings.Join(granted, ",") {
				t.Fatalf("the hook followed %v, the core granted %v: streamRequestedTopics no longer parses ?topics= as the core does", followed, granted)
			}
			nextFrame(t, frames, "the cursor frame")
			for _, topic := range granted {
				eventType := "topic.check." + strings.ReplaceAll(topic, ":", ".")
				notify(t, authApp, token, topic, eventType, map[string]any{"topic": topic})
				if f := nextEvent(t, frames, "the event on "+topic); f.event != eventType {
					t.Fatalf("on %s the stream delivered %q, want %q", topic, f.event, eventType)
				}
			}
		})
	}
}

// TestOneEventOnTwoTopicsIsFramedAsTheCoreFramesIt: a login is one event on
// global and on user:<id>. In process the core broadcasts it global first, and
// its per-connection deduplication suppresses the second copy — so the frame's
// topic is global even for a connection that listed user:<id> first, and with
// tools.sse.deduplicate off the connection gets both, global then user:<id>.
// Through the log it must be the same.
func TestOneEventOnTwoTopicsIsFramedAsTheCoreFramesIt(t *testing.T) {
	for _, dedup := range []bool{true, false} {
		t.Run("deduplicate "+strconv.FormatBool(dedup), func(t *testing.T) {
			factory, table, endpoint := sseTable(t)
			kv := []string{"AWESOME_AUTH_TOOLS_SSE_DEDUPLICATE", strconv.FormatBool(dedup)}
			authApp := newSseApp(t, sseEnv(table, endpoint, kv...), factory)
			streamApp := newSseApp(t, sseEnv(table, endpoint, append(kv, EntrypointEnv, entrypointStream)...), factory)
			email := "sse-dedup-" + randomSuffix(t) + "@example.test"
			token := registerAndToken(t, authApp, email).accessToken
			uid := subjectOf(t, token)

			q := url.Values{"token": {token}, "topics": {"user:" + uid + ",global"}}
			_, frames, stop := openStream(t, streamApp, q.Encode(), nil)
			defer stop()
			nextFrame(t, frames, "the connected frame")
			nextFrame(t, frames, "the cursor frame")

			login := invoke(t, authApp, http.MethodPost, "/auth/login",
				jsonHeaders(auth.AuthStrategyHeader, auth.AuthStrategyBearer), nil, registerBody(email))
			if login.StatusCode != http.StatusOK {
				t.Fatalf("login = %d (%s)", login.StatusCode, login.Body)
			}
			notify(t, authApp, token, "user:"+uid, "sentinel", map[string]any{})

			// Every frame up to the sentinel, by id: the login's events.
			byID := map[string][]string{}
			var order []string
			for {
				f := nextEvent(t, frames, "the login's frames and the sentinel")
				if f.event == "sentinel" {
					break
				}
				var frame struct {
					Topic string `json:"topic"`
				}
				if err := json.Unmarshal([]byte(f.data), &frame); err != nil {
					t.Fatalf("event data %q: %v", f.data, err)
				}
				if _, ok := byID[f.id]; !ok {
					order = append(order, f.id)
				}
				byID[f.id] = append(byID[f.id], frame.Topic)
			}
			if len(order) == 0 {
				t.Fatal("the login raised no event on the stream")
			}
			want := "global"
			if !dedup {
				want = "global,user:" + uid
			}
			for _, id := range order {
				if got := strings.Join(byID[id], ","); got != want {
					t.Errorf("event %s was framed under %s, want %s", id, got, want)
				}
			}
		})
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
	// The replay limit's cut: written after the last replayed frame still
	// draining from the queue, and before the first thing newer — a heartbeat
	// or a frame whose id sorts after it.
	const l1, l2, l3 = "01J8Z6R4Q1000000000000000A", "01J8Z6R4Q2000000000000000A", "01J8Z6R4Q3000000000000000A"
	frame := func(id string) string { return "id: " + id + "\nevent: e\ndata: {}\n\n" }
	cutBytes := string(sseReplayCutFrames(100, floor))
	for _, next := range []string{": heartbeat\n\n", frame(l3)} {
		rec := httptest.NewRecorder()
		w := &resumeWriter{ResponseWriter: rec, prelude: resumePrelude(cases[0].resume)}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("id: x\nevent: connected\ndata: {}\n\n"))
		w.cut(l2, sseReplayCutFrames(100, floor))
		for _, p := range []string{frame(l1), frame(l2), next} {
			_, _ = w.Write([]byte(p))
		}
		want := "id: x\nevent: connected\ndata: {}\n\n" + cases[0].want + frame(l1) + frame(l2) + cutBytes + next
		if got := rec.Body.String(); got != want {
			t.Errorf("stream with a cut = %q, want %q", got, want)
		}
	}
	if !strings.HasPrefix(cutBytes, ": replay truncated: the replay reached 100 events") || !strings.HasSuffix(cutBytes, "id: "+floor+"\n\n") {
		t.Errorf("the cut's frames = %q", cutBytes)
	}

	rec := httptest.NewRecorder()
	w := &resumeWriter{ResponseWriter: rec, prelude: resumePrelude(cases[0].resume)}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"error":"SSE not enabled"}`))
	if strings.Contains(rec.Body.String(), "id:") {
		t.Errorf("the prelude was appended to a response that is not a stream: %q", rec.Body.String())
	}
}

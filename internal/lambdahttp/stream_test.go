package lambdahttp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// The streaming adapter, driven the way the Go runtime drives it: call the
// handler, take the response, read its Body as the runtime would. Every wait is
// on a channel with a bound, never a sleep standing in for a flush.

func streamEvent(method, path, query string, headers map[string]string, cookies []string) *events.LambdaFunctionURLRequest {
	evt := &events.LambdaFunctionURLRequest{
		RawPath:        path,
		RawQueryString: query,
		Headers:        headers,
		Cookies:        cookies,
	}
	evt.RequestContext.HTTP.Method = method
	evt.RequestContext.HTTP.Path = path
	evt.RequestContext.HTTP.SourceIP = "198.51.100.7"
	evt.RequestContext.DomainName = "abc.lambda-url.eu-west-1.on.aws"
	return evt
}

func within(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

// TestStreamingHandlerDeliversBytesBeforeTheHandlerReturns is the property the
// whole file exists for: the first frame reaches the reader while the handler
// is still running, and it does so through http.ResponseController — the
// probe the core's SseManager.Serve makes — not through a type assertion.
func TestStreamingHandlerDeliversBytesBeforeTheHandlerReturns(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	finished := make(chan struct{})
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(finished)
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/")
		rc := http.NewResponseController(w)
		if err := rc.Flush(); err != nil {
			t.Errorf("Flush through the ResponseController: %v", err)
			return
		}
		if err := rc.SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Errorf("SetWriteDeadline through the ResponseController: %v", err)
		}
		_, _ = w.Write([]byte("id: 1\nevent: first\ndata: {}\n\n"))
		<-release
		w.Header().Set("X-Too-Late", "yes")
		_, _ = w.Write([]byte("id: 2\nevent: second\ndata: {}\n\n"))
	})
	resp, err := NewStreamingHandler(h, Options{}, 0)(context.Background(), streamEvent(http.MethodGet, "/tools/stream", "", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Headers["Content-Type"] != "text/event-stream" {
		t.Fatalf("prelude = %d %v", resp.StatusCode, resp.Headers)
	}
	if strings.Join(resp.Cookies, "|") != "a=1; Path=/|b=2; Path=/" {
		t.Errorf("cookies = %q: every Set-Cookie must reach the cookies array, none comma-joined", resp.Cookies)
	}

	body := bufio.NewReader(resp.Body)
	firstFrame := make(chan string, 1)
	go func() {
		var b strings.Builder
		for {
			line, err := body.ReadString('\n')
			b.WriteString(line)
			if err != nil || line == "\n" {
				firstFrame <- b.String()
				return
			}
		}
	}()
	select {
	case got := <-firstFrame:
		if !strings.Contains(got, "event: first") {
			t.Fatalf("first frame = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first frame did not arrive while the handler was still running: the response is buffered, not streamed")
	}
	close(release)
	rest, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read the rest: %v", err)
	}
	if !strings.Contains(string(rest), "event: second") {
		t.Errorf("rest = %q", rest)
	}
	within(t, finished, "the handler to return")
	if _, ok := resp.Headers["X-Too-Late"]; ok {
		t.Error("a header set after the prelude went reached the response")
	}
}

// TestStreamingHandlerNormalisesTheRequestLikeTheBufferedPath: the Cookies
// array becomes a Cookie header — the reason lambdaurl.Wrap is not used — and
// the query string, the method and the source address arrive.
func TestStreamingHandlerNormalisesTheRequestLikeTheBufferedPath(t *testing.T) {
	t.Parallel()
	seen := make(chan *http.Request, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r
		w.WriteHeader(http.StatusNoContent)
	})
	evt := streamEvent(http.MethodGet, "/auth/tools/stream", "token=abc&topics=global",
		map[string]string{"last-event-id": "01J00000000000000000000000"},
		[]string{"__Host-accessToken=tok", "other=1"})
	resp, err := NewStreamingHandler(h, Options{}, 0)(context.Background(), evt)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	r := <-seen
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status = %d", resp.StatusCode)
	}
	if c, err := r.Cookie("__Host-accessToken"); err != nil || c.Value != "tok" {
		t.Errorf("the access-token cookie did not arrive: %v %v", c, err)
	}
	if got := r.URL.Query().Get("token"); got != "abc" {
		t.Errorf("token = %q", got)
	}
	if got := r.Header.Get("Last-Event-ID"); got != "01J00000000000000000000000" {
		t.Errorf("Last-Event-ID = %q", got)
	}
	if r.URL.Path != "/auth/tools/stream" || r.Method != http.MethodGet {
		t.Errorf("request = %s %s", r.Method, r.URL.Path)
	}
}

// TestStreamingHandlerEndsBeforeTheInvocationDeadline: the request context ends
// the margin before the invocation's own, so a stream returns and flushes
// rather than being killed mid-write.
func TestStreamingHandlerEndsBeforeTheInvocationDeadline(t *testing.T) {
	t.Parallel()
	got := make(chan time.Time, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d, _ := r.Context().Deadline()
		got <- d
	})
	invocation := time.Now().Add(time.Hour)
	ctx, cancel := context.WithDeadline(context.Background(), invocation)
	defer cancel()
	resp, err := NewStreamingHandler(h, Options{}, 7*time.Second)(ctx, streamEvent(http.MethodGet, "/", "", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.ReadAll(resp.Body)
	if d := <-got; !d.Equal(invocation.Add(-7 * time.Second)) {
		t.Errorf("request deadline = %v, want the invocation's less 7s (%v)", d, invocation.Add(-7*time.Second))
	}
}

// TestStreamingHandlerPanics: before the prelude a panic is a clean 500, as on
// the buffered path; after it the body ends with an error, because the client
// was already told 200.
func TestStreamingHandlerPanics(t *testing.T) {
	t.Parallel()
	var (
		mu       sync.Mutex
		reported []error
	)
	opts := Options{OnError: func(_ context.Context, err error) { mu.Lock(); reported = append(reported, err); mu.Unlock() }}

	before := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "leak=1")
		panic("boom")
	})
	resp, err := NewStreamingHandler(before, opts, 0)(context.Background(), streamEvent(http.MethodGet, "/", "", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusInternalServerError || len(body) != 0 || err != nil || len(resp.Cookies) != 0 {
		t.Errorf("panic before the prelude = %d %q %v cookies %v, want a bare 500", resp.StatusCode, body, err, resp.Cookies)
	}

	after := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("partial"))
		panic("boom")
	})
	resp, err = NewStreamingHandler(after, opts, 0)(context.Background(), streamEvent(http.MethodGet, "/", "", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "partial" || err == nil {
		t.Errorf("panic mid-stream = %d %q %v, want the 200 already sent, the bytes so far and a read error", resp.StatusCode, body, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(reported) != 2 {
		t.Errorf("%d panics reported, want 2", len(reported))
	}
}

// TestStreamingHandlerHonoursTheWriteDeadline: a write the runtime does not take
// in time fails, which is how the core's bound on a stuck write reaches this
// transport.
func TestStreamingHandlerHonoursTheWriteDeadline(t *testing.T) {
	t.Parallel()
	result := make(chan error, 1)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc := http.NewResponseController(w)
		_ = rc.Flush()
		_ = rc.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		_, err := w.Write([]byte("nobody reads this"))
		result <- err
	})
	resp, err := NewStreamingHandler(h, Options{}, 0)(context.Background(), streamEvent(http.MethodGet, "/", "", nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	// The body is deliberately not read: the runtime has stopped taking bytes.
	select {
	case err := <-result:
		if !errors.Is(err, ErrStreamWriteTimeout) {
			t.Errorf("stuck write = %v, want ErrStreamWriteTimeout", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a write nobody read never returned")
	}
	_ = resp
}

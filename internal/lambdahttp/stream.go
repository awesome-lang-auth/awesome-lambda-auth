package lambdahttp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
)

// Function URL response streaming (D9c).
//
// A Function URL whose InvokeMode is RESPONSE_STREAM does not take the
// JSON-in/JSON-out contract the rest of this package renders: the handler
// returns an *events.LambdaFunctionURLStreamingResponse whose Body is an
// io.Reader, and the Go runtime copies that reader to the client as it
// produces bytes (aws-lambda-go v1.54.0, lambda/handler.go: a response value
// that is an io.Reader is streamed as-is; events/lambda_function_urls.go writes
// the status/headers/cookies prelude ahead of it). That is the one runtime
// shape in which a Server-Sent Events stream is a stream and not a batch.
//
// # Why not lambdaurl.Wrap
//
// aws-lambda-go ships exactly this adapter, lambdaurl.Wrap, and it is not used,
// for two reasons read off its source rather than its documentation:
//
//   - Its response writer has no Flush. The core's SseManager.Serve probes the
//     writer with http.ResponseController.Flush before it writes a byte and
//     answers ErrSseStreamingUnsupported when that fails (sse.go), so behind
//     lambdaurl.Wrap every stream would be a 500 — the one outcome the probe
//     exists to produce.
//   - It copies request.Headers and nothing else. A Function URL delivers the
//     request's cookies in a separate Cookies array, not as a Cookie header
//     (the reason this package exists; see the package comment), so behind it
//     the __Host-accessToken cookie — the core's recommended alternative to a
//     token in the query string (tools_stream.go) — would never arrive.
//
// So the request is normalised by NewRequest, exactly as the buffered path
// normalises it, and the writer is this file's.
//
// # What the writer promises
//
// Status and headers are frozen at the first Write, WriteHeader or Flush, as
// net/http freezes them, because that is the moment the prelude has to be
// handed to the runtime; a header set after it is dropped, as it would be on a
// socket. Flush is real in the sense that matters — every Write goes straight
// into a synchronous pipe the runtime is reading, so nothing is held back — and
// it is what makes the core's probe succeed. SetWriteDeadline is honoured: a
// write the runtime has not taken by the deadline fails and ends the response,
// which is how the core's ten-second bound on a stuck write (sseWriteTimeout)
// reaches this transport at all.
//
// # What it cannot promise, stated
//
// A panic after the prelude has gone cannot become a clean 500 the way it does
// on the buffered path (Adapter.invoke), because the client has already been
// told 200: the body is closed with an error and the stream ends where it was.
// That is net/http's own behaviour for the same case.

// ErrStreamWriteTimeout is what a Write answers when the runtime did not take
// its bytes before the deadline the handler set.
var ErrStreamWriteTimeout = errors.New("lambdahttp: stream write missed its deadline")

// DefaultStreamDeadlineMargin is how long before the invocation's own deadline
// the request context is cancelled. A Function URL invocation that reaches its
// timeout is killed mid-write and reported as an error; cancelling first lets
// the handler return, the runtime flush the last bytes and the response end
// cleanly, which for an SSE stream is the ordinary end of a segment that the
// client reconnects from.
const DefaultStreamDeadlineMargin = 5 * time.Second

// StreamingHandler is the handler shape lambda.StartHandlerFunc takes for a
// Function URL in RESPONSE_STREAM mode. An alias rather than a defined type,
// because lambda.StartHandlerFunc constrains its argument to the exact func
// type and a defined type would not satisfy it.
type StreamingHandler = func(context.Context, *events.LambdaFunctionURLRequest) (*events.LambdaFunctionURLStreamingResponse, error)

// NewStreamingHandler serves Function URL requests with h, streaming whatever
// it writes. margin is how long before the invocation deadline the request
// context ends; zero selects DefaultStreamDeadlineMargin and a negative value
// disables it.
func NewStreamingHandler(h http.Handler, opts Options, margin time.Duration) StreamingHandler {
	if margin == 0 {
		margin = DefaultStreamDeadlineMargin
	}
	report := func(ctx context.Context, err error) {
		if opts.OnError != nil && err != nil {
			opts.OnError(ctx, err)
		}
	}
	return func(ctx context.Context, evt *events.LambdaFunctionURLRequest) (*events.LambdaFunctionURLStreamingResponse, error) {
		if evt == nil {
			evt = &events.LambdaFunctionURLRequest{}
		}
		cancel := context.CancelFunc(func() {})
		if deadline, ok := ctx.Deadline(); ok && margin > 0 {
			ctx, cancel = context.WithDeadline(ctx, deadline.Add(-margin))
		}
		req, err := NewRequest(ctx, evt, opts)
		if err != nil {
			cancel()
			report(ctx, err)
			return &events.LambdaFunctionURLStreamingResponse{StatusCode: http.StatusBadRequest, Body: http.NoBody}, nil
		}

		pr, pw := io.Pipe()
		w := &streamWriter{header: make(http.Header), pipe: pw, ready: make(chan struct{})}
		go func() {
			defer cancel()
			defer func() {
				p := recover()
				if p == nil {
					w.commit(http.StatusOK)
					_ = pw.Close()
					return
				}
				if p == http.ErrAbortHandler {
					report(req.Context(), errors.New("lambdahttp: handler aborted the streamed response"))
				} else {
					report(req.Context(), fmt.Errorf("lambdahttp: handler panic: %v\n%s", p, debug.Stack()))
				}
				if w.commitClean(http.StatusInternalServerError) {
					// Nothing had reached the client: the panic is an ordinary
					// 500 with an empty body, as on the buffered path.
					_ = pw.Close()
					return
				}
				_ = pw.CloseWithError(fmt.Errorf("lambdahttp: handler panicked mid-stream: %v", p))
			}()
			h.ServeHTTP(w, req)
		}()

		<-w.ready
		cookies, rest := splitSetCookie(w.frozen)
		return &events.LambdaFunctionURLStreamingResponse{
			StatusCode: w.status,
			Headers:    joinedHeaders(rest),
			Cookies:    cookies,
			Body:       pr,
		}, nil
	}
}

// streamWriter is the http.ResponseWriter a streamed handler writes to. See the
// file header for what it promises.
type streamWriter struct {
	header http.Header
	pipe   *io.PipeWriter

	once   sync.Once
	ready  chan struct{}
	frozen http.Header
	status int

	mu       sync.Mutex
	deadline time.Time
}

func (w *streamWriter) Header() http.Header { return w.header }

// commit freezes the status and headers the first time anything is sent.
func (w *streamWriter) commit(code int) {
	w.once.Do(func() {
		w.status = code
		w.frozen = w.header.Clone()
		close(w.ready)
	})
}

// commitClean commits code with no headers, reporting whether this call was
// the one that committed — false when the prelude had already gone.
func (w *streamWriter) commitClean(code int) bool {
	committed := false
	w.once.Do(func() {
		committed = true
		w.status = code
		w.frozen = http.Header{}
		close(w.ready)
	})
	return committed
}

func (w *streamWriter) WriteHeader(code int) {
	// Informational statuses are not a final answer, and a Function URL has no
	// way to send one ahead of it; net/http sends them and keeps going, here
	// they are dropped.
	if code < 200 {
		return
	}
	w.commit(code)
}

func (w *streamWriter) Write(p []byte) (int, error) {
	w.commit(http.StatusOK)
	w.mu.Lock()
	deadline := w.deadline
	w.mu.Unlock()
	if deadline.IsZero() {
		return w.pipe.Write(p)
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		_ = w.pipe.CloseWithError(ErrStreamWriteTimeout)
		return 0, ErrStreamWriteTimeout
	}
	// io.Pipe has no deadline of its own; closing it with an error is what
	// unblocks a Write the reader is not taking.
	timer := time.AfterFunc(wait, func() { _ = w.pipe.CloseWithError(ErrStreamWriteTimeout) })
	n, err := w.pipe.Write(p)
	if !timer.Stop() {
		// The deadline fired: whatever the pipe answered — a short write, or
		// the closed-pipe error the writer side sees after CloseWithError —
		// the reason is the deadline.
		return n, ErrStreamWriteTimeout
	}
	return n, err
}

// Flush commits the prelude. Every Write already goes straight to the runtime,
// so there is nothing buffered to push.
func (w *streamWriter) Flush() { w.commit(http.StatusOK) }

// FlushError is what http.ResponseController.Flush calls, and it is the probe
// the core's SseManager.Serve makes before it writes a byte.
func (w *streamWriter) FlushError() error {
	w.Flush()
	return nil
}

// SetWriteDeadline bounds the Writes that follow it; the zero time removes the
// bound. It is found by http.ResponseController.SetWriteDeadline.
func (w *streamWriter) SetWriteDeadline(t time.Time) error {
	w.mu.Lock()
	w.deadline = t
	w.mu.Unlock()
	return nil
}

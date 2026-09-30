package contract

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// GET <tools>/stream, black-box (D9c): the reference's frame shape, and this
// product's resume guarantee.
//
// The stream is read over plain net/http, never through the suite's Client,
// which buffers whole bodies: a request with a bounded context, a line reader,
// and only the first frames asserted — the connection is closed as soon as the
// case has what it needs, so nothing here holds a stream open past its
// assertion and nothing sleeps for a heartbeat.
//
// Two targets. The stream on the deployment's own origin — <base><tools>/stream,
// which on this product is the CloudFront behaviour in front of the SSE
// function, and on the reference is the tools router itself — and, when
// AWESOME_AUTH_CONTRACT_SSE_URL names it, the SSE function's Function URL
// directly. Running both is how a CloudFront change that starts buffering the
// stream is told apart from a protocol break: the same case passes on the URL
// and fails on the distribution. Events are always triggered through the base
// URL, because that is where POST <tools>/notify lives.

// SSEURLEnv is the origin — scheme and host, no path — of the SSE function's
// Function URL: the stack's SseFunctionUrl output with its trailing slash
// dropped. Unset means the stream is tried on the base URL alone.
const SSEURLEnv = "AWESOME_AUTH_CONTRACT_SSE_URL"

// CapSSE is the stream answering at least one target with text/event-stream
// and a connected frame. CapSSEResume is the product's added guarantee, read
// off the same connection: the id-only cursor frame this product writes after
// the connected frame (docs/sse.md). The reference writes none — it has no
// resume (sse-manager.ts reads Last-Event-ID nowhere) — so against it the
// resume case skips, as a declared absence and not a failure.
const (
	CapSSE       Capability = "sse"
	CapSSEResume Capability = "sse-resume"
)

// sseTargets is what the probe found answering, in the order the cases run
// them. It is package state because a probe records capabilities and nothing
// else, and the cases need to know which of the two origins to open.
var sseTargets []string

func init() {
	registerCapability(capabilityDecl{
		Name:    CapSSE,
		Settles: []Capability{CapSSEResume},
		Stage:   stageProbed,
		Probe: func(t *testing.T, p *probeRun) {
			// A bearer login of the provisioned account, because ?token= is
			// the credential an EventSource can carry to either origin and a
			// cookie reaches only the base one.
			login := p.Env.NewClient().POST(t, "/login", body{"email": p.account.Email, "password": p.account.Password}, BearerStrategy())
			if login.Status != 200 {
				p.Set(CapSSE, capability{state: capBroken, why: fmt.Sprintf("cannot log in with a bearer strategy to probe the stream: %d", login.Status)})
				p.Set(CapSSEResume, capability{state: capBroken, why: "the stream was not probed"})
				return
			}
			token := login.str(t, "accessToken")

			origins := []string{p.Env.BaseURL}
			if u := strings.TrimSuffix(strings.TrimSpace(os.Getenv(SSEURLEnv)), "/"); u != "" {
				origins = append(origins, u)
			}
			var why []string
			resume := false
			broken := ""
			for _, origin := range origins {
				s, err := openSSE(p.Env, origin, url.Values{"token": {token}}, nil, 10*time.Second)
				if err != nil {
					broken = err.Error()
					continue
				}
				switch {
				case s.status == 404:
					why = append(why, fmt.Sprintf("%s answered 404", s.target))
				case s.status == 401 || s.status == 403:
					// A stream mounted behind a guard this suite's bearer
					// cannot pass: under tools.auth apiKey — the SAM
					// template's default — ?token= becomes Authorization:
					// Bearer, which the API-key guard does not read, and the
					// admin posture wants the console's token. Not a fault;
					// the capability is absent for this credential, as
					// classifyTools says of the tools router itself.
					why = append(why, fmt.Sprintf("%s answered %d: mounted behind a guard this suite's session cannot pass (tools.auth is apiKey or admin)", s.target, s.status))
				case s.status != 200 || !strings.HasPrefix(s.contentType, "text/event-stream"):
					broken = fmt.Sprintf("%s answered %d %q, which is neither a stream nor a declared absence", s.target, s.status, s.contentType)
				default:
					first, err := s.next()
					if err != nil || first.event != "connected" {
						broken = fmt.Sprintf("%s streamed, but its first frame was %+v (%v), not connected", s.target, first, err)
						break
					}
					sseTargets = append(sseTargets, origin)
					why = append(why, fmt.Sprintf("%s streamed a connected frame", s.target))
					if cursor, err := s.next(); err == nil && cursor.hasID && cursor.event == "" && cursor.data == "" {
						resume = true
					}
				}
				s.close()
			}
			switch {
			case broken != "":
				p.Set(CapSSE, capability{state: capBroken, why: broken})
			case len(sseTargets) == 0:
				p.Set(CapSSE, capability{state: capAbsent, why: strings.Join(why, "; ") + " — no transport serves the stream here"})
			default:
				p.Set(CapSSE, capability{state: capOn, why: strings.Join(why, "; ")})
			}
			if resume {
				p.Set(CapSSEResume, capability{state: capOn, why: "an id-only cursor frame follows the connected frame"})
			} else {
				p.Set(CapSSEResume, capability{state: capAbsent, why: "no cursor frame follows the connected frame, so the stream offers no resume (the reference's behaviour)"})
			}
		},
	})
}

// sseStream is one open stream: the response and a frame reader over it.
type sseStream struct {
	target      string
	status      int
	contentType string
	lines       *bufio.Reader
	close       func()
}

// sseFrameRead is one frame, parsed.
type sseFrameRead struct {
	id, event, data string
	hasID           bool
	comments        []string
}

// openSSE opens GET <origin><tools>/stream with a bounded lifetime. The
// deadline bounds the whole connection, so a stream that stops sending cannot
// hang a case.
func openSSE(e *Env, origin string, query url.Values, header http.Header, deadline time.Duration) (*sseStream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), deadline)
	target := origin + e.ToolsPath + "/stream"
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("Accept", "text/event-stream")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("GET %s: %w", redactToken(target), err)
	}
	return &sseStream{
		target:      "GET " + redactToken(target),
		status:      resp.StatusCode,
		contentType: resp.Header.Get("Content-Type"),
		lines:       bufio.NewReader(resp.Body),
		close:       func() { cancel(); _ = resp.Body.Close() },
	}, nil
}

// redactToken keeps the access token out of failure messages.
func redactToken(target string) string {
	if i := strings.Index(target, "token="); i >= 0 {
		j := strings.IndexByte(target[i:], '&')
		if j < 0 {
			return target[:i] + "token=[REDACTED]"
		}
		return target[:i] + "token=[REDACTED]" + target[i+j:]
	}
	return target
}

// next reads one frame.
func (s *sseStream) next() (sseFrameRead, error) {
	var f sseFrameRead
	for {
		line, err := s.lines.ReadString('\n')
		if err != nil {
			return f, err
		}
		line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
		switch {
		case line == "":
			return f, nil
		case strings.HasPrefix(line, ":"):
			f.comments = append(f.comments, line)
		case strings.HasPrefix(line, "id:"):
			f.id, f.hasID = strings.TrimPrefix(strings.TrimPrefix(line, "id:"), " "), true
		case strings.HasPrefix(line, "event:"):
			f.event = strings.TrimPrefix(strings.TrimPrefix(line, "event:"), " ")
		case strings.HasPrefix(line, "data:"):
			f.data = strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " ")
		}
	}
}

// nextEvent reads frames until one carries an event line whose type starts
// with prefix, skipping heartbeats, the cursor frame and every other event.
// Other events are expected: every connection holds the global topic, which
// carries every login on the deployment — the suite's own included — and on
// this product a resume re-delivers what the look-back below the cursor holds.
func (s *sseStream) nextEvent(t *testing.T, prefix, what string) sseFrameRead {
	t.Helper()
	for {
		f, err := s.next()
		if err != nil {
			t.Fatalf("%s: the stream ended before %s: %v", s.target, what, err)
		}
		if f.event != "" && strings.HasPrefix(f.event, prefix) {
			return f
		}
	}
}

// openConnected opens the stream and consumes the connected frame and, on
// this product, the cursor frame after it.
func openConnected(t *testing.T, e *Env, origin, token string, header http.Header) *sseStream {
	t.Helper()
	s, err := openSSE(e, origin, url.Values{"token": {token}}, header, 30*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.close)
	if s.status != 200 || !strings.HasPrefix(s.contentType, "text/event-stream") {
		t.Fatalf("%s answered %d %q, want 200 text/event-stream", s.target, s.status, s.contentType)
	}
	if f, err := s.next(); err != nil || f.event != "connected" {
		t.Fatalf("%s: first frame %+v (%v), want connected", s.target, f, err)
	}
	return s
}

// notifyUser triggers one event on the user's own topic through the base URL.
func notifyUser(t *testing.T, e *Env, token, uid, eventType string, data map[string]any) {
	t.Helper()
	e.NewClient().POST(t, e.tools("/notify/user:"+uid), body{"type": eventType, "data": data}, Bearer(token)).mustStatus(t, 202)
}

func init() {
	register(
		Case{
			Name:  "sse/stream-emits-named-frames-with-rawData",
			Doc:   "reference sse-manager.ts:140-146 and :250-252, tools.router.ts:185-220 — GET <tools>/stream?token= authenticates through the query token, opens with a `connected` frame, and delivers a notified event as `id:`/`event:`/`data:` lines whose JSON carries the payload under rawData and no `data` key",
			Needs: []Capability{CapTools, CapSSE},
			Run: func(t *testing.T, e *Env) {
				for _, origin := range sseTargets {
					t.Run(origin, func(t *testing.T) {
						c, _, token := e.LoginBearer(t)
						uid := c.GET(t, "/me", Bearer(token)).mustStatus(t, 200).str(t, "id")
						s := openConnected(t, e, origin, token, nil)

						eventType := fmt.Sprintf("contract.sse.%d", time.Now().UnixNano())
						notifyUser(t, e, token, uid, eventType, map[string]any{"n": 1, "s": "<b>&</b>"})
						f := s.nextEvent(t, eventType, "the notified event")
						if f.event != eventType || f.id == "" {
							t.Fatalf("frame = %+v, want event %q with an id", f, eventType)
						}
						var frame map[string]any
						if err := json.Unmarshal([]byte(f.data), &frame); err != nil {
							t.Fatalf("data line is not JSON: %q (%v)", f.data, err)
						}
						if _, ok := frame["data"]; ok {
							t.Errorf("the frame's JSON carries a `data` key; the reference puts the payload under rawData alone: %s", f.data)
						}
						raw, _ := frame["rawData"].(map[string]any)
						if raw["s"] != "<b>&</b>" || raw["n"] != float64(1) {
							t.Errorf("rawData = %v, want the notified payload", frame["rawData"])
						}
						if frame["type"] != eventType || frame["topic"] != "user:"+uid || frame["id"] != f.id {
							t.Errorf("frame fields = %v, want type, topic user:%s and the id line's id", frame, uid)
						}
					})
				}
			},
		},

		Case{
			Name:  "sse/resume-replays-after-last-event-id",
			Doc:   "product deviation sse-resume-replays-from-the-event-log (docs/sse.md) — a reconnect with Last-Event-ID set to an event already received is handed the event raised while it was away, and not the one it had",
			Needs: []Capability{CapTools, CapSSE, CapSSEResume},
			Run: func(t *testing.T, e *Env) {
				for _, origin := range sseTargets {
					t.Run(origin, func(t *testing.T) {
						c, _, token := e.LoginBearer(t)
						uid := c.GET(t, "/me", Bearer(token)).mustStatus(t, 200).str(t, "id")
						stamp := time.Now().UnixNano()
						earlier, later := fmt.Sprintf("contract.sse.earlier.%d", stamp), fmt.Sprintf("contract.sse.later.%d", stamp)

						s := openConnected(t, e, origin, token, nil)
						notifyUser(t, e, token, uid, earlier, map[string]any{"which": "earlier"})
						first := s.nextEvent(t, earlier, "the earlier event")
						if first.event != earlier {
							t.Fatalf("first event %q, want %q", first.event, earlier)
						}
						s.close()

						notifyUser(t, e, token, uid, later, map[string]any{"which": "later"})

						resumed := openConnected(t, e, origin, token, http.Header{"Last-Event-ID": {first.id}})
						// Only this run's two events are asserted: the look-back
						// below the cursor may re-deliver anything else the
						// window holds (at-least-once), and never the cursor's
						// own event.
						for {
							got := resumed.nextEvent(t, "contract.sse.", "the replayed event")
							if got.event == earlier {
								t.Fatalf("the reconnect replayed the event at the cursor (%s), which it had already received", earlier)
							}
							if got.event == later {
								break
							}
						}
					})
				}
			},
		},
	)
}

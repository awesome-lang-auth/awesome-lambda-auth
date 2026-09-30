package dynamodb

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"
)

// The SSE event log against DynamoDB Local (data-model.md §1.5): what Publish
// writes, that the ULIDs it keys on are ordered, and what Follow hands the
// manager — in order, once, after a cursor, and not past the retention.
//
// Nothing here sleeps for a poll interval. The logs are built with a
// millisecond-scale interval and every wait is a bounded wait for a
// delivery, so the suite stays fast under -race and parallel load.

// fastSseLog is a log over a fresh table that polls every 5 ms.
func fastSseLog(t *testing.T, mutate ...func(*Options)) (*SseLog, *Store) {
	t.Helper()
	store, _ := newStore(t, mutate...)
	return store.SseLog(SseLogOptions{PollInterval: 5 * time.Millisecond, IdleInterval: 5 * time.Millisecond}), store
}

// collector is the manager's callback, recorded.
type collector struct {
	mu     sync.Mutex
	events []auth.StreamEvent
	topics []string
	signal chan struct{}
}

func newCollector() *collector { return &collector{signal: make(chan struct{}, 1024)} }

func (c *collector) fn(topic string, ev auth.StreamEvent) {
	c.mu.Lock()
	c.events = append(c.events, ev)
	c.topics = append(c.topics, topic)
	c.mu.Unlock()
	c.signal <- struct{}{}
}

// await waits for n deliveries in total, with a bound that is a failure and
// not a timing assumption.
func (c *collector) await(t *testing.T, n int) []auth.StreamEvent {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		c.mu.Lock()
		got := len(c.events)
		c.mu.Unlock()
		if got >= n {
			c.mu.Lock()
			defer c.mu.Unlock()
			return append([]auth.StreamEvent(nil), c.events...)
		}
		select {
		case <-c.signal:
		case <-deadline:
			t.Fatalf("waited for %d deliveries, got %d", n, got)
		}
	}
}

func (c *collector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// follow starts Follow on a goroutine and returns the function that stops it
// and reports its error.
func follow(t *testing.T, l *SseLog, f SseFollow) func() error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Follow(ctx, f) }()
	var once sync.Once
	var err error
	stop := func() error {
		once.Do(func() {
			cancel()
			select {
			case err = <-done:
			case <-time.After(10 * time.Second):
				t.Errorf("Follow did not return after its context was cancelled")
			}
		})
		return err
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

func publish(t *testing.T, l *SseLog, topic string, ev auth.StreamEvent) {
	t.Helper()
	ev.Topic = topic
	if err := l.Publish(context.Background(), topic, ev); err != nil {
		t.Fatalf("publish %s to %s: %v", ev.ID, topic, err)
	}
}

// storedULID reads the one event under topic and returns its ULID.
func storedULIDs(t *testing.T, store *Store, topic string) []string {
	t.Helper()
	l := store.SseLog(SseLogOptions{})
	c := newCollector()
	if err := l.Subscribe(context.Background(), c.fn); err != nil {
		t.Fatal(err)
	}
	var out []string
	entries, _, err := l.readTopic(context.Background(), topic, ulid{}, map[ulid]struct{}{}, ulid{})
	if err != nil {
		t.Fatalf("read %s: %v", topic, err)
	}
	for _, e := range entries {
		out = append(out, e.id.String())
	}
	return out
}

func TestULIDEncodingRoundTripsAndSortsAsItsTime(t *testing.T) {
	t.Parallel()
	clock := &ulidClock{now: time.Now}
	var prev string
	for i := 0; i < 5000; i++ {
		u, err := clock.next()
		if err != nil {
			t.Fatal(err)
		}
		s := u.String()
		if len(s) != ulidLen {
			t.Fatalf("encoded %q is %d characters", s, len(s))
		}
		back, err := parseULID(s)
		if err != nil || back != u {
			t.Fatalf("round trip of %q: %v, %x != %x", s, err, back, u)
		}
		if prev != "" && s <= prev {
			t.Fatalf("ULID %d = %s does not sort after %s: monotonicity is what per-publisher order rests on", i, s, prev)
		}
		prev = s
	}

	at := time.Date(2026, 9, 30, 12, 0, 0, 123_000_000, time.UTC)
	if got := ulidAt(at).time(); !got.Equal(at) {
		t.Errorf("ulidAt(%v).time() = %v", at, got)
	}
	if a, b := ulidAt(at).String(), ulidAt(at.Add(time.Millisecond)).String(); a >= b {
		t.Errorf("a later millisecond sorts before an earlier one: %s >= %s", b, a)
	}
	for _, bad := range []string{"", "8ZZZZZZZZZZZZZZZZZZZZZZZZZ", "01ARZ3NDEKTSV4RRFFQ69G5FAI", strings.Repeat("0", 25), "00000000-0000-4000-8000-000000000000"} {
		if _, err := parseULID(bad); err == nil {
			t.Errorf("parseULID(%q) accepted a value this log never mints", bad)
		}
	}
}

// TestULIDClockDoesNotStepBackwards: a clock that moves backwards keeps minting
// above what it already handed out, because an id below one already delivered
// would be invisible to every cursor past it.
func TestULIDClockDoesNotStepBackwards(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	clock := &ulidClock{now: func() time.Time { return now }}
	first, _ := clock.next()
	now = now.Add(-time.Second)
	second, err := clock.next()
	if err != nil {
		t.Fatal(err)
	}
	if second.String() <= first.String() {
		t.Fatalf("after the clock stepped back, %s does not sort after %s", second, first)
	}
}

// TestStreamTopicsAuthoriseOnlyTheLoggedShapes pins the premise of skipping a
// topic on Publish: every topic StreamTopics can authorise is streamable, and
// the session copy EventTopics fans to is not something any stream can hold.
// It fails the day the core authorises a fourth shape.
func TestStreamTopicsAuthoriseOnlyTheLoggedShapes(t *testing.T) {
	t.Parallel()
	for _, topic := range auth.StreamTopics("u1", "t1", nil) {
		if !streamableTopic(topic) {
			t.Errorf("StreamTopics authorises %q, which Publish would not log", topic)
		}
	}
	requested := []string{"session:s1", "custom:x", "global", "user:u1"}
	for _, topic := range auth.StreamTopics("u1", "t1", requested) {
		if !streamableTopic(topic) {
			t.Errorf("StreamTopics authorises %q from a request, which Publish would not log", topic)
		}
	}
	if streamableTopic(auth.SseTopicSessionPrefix + "s1") {
		t.Error("a session topic is streamable, but no stream can hold one")
	}
}

// TestSsePublishWritesOneItemPerSubscribableTopic: one event, published the way
// Track publishes it — the same StreamEvent to four topics — is one ULID under
// every topic a stream can hold, and nothing under the one it cannot.
func TestSsePublishWritesOneItemPerSubscribableTopic(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)
	store, client := newStore(t, func(o *Options) { o.Now = func() time.Time { return now } })
	l := store.SseLog(SseLogOptions{Retention: 2 * time.Hour})

	ev := auth.StreamEvent{
		ID: "core-uuid-1", Type: "identity.auth.login.success", Timestamp: "2026-09-30T12:00:00.000Z",
		Data: map[string]any{"email": "a@example.test"}, UserID: "u1", TenantID: "t1",
	}
	for _, topic := range []string{"global", "tenant:t1", "user:u1", "session:s1", "custom:x"} {
		publish(t, l, topic, ev)
	}

	var ids []string
	for _, topic := range []string{"global", "tenant:t1", "user:u1"} {
		got := storedULIDs(t, store, topic)
		if len(got) != 1 {
			t.Fatalf("%s holds %d events, want 1", topic, len(got))
		}
		ids = append(ids, got[0])
	}
	if ids[0] != ids[1] || ids[1] != ids[2] {
		t.Errorf("one event carries three ULIDs %v: the core's deduplication and the cross-topic order both need one", ids)
	}
	for _, topic := range []string{"session:s1", "custom:x"} {
		if got := storedULIDs(t, store, topic); len(got) != 0 {
			t.Errorf("%s holds %d events; no stream can hold that topic, so nothing should be written", topic, len(got))
		}
	}

	raw := rawItem(t, client, store.table, ssePK("global"), skSsePrefix+ids[0])
	if got := getS(raw, attrType); got != typeSseEvent {
		t.Errorf("_t = %q", got)
	}
	if got := getS(raw, attrSseCoreID); got != "core-uuid-1" {
		t.Errorf("coreId = %q, want the id Broadcast minted", got)
	}
	if got, want := getN(raw, attrTTL), now.Add(2*time.Hour).Unix(); got != want {
		t.Errorf("ttl = %d, want %d (epoch seconds, retention past the write)", got, want)
	}
	if _, ok := raw[attrSseMetadata]; ok {
		t.Error("metadata was written for an event that carried none")
	}
}

// TestSseFollowReplaysInOrderAfterTheCursor is the resume guarantee: events
// after the cursor, oldest first, across topics, each once; nothing at or
// before it.
func TestSseFollowReplaysInOrderAfterTheCursor(t *testing.T) {
	t.Parallel()
	l, store := fastSseLog(t)
	c := newCollector()
	if err := l.Subscribe(context.Background(), c.fn); err != nil {
		t.Fatal(err)
	}

	publish(t, l, "global", auth.StreamEvent{ID: "e1", Type: "one", Data: 1})
	publish(t, l, "user:u1", auth.StreamEvent{ID: "e2", Type: "two", Data: 2})
	// e3 goes to both topics, as Track sends one event to several.
	publish(t, l, "global", auth.StreamEvent{ID: "e3", Type: "three", Data: 3})
	publish(t, l, "user:u1", auth.StreamEvent{ID: "e3", Type: "three", Data: 3})
	publish(t, l, "global", auth.StreamEvent{ID: "e4", Type: "four", Data: 4})

	first := storedULIDs(t, store, "global")[0]
	resume := l.Resume(first)
	if !resume.Replay || resume.Truncated || resume.Unrecognised || resume.Floor != first {
		t.Fatalf("Resume(%s) = %+v, want a replay from it", first, resume)
	}
	stop := follow(t, l, SseFollow{Topics: []string{"global", "user:u1"}, Floor: resume.Floor})

	got := c.await(t, 3)
	var types []string
	for _, ev := range got {
		types = append(types, ev.Type)
	}
	if strings.Join(types, ",") != "two,three,four" {
		t.Fatalf("replayed %v, want two,three,four: after the cursor, oldest first, the two-topic event once", types)
	}
	for i := 1; i < len(got); i++ {
		if got[i].ID <= got[i-1].ID {
			t.Errorf("delivery %d id %s does not sort after %s", i, got[i].ID, got[i-1].ID)
		}
	}
	// Let a few more polls run over the same events: the look-back re-reads
	// them, and the delivered set must keep them from arriving twice.
	time.Sleep(50 * time.Millisecond)
	if n := c.count(); n != 3 {
		t.Errorf("%d deliveries after further polls, want 3: the look-back re-delivered", n)
	}
	if err := stop(); err != nil {
		t.Errorf("Follow returned %v on an ordinary end", err)
	}
}

// TestSseFollowDeliversLiveEvents: a connection with no cursor starts from now
// and hears what is published after it, in order.
func TestSseFollowDeliversLiveEvents(t *testing.T) {
	t.Parallel()
	l, _ := fastSseLog(t)
	c := newCollector()
	if err := l.Subscribe(context.Background(), c.fn); err != nil {
		t.Fatal(err)
	}
	publish(t, l, "global", auth.StreamEvent{ID: "before", Type: "before"})
	// A millisecond boundary between the event above and the floor below, so
	// "from now" is unambiguous about which side of it the event is on.
	time.Sleep(2 * time.Millisecond)
	resume := l.Resume("")
	if resume.Replay || resume.Truncated || resume.Unrecognised {
		t.Fatalf("Resume(\"\") = %+v, want a plain start from now", resume)
	}

	ready := make(chan struct{})
	stop := follow(t, l, SseFollow{
		Topics: []string{"global"},
		Floor:  resume.Floor,
		Ready: func() bool {
			select {
			case <-ready:
				return true
			default:
				return false
			}
		},
	})
	for i := 0; i < 40; i++ {
		publish(t, l, "global", auth.StreamEvent{ID: "live-" + strconv.Itoa(i), Type: "live-" + strconv.Itoa(i)})
	}
	// Nothing is delivered before the connection says it is registered.
	time.Sleep(30 * time.Millisecond)
	if n := c.count(); n != 0 {
		t.Fatalf("%d events delivered before the connection was ready", n)
	}
	close(ready)

	got := c.await(t, 40)
	for i, ev := range got {
		if want := "live-" + strconv.Itoa(i); ev.Type != want {
			t.Fatalf("delivery %d is %q, want %q: live events arrive in publication order, and the one before the floor not at all", i, ev.Type, want)
		}
	}
	_ = stop()
}

// TestSseEventBytesSurviveTheLog: what the subscriber's frame writer is handed
// renders the payload exactly as the publisher's would have — key order, the
// three characters encoding/json escapes by default, and numbers.
func TestSseEventBytesSurviveTheLog(t *testing.T) {
	t.Parallel()
	l, _ := fastSseLog(t)
	c := newCollector()
	if err := l.Subscribe(context.Background(), c.fn); err != nil {
		t.Fatal(err)
	}
	type payload struct {
		Zeta  string  `json:"zeta"`
		Alpha float64 `json:"alpha"`
		HTML  string  `json:"html"`
	}
	data := payload{Zeta: "z", Alpha: 1.5e-7, HTML: "<a href=\"x?y=1&z=2\">"}
	meta := map[string]any{"n": 12345678901234, "b": []any{"x"}}
	resume := l.Resume("")
	stop := follow(t, l, SseFollow{Topics: []string{"user:u1"}, Floor: resume.Floor})
	publish(t, l, "user:u1", auth.StreamEvent{ID: "p", Type: "t", Timestamp: "2026-09-30T12:00:00.000Z", Data: data, Metadata: meta, UserID: "u1"})
	got := c.await(t, 1)[0]
	_ = stop()

	want, _ := sseJSON(data)
	raw, ok := got.Data.(json.RawMessage)
	if !ok || string(raw) != string(want) {
		t.Errorf("payload = %#v, want the bytes %s", got.Data, want)
	}
	wantMeta, _ := sseJSON(meta)
	gotMeta, _ := sseJSON(got.Metadata)
	if string(gotMeta) != string(wantMeta) {
		t.Errorf("metadata renders %s, want %s", gotMeta, wantMeta)
	}
	if got.Timestamp != "2026-09-30T12:00:00.000Z" || got.UserID != "u1" || got.Topic != "user:u1" || got.Type != "t" {
		t.Errorf("fields did not survive: %+v", got)
	}
	if _, err := parseULID(got.ID); err != nil {
		t.Errorf("the delivered id %q is not the ULID: %v", got.ID, err)
	}
}

// TestSseRetentionBoundsTheReplay: a cursor older than the retention is
// truncated to the horizon, and an event older than the retention is not
// replayed even while TTL has not yet deleted it.
func TestSseRetentionBoundsTheReplay(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	now := time.Now().UTC()
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	store, _ := newStore(t, func(o *Options) { o.Now = clock })
	l := store.SseLog(SseLogOptions{Retention: time.Hour, PollInterval: 5 * time.Millisecond, IdleInterval: 5 * time.Millisecond})
	c := newCollector()
	if err := l.Subscribe(context.Background(), c.fn); err != nil {
		t.Fatal(err)
	}

	// Two hours ago: past the retention.
	mu.Lock()
	now = now.Add(-2 * time.Hour)
	mu.Unlock()
	publish(t, l, "global", auth.StreamEvent{ID: "old", Type: "old"})
	oldCursor := storedULIDs(t, store, "global")[0]
	mu.Lock()
	now = now.Add(2 * time.Hour)
	mu.Unlock()
	publish(t, l, "global", auth.StreamEvent{ID: "recent", Type: "recent"})

	resume := l.Resume(oldCursor)
	if !resume.Truncated || !resume.Replay {
		t.Fatalf("Resume(a cursor two hours old, retention one) = %+v, want truncated", resume)
	}
	stop := follow(t, l, SseFollow{Topics: []string{"global"}, Floor: resume.Floor})
	got := c.await(t, 1)
	time.Sleep(30 * time.Millisecond)
	_ = stop()
	if len(got) != 1 || got[0].Type != "recent" || c.count() != 1 {
		t.Fatalf("replayed %d events (first %q), want only the recent one", c.count(), got[0].Type)
	}

	for _, bad := range []string{"not-a-cursor", "00000000-0000-4000-8000-000000000000", ulidAt(now.Add(time.Hour)).String()} {
		if r := l.Resume(bad); !r.Unrecognised || r.Replay {
			t.Errorf("Resume(%q) = %+v, want unrecognised and a start from now", bad, r)
		}
	}
}

// TestSseFollowPagesThroughABacklog: a replay longer than a page arrives whole
// and in order, a page at a time, which is what keeps it inside the core's
// per-connection queue.
func TestSseFollowPagesThroughABacklog(t *testing.T) {
	t.Parallel()
	store, _ := newStore(t)
	l := store.SseLog(SseLogOptions{PollInterval: 5 * time.Millisecond, IdleInterval: 5 * time.Millisecond, Page: 8})
	c := newCollector()
	if err := l.Subscribe(context.Background(), c.fn); err != nil {
		t.Fatal(err)
	}
	floor := l.Resume("").Floor
	time.Sleep(2 * time.Millisecond)
	const n = 50
	for i := 0; i < n; i++ {
		publish(t, l, "tenant:t1", auth.StreamEvent{ID: "b" + strconv.Itoa(i), Type: strconv.Itoa(i)})
	}
	stop := follow(t, l, SseFollow{Topics: []string{"tenant:t1"}, Floor: floor})
	got := c.await(t, n)
	_ = stop()
	for i, ev := range got {
		if ev.Type != strconv.Itoa(i) {
			t.Fatalf("delivery %d is %q, want %d", i, ev.Type, i)
		}
	}
	if c.count() != n {
		t.Errorf("%d deliveries, want %d", c.count(), n)
	}
}

// TestSseFollowStopsWithItsSubscription: the interface requires that a
// cancelled subscription context stops the callbacks.
func TestSseFollowStopsWithItsSubscription(t *testing.T) {
	t.Parallel()
	l, _ := fastSseLog(t)
	subCtx, cancel := context.WithCancel(context.Background())
	c := newCollector()
	if err := l.Subscribe(subCtx, c.fn); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- l.Follow(context.Background(), SseFollow{Topics: []string{"global"}, Floor: l.Resume("").Floor})
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Follow returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Follow kept running after its subscription was cancelled")
	}

	if err := (&SseLog{}).Follow(context.Background(), SseFollow{}); err != ErrSseNotSubscribed {
		t.Errorf("Follow with no subscription = %v, want ErrSseNotSubscribed", err)
	}
}

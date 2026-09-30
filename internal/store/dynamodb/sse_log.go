package dynamodb

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file is the SSE event log (D9c, data-model.md §1.5): the
// auth.SseDistributor this product implements, and the thing that makes a
// resume cursor mean something.
//
//	PK=SSE#<topic>   SK=E#<ulid>   ttl
//
// # Why a distributor is a log here
//
// The core's SseManager holds its connections in the memory of one process and
// reaches any other process only through a distributor (sse.go, SseDistributor).
// On a Lambda Function URL every connection is its own execution environment,
// so the distributor is not a scaling knob but the whole delivery path: the
// auth function's manager publishes, and the SSE function's manager — one
// connection per environment — hears it only if something carries it across.
// A table the stack already has, polled, is the carrier with no new resource
// and no standing charge. docs/cost-model.md §3.1 prices the poll.
//
// And because it is a log, it can do what the core deliberately does not: a
// connection that arrives with a cursor can be handed what it missed. The
// reference reads Last-Event-ID nowhere and neither does the core (sse.go,
// SseManager's comment: "there is no resume"), so that is a guarantee this
// product adds rather than one it implements, and it is registered as such
// (cmd/auth/deviations.go, sse-resume-replays-from-the-event-log). The
// semantics are docs/sse.md's; the mechanics are below.
//
// # The two halves, and who runs which
//
// Publish is the auth function's half: a PutItem per subscribable topic, and
// nothing else — that function holds no connection. Subscribe, in both
// functions, records the callback the core's manager hands it and starts
// nothing, because a poll loop needs to know which topics to poll and the
// interface does not say. Follow is the SSE function's half: the poll loop for
// the one connection its environment serves, started by the stream hook in
// cmd/auth once the guard has admitted the caller and the topics are known.
//
// # What the core's contract asks, and how each clause is met
//
// SseDistributor states three things (sse.go). Ordering: none required; this
// one delivers in SK order, which is ULID order — per topic, and across the
// topics of one connection because each poll merges them. Duplication:
// at-least-once is safe only for an immediate redelivery, because the
// manager's deduplication compares against the previous event alone; so
// Follow keeps its own set of delivered ULIDs and never hands the same one to
// the manager twice, and the one event published to several topics is one
// ULID (below) and is delivered once. Unavailability: a Publish error makes the
// manager deliver locally, which in the auth function is nobody — so a failed
// write is logged here, because the core swallows it.

// Defaults for SseLogOptions. The two the configuration exposes are
// tools.sse.pollIntervalMs and tools.sse.eventLogRetentionSeconds; the rest are
// this file's own and are argued where they are used.
const (
	DefaultSseRetention    = 24 * time.Hour
	DefaultSsePollInterval = time.Second

	// DefaultSseIdleInterval and DefaultSseIdleAfter are the back-off: a
	// connection that has seen nothing for a minute polls every five seconds
	// until the next event, which snaps it back. docs/cost-model.md §3.1 has
	// the arithmetic; the short version is that the poll is the one line of a
	// held connection's bill that is not GB-seconds, and a minute of silence
	// is the point past which a second of added latency on the next event is
	// cheaper than the reads that would have avoided it.
	DefaultSseIdleInterval = 5 * time.Second
	DefaultSseIdleAfter    = time.Minute

	// DefaultSseSettle is how far behind the newest delivered event each poll
	// looks again. data-model.md §1.5 argues it: an eventually consistent read,
	// or a second publisher's slower write, can make an older ULID visible
	// after a newer one, and a cursor that only moved forward would skip it.
	// Three seconds covers DynamoDB's sub-second consistency window and a
	// PutItem's ordinary latency with room for a retry.
	DefaultSseSettle = 3 * time.Second

	// DefaultSsePage bounds both one Query page and one delivery batch. It is
	// half the core's per-connection queue (defaultSseSendBuffer, 64, sse.go),
	// because the manager disconnects a connection whose queue overflows
	// (sse-slow-consumer-is-disconnected) and a replay of a busy hour must not
	// be the thing that overflows it: a batch of 32 is queued, the stream
	// writes it while the next Query is in flight, and a client that cannot
	// keep up is disconnected and resumes from its last id — which is the
	// failure mode the resume guarantee turns from data loss into a reconnect.
	DefaultSsePage = 32
)

// MaxSseEventBytes caps one logged event, as itemBytes accounts for it: the
// same margin under DynamoDB's 400 KB as every other caller-shaped item here.
// The payload is whatever POST <tools>/track or POST <tools>/notify was handed.
const MaxSseEventBytes = 300 * 1024

// maxSseTopicLen bounds the partition key's variable segment. A notify target
// is taken from the request path, so the topic is caller-shaped.
const maxSseTopicLen = 1024

// maxSseIDMemo is how many core-minted event ids Publish remembers the ULID of.
// The fan-out it exists for is one event published to up to four topics in one
// synchronous loop (AuthTools.Track), so the memo has to outlive a handful of
// interleaved requests and nothing more; a thousand is generous and costs a
// few tens of kilobytes.
const maxSseIDMemo = 1024

// ErrSseEventTooLarge means one event exceeds MaxSseEventBytes. Nothing was
// written.
var ErrSseEventTooLarge = errors.New("dynamodb: SSE event exceeds the item size limit")

// ErrSseNotSubscribed means Follow was called before the core's manager
// subscribed, so there is no callback to deliver to.
var ErrSseNotSubscribed = errors.New("dynamodb: SSE log followed before any manager subscribed to it")

// typeSseEvent is one logged event (data-model.md §5, "SSE event").
const typeSseEvent = "sseevent"

// SSE event attributes. `userId`, `tenantId` and `createdAt` are shared.
const (
	attrSseCoreID    = "coreId"
	attrSseType      = "type"
	attrSseTimestamp = "timestamp"
	attrSseTopic     = "topic"
	attrSseData      = "data"
	attrSseMetadata  = "metadata"
)

const (
	pkSsePrefix = "SSE" + keySep
	skSsePrefix = "E" + keySep
)

func ssePK(topic string) string { return pkSsePrefix + topic }
func sseSK(u ulid) string       { return skSsePrefix + u.String() }

// SseLogOptions configures an SseLog. The zero value is the defaults.
type SseLogOptions struct {
	// Retention is the TTL every event is written with and the replay
	// horizon. Defaults to DefaultSseRetention.
	Retention time.Duration
	// PollInterval is the poll period while events arrive. Defaults to
	// DefaultSsePollInterval.
	PollInterval time.Duration
	// IdleInterval and IdleAfter are the back-off. Default to
	// DefaultSseIdleInterval and DefaultSseIdleAfter.
	IdleInterval time.Duration
	IdleAfter    time.Duration
	// Settle is the look-back. Defaults to DefaultSseSettle.
	Settle time.Duration
	// Page bounds a Query page and a delivery batch. Defaults to
	// DefaultSsePage.
	Page int
}

// SseLog is the event log. Build it with Store.SseLog; it is safe for
// concurrent use.
type SseLog struct {
	store *Store
	opts  SseLogOptions
	clock ulidClock
	log   *slog.Logger

	mu     sync.Mutex
	fn     func(topic string, event auth.StreamEvent)
	subCtx context.Context

	memoMu    sync.Mutex
	memo      map[string]ulid
	memoOrder []string
}

// SseLog returns the event log over this store's table. Each call builds a new
// log with its own ULID clock and id memo, so a composition root builds one
// and hands it to the one manager it has.
func (s *Store) SseLog(opts SseLogOptions) *SseLog {
	if opts.Retention <= 0 {
		opts.Retention = DefaultSseRetention
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultSsePollInterval
	}
	if opts.IdleInterval <= 0 {
		opts.IdleInterval = DefaultSseIdleInterval
	}
	if opts.IdleInterval < opts.PollInterval {
		opts.IdleInterval = opts.PollInterval
	}
	if opts.IdleAfter <= 0 {
		opts.IdleAfter = DefaultSseIdleAfter
	}
	if opts.Settle <= 0 {
		opts.Settle = DefaultSseSettle
	}
	if opts.Page <= 0 {
		opts.Page = DefaultSsePage
	}
	return &SseLog{
		store: s,
		opts:  opts,
		clock: ulidClock{now: s.now},
		log:   s.log,
		memo:  make(map[string]ulid, maxSseIDMemo),
	}
}

// SseDistributor is handed to the core by name (auth.WithSseDistributor), so a
// drift is not a failed type assertion but a composition root that no longer
// compiles — which is the better failure, and is pinned here anyway so the
// store package fails first. See interfaces.go for the convention.
var _ auth.SseDistributor = (*SseLog)(nil)

// streamableTopic reports whether any stream can hold topic. StreamTopics
// authorises exactly three shapes (auth_tools.go) and every topic a connection
// holds comes from it, so an event published anywhere else — the session:<sid>
// copy EventTopics fans every identity event to, a custom: notify target — is
// an item nobody could ever read. data-model.md §1.5 argues skipping it;
// TestStreamTopicsAuthoriseOnlyTheLoggedShapes fails the day the core
// authorises a fourth shape.
func streamableTopic(topic string) bool {
	return topic == auth.SseTopicGlobal ||
		strings.HasPrefix(topic, auth.SseTopicTenantPrefix) ||
		strings.HasPrefix(topic, auth.SseTopicUserPrefix)
}

// Publish writes the event under topic.
//
// The event's id is replaced by a ULID in the log, the same ULID for every
// topic the one event is published to: Broadcast calls Publish once per topic
// with the event it built once, and the id it minted is the key the memo maps.
// The id Broadcast minted is kept as coreId. See data-model.md §1.5 for why the
// ULID comes from this store's clock and never from event.Timestamp.
func (l *SseLog) Publish(ctx context.Context, topic string, event auth.StreamEvent) error {
	if !streamableTopic(topic) {
		return nil
	}
	if err := checkOpaque("sse topic", topic, maxSseTopicLen); err != nil {
		return l.refused(topic, err)
	}
	id, err := l.ulidFor(event.ID)
	if err != nil {
		return l.refused(topic, err)
	}
	it, err := l.eventItem(topic, id, event)
	if err != nil {
		return l.refused(topic, err)
	}
	if n := itemBytes(it); n > MaxSseEventBytes {
		return l.refused(topic, wrapSize(ErrSseEventTooLarge, id.String(), n, MaxSseEventBytes))
	}
	if _, err := l.store.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName: aws.String(l.store.table),
		Item:      it,
	}); err != nil {
		return l.refused(topic, wrap("publish sse event", err))
	}
	return nil
}

// refused logs a Publish that failed and returns the error for the core. The
// core answers it by delivering locally (sse.go, Broadcast), which in the auth
// function reaches nobody, and returns nothing to its own caller — so this
// line is the only record that an event was not logged. The topic's shape is
// logged and not the topic, which carries a user or tenant id.
func (l *SseLog) refused(topic string, err error) error {
	shape := "other"
	switch {
	case topic == auth.SseTopicGlobal:
		shape = auth.SseTopicGlobal
	case strings.HasPrefix(topic, auth.SseTopicTenantPrefix):
		shape = auth.SseTopicTenantPrefix
	case strings.HasPrefix(topic, auth.SseTopicUserPrefix):
		shape = auth.SseTopicUserPrefix
	}
	l.log.Warn("sse event not logged: no stream will receive it",
		slog.String("topicKind", shape),
		slog.String("error", err.Error()))
	return err
}

// ulidFor returns the ULID for a core-minted id, minting one on first sight.
func (l *SseLog) ulidFor(coreID string) (ulid, error) {
	if coreID == "" {
		return l.clock.next()
	}
	l.memoMu.Lock()
	defer l.memoMu.Unlock()
	if u, ok := l.memo[coreID]; ok {
		return u, nil
	}
	u, err := l.clock.next()
	if err != nil {
		return ulid{}, err
	}
	if len(l.memoOrder) >= maxSseIDMemo {
		delete(l.memo, l.memoOrder[0])
		l.memoOrder = l.memoOrder[1:]
	}
	l.memo[coreID] = u
	l.memoOrder = append(l.memoOrder, coreID)
	return u, nil
}

// sseJSON renders a value the way the core's frame writer does — encoding/json
// with HTML escaping off and the trailing newline trimmed (sse.go,
// sseMarshal) — so that the bytes stored are the bytes a local delivery would
// have put on the wire.
func sseJSON(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// eventItem encodes one event (data-model.md §5, "SSE event").
func (l *SseLog) eventItem(topic string, id ulid, e auth.StreamEvent) (item, error) {
	data, err := sseJSON(e.Data)
	if err != nil {
		return nil, fmt.Errorf("dynamodb: sse event payload: %w", err)
	}
	it := item{}.
		sAlways(attrPK, ssePK(topic)).
		sAlways(attrSK, sseSK(id)).
		stamp(typeSseEvent).
		s(attrSseCoreID, e.ID).
		sAlways(attrSseType, e.Type).
		sAlways(attrSseTimestamp, e.Timestamp).
		sAlways(attrSseTopic, topic).
		sAlways(attrSseData, string(data)).
		s(attrUserID, e.UserID).
		s(attrTenantID, e.TenantID)
	if e.Metadata != nil {
		meta, err := sseJSON(e.Metadata)
		if err != nil {
			return nil, fmt.Errorf("dynamodb: sse event metadata: %w", err)
		}
		it = it.sAlways(attrSseMetadata, string(meta))
	}
	created := l.store.nowUTC()
	return it.sAlways(attrCreatedAt, formatTime(created)).ttl(created.Add(l.opts.Retention)), nil
}

// sseEventFromItem decodes one logged event into the StreamEvent the manager
// is handed, with the ULID as its id.
func sseEventFromItem(m map[string]types.AttributeValue) (ulid, auth.StreamEvent, error) {
	if err := checkVersion(m, typeSseEvent); err != nil {
		return ulid{}, auth.StreamEvent{}, err
	}
	sk, ok := strings.CutPrefix(getS(m, attrSK), skSsePrefix)
	if !ok {
		return ulid{}, auth.StreamEvent{}, fmt.Errorf("dynamodb: sse event with sort key %q", getS(m, attrSK))
	}
	id, err := parseULID(sk)
	if err != nil {
		return ulid{}, auth.StreamEvent{}, err
	}
	ev := auth.StreamEvent{
		ID:        id.String(),
		Type:      getS(m, attrSseType),
		Timestamp: getS(m, attrSseTimestamp),
		Topic:     getS(m, attrSseTopic),
		// The payload's own bytes, handed back as a RawMessage so the frame
		// writer emits them unchanged (data-model.md §1.5).
		Data:     json.RawMessage(getS(m, attrSseData)),
		UserID:   getS(m, attrUserID),
		TenantID: getS(m, attrTenantID),
	}
	if raw, ok := m[attrSseMetadata].(*types.AttributeValueMemberS); ok {
		dec := json.NewDecoder(strings.NewReader(raw.Value))
		dec.UseNumber()
		var meta map[string]any
		if err := dec.Decode(&meta); err != nil {
			return ulid{}, auth.StreamEvent{}, fmt.Errorf("dynamodb: sse event metadata: %w", err)
		}
		if meta == nil {
			meta = map[string]any{}
		}
		ev.Metadata = meta
	}
	return id, ev, nil
}

// Subscribe records the manager's callback. It starts no poll: the interface
// carries no topics, and a loop that polled "everything" would be a Scan. See
// the file header for who calls Follow instead. ctx bounds the subscription:
// once it is done, Follow stops calling fn, as the interface requires.
func (l *SseLog) Subscribe(ctx context.Context, fn func(topic string, event auth.StreamEvent)) error {
	if fn == nil {
		return errors.New("dynamodb: SSE log subscribed with a nil callback")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fn = fn
	l.subCtx = ctx
	return nil
}

// SseResume is a connection's starting point, resolved from what the client
// sent.
type SseResume struct {
	// Floor is the cursor the poll starts after, always a ULID this log can
	// compare. It is what the stream hands the client back as its first id
	// (docs/sse.md, "the cursor frame").
	Floor string
	// Replay reports that the client sent a cursor this log recognised and
	// is being handed what came after it.
	Replay bool
	// Truncated reports a cursor older than the retention: replay starts at
	// the horizon, and what was before it is gone.
	Truncated bool
	// Unrecognised reports a cursor this log did not mint — a UUID from the
	// connected frame of a client that has never had the cursor frame, a
	// value from another deployment, garbage — or one from the future. The
	// connection starts from now, as the reference's always does.
	Unrecognised bool
}

// futureCursorSlack is how far ahead of this clock a cursor may be and still be
// taken at its word. Two Lambda environments' clocks agree to milliseconds; a
// cursor minutes ahead did not come from here, and taking it would silence the
// connection until the clock caught up.
const futureCursorSlack = time.Minute

// Resume resolves a client's cursor — Last-Event-ID, or ?lastEventId= — into
// the connection's starting point. docs/sse.md states the semantics.
func (l *SseLog) Resume(cursor string) SseResume {
	now := l.store.nowUTC()
	fromNow := ulidAt(now).String()
	cursor = strings.TrimSpace(cursor)
	if cursor == "" {
		return SseResume{Floor: fromNow}
	}
	u, err := parseULID(cursor)
	if err != nil || u.time().After(now.Add(futureCursorSlack)) {
		return SseResume{Floor: fromNow, Unrecognised: true}
	}
	horizon := now.Add(-l.opts.Retention)
	if u.time().Before(horizon) {
		return SseResume{Floor: ulidAt(horizon).String(), Replay: true, Truncated: true}
	}
	return SseResume{Floor: u.String(), Replay: true}
}

// SseFollow is one connection's subscription.
type SseFollow struct {
	// Topics are the topics the connection holds, as StreamTopics resolved
	// them.
	Topics []string
	// Floor is SseResume.Floor.
	Floor string
	// Ready reports that the connection is registered with the manager. Serve
	// writes the connected frame before it registers the connection
	// (sse.go), so a delivery before then would reach nobody while the
	// cursor moved past it. Nil means ready.
	Ready func() bool
}

// Follow polls the connection's topics and hands every new event to the
// manager's callback, oldest first, until ctx is done or the subscription is.
// It returns nil on an ordinary end and the error of a failed Query otherwise;
// a failed Query ends the follow, and the stream with it, so the client
// reconnects with its last id instead of sitting on a stream that has stopped
// hearing anything.
func (l *SseLog) Follow(ctx context.Context, f SseFollow) error {
	l.mu.Lock()
	fn, subCtx := l.fn, l.subCtx
	l.mu.Unlock()
	if fn == nil {
		return ErrSseNotSubscribed
	}
	floor, err := parseULID(f.Floor)
	if err != nil {
		return fmt.Errorf("dynamodb: sse follow floor: %w", err)
	}
	if len(f.Topics) == 0 {
		// A stream that connected with nothing it may hear (StreamTopics
		// intersected the request away): nothing to poll, and nothing to
		// deliver, for the life of the connection.
		<-ctx.Done()
		return nil
	}
	if subCtx == nil {
		subCtx = context.Background()
	}

	if f.Ready != nil {
		if !waitReady(ctx, subCtx, f.Ready) {
			return nil
		}
	}

	// One high-water mark per topic, starting at the floor, and the set of
	// ULIDs already delivered, which the look-back makes necessary.
	high := make(map[string]ulid, len(f.Topics))
	for _, t := range f.Topics {
		high[t] = floor
	}
	seen := make(map[ulid]struct{})
	lastEvent := time.Now()

	for {
		delivered, more, err := l.pollOnce(ctx, f.Topics, floor, high, seen, fn)
		if err != nil {
			if ctx.Err() != nil || subCtx.Err() != nil {
				return nil
			}
			return err
		}

		var wait time.Duration
		switch {
		case more:
			// A page came back full: catching up, so no pause. The Query
			// itself is the pacing, and the batch is sized to the queue.
			wait = 0
		case delivered > 0:
			lastEvent = time.Now()
			wait = l.opts.PollInterval
		case time.Since(lastEvent) >= l.opts.IdleAfter:
			wait = l.opts.IdleInterval
		default:
			wait = l.opts.PollInterval
		}
		if delivered > 0 {
			lastEvent = time.Now()
		}

		if wait == 0 {
			select {
			case <-ctx.Done():
				return nil
			case <-subCtx.Done():
				return nil
			default:
				continue
			}
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-subCtx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// waitReady blocks until ready reports true or either context ends. It polls,
// because the manager offers no signal for "registered" — ConnectionCount is
// the one observable — and the window it covers is the microseconds between
// Serve's first write and its map insert.
func waitReady(ctx, subCtx context.Context, ready func() bool) bool {
	for !ready() {
		select {
		case <-ctx.Done():
			return false
		case <-subCtx.Done():
			return false
		case <-time.After(2 * time.Millisecond):
		}
	}
	return true
}

// sseEntry is one event read in a poll, before delivery.
type sseEntry struct {
	id    ulid
	topic string
	event auth.StreamEvent
}

// pollOnce reads every topic once and delivers what is new, in ULID order,
// at most Page of it. more reports that a topic had more than a page or that
// the batch was cut, so the caller polls again at once.
func (l *SseLog) pollOnce(ctx context.Context, topics []string, floor ulid, high map[string]ulid, seen map[ulid]struct{}, fn func(string, auth.StreamEvent)) (int, bool, error) {
	now := l.store.nowUTC()
	horizon := ulidAt(now.Add(-l.opts.Retention))

	var batch []sseEntry
	more := false
	lowest := ulid{}
	for i, topic := range topics {
		lower := lookBack(high[topic], floor, l.opts.Settle)
		if i == 0 || bytes.Compare(lower[:], lowest[:]) < 0 {
			lowest = lower
		}
		entries, full, err := l.readTopic(ctx, topic, lower, seen, horizon)
		if err != nil {
			return 0, false, err
		}
		batch = append(batch, entries...)
		more = more || full
	}

	// ULID order across topics. The same ULID under two topics — one event
	// published to both — sorts adjacently and is delivered once, under the
	// first; the connection holds both topics or it would not be polling them.
	sort.SliceStable(batch, func(i, j int) bool {
		return bytes.Compare(batch[i].id[:], batch[j].id[:]) < 0
	})
	delivered := 0
	for _, e := range batch {
		if _, dup := seen[e.id]; !dup {
			if delivered == l.opts.Page {
				// The batch is cut here, and nothing past the cut moves a
				// high-water mark: those events are read again next time.
				more = true
				break
			}
			fn(e.topic, e.event)
			seen[e.id] = struct{}{}
			delivered++
		}
		// An event already delivered — under this topic in an earlier poll,
		// or under another topic in this one — still moves this topic's
		// mark, so a topic whose every event is a copy does not re-read its
		// partition from the floor for the life of the connection.
		if mark := high[e.topic]; bytes.Compare(e.id[:], mark[:]) > 0 {
			high[e.topic] = e.id
		}
	}

	// The delivered set only has to remember what a look-back can still
	// return; anything below the lowest lower bound is behind every cursor.
	for id := range seen {
		if bytes.Compare(id[:], lowest[:]) <= 0 {
			delete(seen, id)
		}
	}
	return delivered, more, nil
}

// lookBack is the lower bound of a topic's next Query: Settle behind its
// high-water mark, and never below the connection's floor — the client's own
// cursor, before which nothing may be replayed.
func lookBack(high, floor ulid, settle time.Duration) ulid {
	back := ulidAt(high.time().Add(-settle))
	if bytes.Compare(back[:], floor[:]) < 0 {
		return floor
	}
	return back
}

// readTopic reads one topic after lower, skipping what is past the retention,
// until it has a page of events not yet delivered or the partition runs out.
// Events already delivered are returned too — the caller moves the topic's
// high-water mark past them — but do not count towards the page. full reports
// that it stopped at a page with more behind it.
func (l *SseLog) readTopic(ctx context.Context, topic string, lower ulid, seen map[ulid]struct{}, horizon ulid) ([]sseEntry, bool, error) {
	in := &awsddb.QueryInput{
		TableName:                aws.String(l.store.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND #SK > :after"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":    avS(ssePK(topic)),
			":after": avS(sseSK(lower)),
		},
		// Eventually consistent, on purpose: the look-back is what makes a
		// stale read safe, and it halves the line that dominates the poll's
		// bill. data-model.md §1.5.
		ConsistentRead:   aws.Bool(false),
		ScanIndexForward: aws.Bool(true),
		Limit:            aws.Int32(int32(l.opts.Page)),
	}
	var out []sseEntry
	fresh := 0
	for {
		page, err := l.store.api.Query(ctx, in)
		if err != nil {
			return nil, false, wrap("poll sse events", err)
		}
		for _, m := range page.Items {
			id, ev, err := sseEventFromItem(m)
			if err != nil {
				return nil, false, err
			}
			// TTL deletion is lazy; the horizon is not (data-model.md §1.5).
			if bytes.Compare(id[:], horizon[:]) < 0 {
				continue
			}
			if _, dup := seen[id]; !dup {
				fresh++
			}
			out = append(out, sseEntry{id: id, topic: topic, event: ev})
		}
		if len(page.LastEvaluatedKey) == 0 {
			return out, false, nil
		}
		if fresh >= l.opts.Page {
			return out, true, nil
		}
		in.ExclusiveStartKey = page.LastEvaluatedKey
	}
}

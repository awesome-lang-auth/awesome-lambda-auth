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
// manager's deduplication compares against the previous event alone. The one
// event published to several topics is one ULID (below), and within a poll
// Follow hands every copy of it to the manager back to back, in the order
// Track broadcasts them (EventTopics: global, tenant:, user:), so the
// manager's own deduplication — tools.sse.deduplicate — does exactly what it
// does in process: the first copy is framed under its own topic and the rest
// are suppressed, or, with deduplication off, each is framed. Across polls the
// copies are no longer adjacent, so Follow keeps its own set of what it
// delivered and hands a late copy over only when deduplication is off.
// Unavailability: a Publish error makes the manager deliver locally, which in
// the auth function is nobody — so a failed write is logged here, because the
// core swallows it, and the event is lost to every stream (docs/sse.md §4).

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

	// DefaultSseReplayLimit bounds what one resume replays, in events, before
	// the stream says the replay was cut and goes live
	// (tools.sse.replayLimit). A resume at a segment boundary misses the few
	// seconds of a reconnect; a hundred events is that at thirty events a
	// second, and it bounds what a cursor anybody can write — the all-zero
	// ULID, one from another deployment — costs to about four pages of reads
	// per connection instead of the whole retention (docs/cost-model.md
	// §3.1).
	DefaultSseReplayLimit = 100
)

// MaxSseEventBytes caps one logged event, as itemBytes accounts for it. The
// payload is whatever POST <tools>/track or POST <tools>/notify was handed —
// caller-shaped, with no size limit short of API Gateway's — and every copy is
// a write to a partition every connection polls, SSE#global among them, which
// holds a thousand write units a second. At DynamoDB's own ceiling one notify
// would be three hundred of them; at 16 KiB it is sixteen, and an identity
// event's tracked record is under one. An event over the cap is not logged:
// Publish refuses it, the refusal is logged, and the core's fallback delivers
// it locally, which in the auth function reaches nobody — so it reaches no
// stream (docs/sse.md §4, "What is not promised").
const MaxSseEventBytes = 16 * 1024

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
	// Page bounds a Query page, a delivery batch, and how many events behind
	// its newest one a topic's look-back re-reads. Defaults to
	// DefaultSsePage.
	Page int
	// ReplayLimit bounds the events one resume replays. Defaults to
	// DefaultSseReplayLimit.
	ReplayLimit int
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
	if opts.ReplayLimit <= 0 {
		opts.ReplayLimit = DefaultSseReplayLimit
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
	// Replay reports that the client sent a cursor this log can place and is
	// being handed what came after it, up to the replay limit.
	Replay bool
	// LookBelow reports that the cursor is an event's id, so the first read
	// reaches the look-back below it: an event older than the cursor whose
	// write was still invisible when the client's last segment ended is
	// delivered now rather than never. A floor — the id-only frame's value,
	// minted by ulidAt with an all-zero random half — is not an event and
	// has nothing owed below it (isFloor).
	LookBelow bool
	// Truncated reports a cursor older than the retention: replay starts at
	// the horizon, and what was before it is gone. The all-zero ULID lands
	// here, as does any cursor dated before the horizon.
	Truncated bool
	// Unrecognised reports a cursor that is not a well-formed ULID — a UUID
	// from the connected frame of a client that has never had the cursor
	// frame, garbage — or one more than a minute in the future. The
	// connection starts from now, as the reference's always does. A
	// well-formed ULID inside the retention is taken at its word whoever
	// minted it: nothing in a ULID says which log wrote it, and the replay
	// limit is what bounds what a foreign one costs.
	Unrecognised bool
}

// isFloor reports a ULID with an all-zero random half: what ulidAt returns,
// and so every floor this log hands a client (the id-only frame, the cut of a
// replay). The clock never mints one for an event — the chance is 2^-80 a
// millisecond — so it is how a cursor says "I heard no event; I was here".
func isFloor(u ulid) bool {
	for _, b := range u[6:] {
		if b != 0 {
			return false
		}
	}
	return true
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
	return SseResume{Floor: u.String(), Replay: true, LookBelow: !isFloor(u)}
}

// SseFollow is one connection's subscription.
type SseFollow struct {
	// Topics are the topics the connection holds, as StreamTopics resolved
	// them.
	Topics []string
	// Floor is SseResume.Floor.
	Floor string
	// Replay is SseResume.Replay: what Follow delivers until it has caught up
	// with the log is a replay, bounded by the replay limit.
	Replay bool
	// LookBelow is SseResume.LookBelow: the first read reaches the look-back
	// below the floor, and the floor's own event is not delivered again.
	LookBelow bool
	// Deduplicate is the manager's own setting (SseManager.Deduplicate,
	// tools.sse.deduplicate): whether a copy of an event that has already
	// been delivered under another topic is handed over again when it turns
	// up in a later poll. Within one poll every copy is handed over, back to
	// back, and the manager decides.
	Deduplicate bool
	// Ready reports that the connection is registered with the manager. Serve
	// writes the connected frame before it registers the connection
	// (sse.go), so a delivery before then would reach nobody while the
	// cursor moved past it. Nil means ready.
	Ready func() bool
	// ReplayCut is called when the replay reaches the replay limit with more
	// of it still in the log: last is the id of the last event replayed, and
	// floor is the ULID the stream continues live from, which the caller
	// writes to the client — after the frame with id last, and with a
	// comment — so that its cursor moves past what was skipped. Nil means
	// nobody is told, and the stream continues live all the same.
	ReplayCut func(last, floor string)
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

	st := newSseFollowState(f.Topics, floor, f.Deduplicate)
	if f.LookBelow {
		// The floor is the last event the client holds, and the one gap the
		// in-connection look-back cannot cover is an event below it whose
		// write was still invisible when the last segment ended. So the
		// first read of each topic starts a look-back below it, and the
		// floor's own event is not handed over again. What else that window
		// holds, the client may already have: at-least-once.
		st.skip, st.hasSkip = floor, true
		for _, t := range f.Topics {
			b, err := l.belowFloor(ctx, t, floor)
			if err != nil {
				if ctx.Err() != nil || subCtx.Err() != nil {
					return nil
				}
				return err
			}
			st.base[t] = b
		}
	}

	replaying, replayed := f.Replay, 0
	lastEvent := time.Now()
	more := false
	for {
		limit := l.opts.Page
		if replaying && l.opts.ReplayLimit-replayed < limit {
			limit = l.opts.ReplayLimit - replayed
		}
		// A poll straight after a full page is catching up, and skips the
		// look-back: what it would re-read was read a moment ago, and the
		// next paced poll looks back again.
		delivered, last, full, err := l.pollOnce(ctx, st, limit, !more, fn)
		if err != nil {
			if ctx.Err() != nil || subCtx.Err() != nil {
				return nil
			}
			return err
		}
		more = full
		if replaying {
			replayed += delivered
			switch {
			case !more:
				replaying = false
			case replayed >= l.opts.ReplayLimit:
				// The replay limit, with more of the replay still in the
				// log: skip the rest and go live from now. The caller tells
				// the client, after the last event replayed, and moves its
				// cursor to the jump, so the skip holds across a reconnect.
				jump := ulidAt(l.store.nowUTC())
				st.jump(jump)
				replaying, more = false, false
				if f.ReplayCut != nil {
					lastID := ""
					if last != (ulid{}) {
						lastID = last.String()
					}
					f.ReplayCut(lastID, jump.String())
				}
			}
		}

		var wait time.Duration
		switch {
		case more:
			// A page came back full: catching up, so no pause. The Query
			// itself is the pacing, and the batch is sized to the queue.
			wait = 0
		case delivered > 0:
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

// sseSeenKey is one delivery Follow remembers: the event, and — with the
// manager's deduplication off — the topic it was delivered under, because
// then each topic's copy is a delivery of its own.
type sseSeenKey struct {
	id    ulid
	topic string
}

// sseFollowState is one connection's position in the log.
type sseFollowState struct {
	topics []string
	dedup  bool
	// base is the lowest bound a topic's read may start from: the floor, or
	// the look-back below it for a resumed cursor.
	base map[string]ulid
	// high is each topic's high-water mark: the newest event read and
	// accounted for.
	high map[string]ulid
	// recent is each topic's last few events at or below its mark, oldest
	// first, which bounds the look-back by count as well as by time.
	recent map[string][]ulid
	// seen is what was delivered and a look-back can still return.
	seen map[sseSeenKey]struct{}
	// skip is the resumed cursor's own event, which the client holds.
	skip    ulid
	hasSkip bool
}

// newSseFollowState starts every topic at floor.
func newSseFollowState(topics []string, floor ulid, dedup bool) *sseFollowState {
	st := &sseFollowState{
		topics: topics,
		dedup:  dedup,
		base:   make(map[string]ulid, len(topics)),
		high:   make(map[string]ulid, len(topics)),
		recent: make(map[string][]ulid, len(topics)),
		seen:   make(map[sseSeenKey]struct{}),
	}
	for _, t := range topics {
		st.base[t], st.high[t] = floor, floor
	}
	return st
}

func (st *sseFollowState) key(id ulid, topic string) sseSeenKey {
	if st.dedup {
		return sseSeenKey{id: id}
	}
	return sseSeenKey{id: id, topic: topic}
}

func (st *sseFollowState) isSeen(id ulid, topic string) bool {
	if st.hasSkip && id == st.skip {
		return true
	}
	_, ok := st.seen[st.key(id, topic)]
	return ok
}

// jump moves every topic to floor and forgets everything behind it: what a
// cut replay continues from.
func (st *sseFollowState) jump(floor ulid) {
	for _, t := range st.topics {
		st.base[t], st.high[t] = floor, floor
		delete(st.recent, t)
	}
	st.seen = make(map[sseSeenKey]struct{})
	st.hasSkip = false
}

// remember records id as read on topic, keeping the newest keep of them.
func (st *sseFollowState) remember(topic string, id ulid, keep int) {
	r := st.recent[topic]
	i := sort.Search(len(r), func(i int) bool { return bytes.Compare(r[i][:], id[:]) >= 0 })
	if i < len(r) && r[i] == id {
		return
	}
	r = append(r, ulid{})
	copy(r[i+1:], r[i:])
	r[i] = id
	if len(r) > keep {
		r = r[len(r)-keep:]
	}
	st.recent[topic] = r
}

// sseEntry is one event read in a poll, before delivery.
type sseEntry struct {
	id    ulid
	topic string
	event auth.StreamEvent
}

// topicRank is the order Track broadcasts one event's topics in — EventTopics
// (auth_tools.go): global, then tenant:, then user: — which is the order the
// copies of one event are handed to the manager in, so that the copy the
// manager frames first, and with deduplication on frames alone, is the copy
// the core's in-process delivery frames: the one under the earliest topic in
// that order, whatever order the client listed its topics in.
func topicRank(topic string) int {
	switch {
	case topic == auth.SseTopicGlobal:
		return 0
	case strings.HasPrefix(topic, auth.SseTopicTenantPrefix):
		return 1
	case strings.HasPrefix(topic, auth.SseTopicUserPrefix):
		return 2
	default:
		return 3
	}
}

// pollOnce reads every topic once and delivers what is new, in ULID order, at
// most limit events of it (an event's copies under several topics count once,
// and are never split across two polls). It returns how many events it
// delivered, the id of the last, and whether a topic had more than a page or
// the batch was cut, so that the caller polls again at once. lookBack is false
// on a poll that is catching up.
func (l *SseLog) pollOnce(ctx context.Context, st *sseFollowState, limit int, lookBack bool, fn func(string, auth.StreamEvent)) (int, ulid, bool, error) {
	now := l.store.nowUTC()
	horizon := ulidAt(now.Add(-l.opts.Retention))
	keep := l.opts.Page + 1

	var batch []sseEntry
	more := false
	lowest := ulid{}
	for i, topic := range st.topics {
		lower := st.high[topic]
		if lookBack {
			lower = lookBackFrom(st.high[topic], st.base[topic], l.opts.Settle)
			// And by count: at most a page of events behind the mark is
			// read again, so a busy topic's look-back is its last Page
			// events rather than three seconds of them — the re-read no
			// longer grows with the event rate.
			if r := st.recent[topic]; len(r) >= keep && bytes.Compare(r[0][:], lower[:]) > 0 {
				lower = r[0]
			}
		}
		if i == 0 || bytes.Compare(lower[:], lowest[:]) < 0 {
			lowest = lower
		}
		entries, full, err := l.readTopic(ctx, topic, lower, st.isSeen, horizon)
		if err != nil {
			return 0, ulid{}, false, err
		}
		batch = append(batch, entries...)
		more = more || full
	}

	// ULID order across topics, and within one ULID the broadcast order.
	sort.SliceStable(batch, func(i, j int) bool {
		if c := bytes.Compare(batch[i].id[:], batch[j].id[:]); c != 0 {
			return c < 0
		}
		return topicRank(batch[i].topic) < topicRank(batch[j].topic)
	})
	delivered := 0
	var last ulid
	for start := 0; start < len(batch); {
		end := start + 1
		for end < len(batch) && batch[end].id == batch[start].id {
			end++
		}
		group := batch[start:end]
		var copies []sseEntry
		for _, e := range group {
			if !st.isSeen(e.id, e.topic) {
				copies = append(copies, e)
			}
		}
		if len(copies) > 0 {
			if delivered >= limit {
				// The batch is cut here, at an event's boundary, and nothing
				// past the cut moves a high-water mark: those events are read
				// again next time.
				more = true
				break
			}
			// Every copy not yet delivered, back to back — decided before
			// any is marked, so that marking the first under deduplication
			// does not hide the rest from the manager: with deduplication
			// on it frames the first and suppresses the others (its
			// lastEventID), exactly as for Track's in-process broadcasts,
			// and with it off it frames each.
			for _, e := range copies {
				fn(e.topic, e.event)
			}
			for _, e := range copies {
				st.seen[st.key(e.id, e.topic)] = struct{}{}
			}
			delivered++
			last = group[0].id
		}
		// An event already delivered — under this topic in an earlier poll,
		// or under another topic — still moves this topic's mark, so a topic
		// whose every event is a copy does not re-read its partition from the
		// floor for the life of the connection.
		for _, e := range group {
			if mark := st.high[e.topic]; bytes.Compare(e.id[:], mark[:]) > 0 {
				st.high[e.topic] = e.id
			}
			st.remember(e.topic, e.id, keep)
		}
		start = end
	}

	// The delivered set only has to remember what a look-back can still
	// return; anything below the lowest lower bound is behind every cursor.
	for k := range st.seen {
		if bytes.Compare(k.id[:], lowest[:]) <= 0 {
			delete(st.seen, k)
		}
	}
	return delivered, last, more, nil
}

// lookBackFrom is the lower bound of a topic's next Query: Settle behind its
// high-water mark, and never below the topic's base — the floor, or for a
// resumed cursor the look-back below it, before which nothing may be
// replayed.
func lookBackFrom(high, base ulid, settle time.Duration) ulid {
	back := ulidAt(high.time().Add(-settle))
	if bytes.Compare(back[:], base[:]) < 0 {
		return base
	}
	return back
}

// belowFloor is the base of a resumed topic: Settle below the cursor, or — if
// that window holds more than a page of events — the page of them nearest the
// cursor, so that the look-back below a resume is bounded by count as the one
// inside a connection is. One Query, newest first, of at most Page+1 keys.
func (l *SseLog) belowFloor(ctx context.Context, topic string, floor ulid) (ulid, error) {
	lo := ulidAt(floor.time().Add(-l.opts.Settle))
	out, err := l.store.api.Query(ctx, &awsddb.QueryInput{
		TableName:                aws.String(l.store.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND #SK BETWEEN :lo AND :hi"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": avS(ssePK(topic)),
			":lo": avS(sseSK(lo)),
			":hi": avS(sseSK(floor)),
		},
		ProjectionExpression: aws.String("#SK"),
		ConsistentRead:       aws.Bool(false),
		ScanIndexForward:     aws.Bool(false),
		Limit:                aws.Int32(int32(l.opts.Page + 1)),
	})
	if err != nil {
		return ulid{}, wrap("look below an sse cursor", err)
	}
	if len(out.Items) <= l.opts.Page {
		return lo, nil
	}
	sk, ok := strings.CutPrefix(getS(out.Items[len(out.Items)-1], attrSK), skSsePrefix)
	if !ok {
		return lo, nil
	}
	oldest, err := parseULID(sk)
	if err != nil {
		return lo, nil
	}
	return oldest, nil
}

// readTopic reads one topic after lower, skipping what is past the retention,
// until it has a page of events not yet delivered or the partition runs out.
// Events already delivered are returned too — the caller moves the topic's
// high-water mark past them — but do not count towards the page. full reports
// that it stopped at a page with more behind it.
func (l *SseLog) readTopic(ctx context.Context, topic string, lower ulid, seen func(ulid, string) bool, horizon ulid) ([]sseEntry, bool, error) {
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
			if !seen(id, topic) {
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

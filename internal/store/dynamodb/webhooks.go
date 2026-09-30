package dynamodb

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	auth "github.com/nik2208/awesome-go-auth"
)

// This file implements the three webhook stores of core v0.8.0: WebhookStore
// (FindByEvent, the only mandatory one), WebhookAdminStore and
// InboundWebhookStore.
//
// One item per subscription, in one directory partition:
//
//	PK=WEBHOOKS  SK=WHK#<id>
//
// Modelled on the template directory (templates.go) and for its reasons. The
// set is bounded and administrator-authored, every read of it is a
// whole-partition Query, and keeping it in the main table rather than behind a
// GSI makes those reads strongly consistent — so the admin who just saved a
// subscription sees it in the next listing, which an eventually-consistent index
// would turn into a lost edit they would report as a bug.
//
// The sort key's tail is the store-assigned id, which means a configuration is
// addressable by the id UpdateWebhook and RemoveWebhook carry, with no second
// pointer item. The price is the listing order; see below.
//
// # FindByEvent is the only filter in the delivery chain
//
// The core is explicit and the consequence is severe: the emit path hands every
// configuration this method returns straight to the sender, which re-checks
// neither isActive nor events. **A store that over-returns delivers.** So the
// three rules — active only, tenant scope, event match — are applied by
// WebhookConfig.Matches, the exported helper the core supplies for exactly this,
// rather than re-derived here. Re-deriving them is how the wildcard, the
// empty-events case and the global-webhook case drift per backend, and the drift
// is invisible until a webhook fires for the wrong tenant.
//
// The same caller swallows a store failure with .catch(() => []), so an error
// from FindByEvent means "no webhooks for this event" and never a failed emit.
// Returning an error is therefore not a way to refuse an event; an empty slice
// is.
//
// # Why the tenant is matched in memory, and why that is not a §3 violation
//
// §3's rule is that tenant isolation is a property of the key and never of a
// filter. It is not bent here, because a webhook's TenantID is not an isolation
// boundary: an empty one means *global*, a subscription that fires for every
// tenant, so the predicate FindByEvent needs is "mine **or** global" and no
// single partition key expresses a disjunction. The rule exists to stop one
// tenant's *user data* being reachable from another tenant's query; this is
// deployment configuration an administrator writes, the whole set is read as one
// Query by design, and the core ships Matches precisely so that stores do this
// in memory. §3 is amended to say so rather than left to look violated.
//
// # Ordering: the one deviation
//
// The core's normative order is first-insertion, which MemoryWebhookStore
// guarantees and which this design cannot reproduce: a Query returns a partition
// in sort-key order, and the sort key's tail is a random id. So all three
// readers — FindByEvent, ListWebhooks and FindByProvider — answer in **id**
// order, and CompatibilityNotes registers it, exactly as it registers the
// template directory's id order against MemoryTemplateStore's insertion order.
//
// The alternative was a creation-timestamp sort key, which would have been
// insertion order in all but pathological cases and would have cost a by-id
// pointer item for the two methods that carry only an id. It was rejected
// because "insertion order except when two land in the same nanosecond or the
// clock steps backwards" is a deviation that has to be registered *anyway*, and
// a registered order that is simply "by id" is one a reader can predict.

// Webhook attributes. They are the reference's JSON key names verbatim
// (WebhookConfig's tags), so a stored subscription round-trips between this port
// and a node-auth deployment unchanged — the same bargain the settings document
// strikes. `isActive` is shared with the tenant and API key items (tenants.go).
const (
	attrWebhookURL     = "url"
	attrWebhookEvents  = "events"
	attrWebhookSecret  = "secret"
	attrMaxRetries     = "maxRetries"
	attrRetryDelayMs   = "retryDelayMs"
	attrWebhookProv    = "provider"
	attrAllowedActions = "allowedActions"
	attrJSScript       = "jsScript"
)

// webhookDirectoryCap bounds every read of the directory. Five hundred, and the
// number is an integrity check rather than a page size, as templateDirectoryCap
// is: a deployment with three digits of webhook subscriptions has something
// writing them that should not be, and FindByEvent reads the whole partition on
// every emitted event, so the cap is also the bound on that read.
const webhookDirectoryCap = 500

// MaxWebhookBytes caps a subscription as itemBytes accounts for it.
//
// JSScript is the reason: it is an administrator-authored program carried as
// data (this port will never run it in process — see WebhookConfig's inbound
// fields and U25's InboundScriptRunner), and nothing in the interface bounds it.
// Refusing at 300 KB, with the same 100 KB margin MaxTemplateBytes keeps, turns
// the SDK's ValidationException into a typed error before anything is written.
const MaxWebhookBytes = 300 * 1024

// ErrWebhookTooLarge means the subscription exceeds MaxWebhookBytes. Nothing was
// written.
var ErrWebhookTooLarge = errors.New("dynamodb: webhook configuration exceeds the item size limit")

// Webhooks returns this store as the auth.WebhookStore the composition root will
// hand to the emit path. The methods are on *Store itself; the accessor exists
// so cmd/auth can find the capability structurally.
func (s *Store) Webhooks() auth.WebhookStore { return s }

// All three are reached by type assertion on the configured webhook store, so a
// drift is a route changing its answer rather than a build failing — and for
// FindByEvent it is worse than a 501: the emit path swallows the failure and
// delivers nothing, silently. See interfaces.go for the convention.
var (
	_ auth.WebhookStore        = (*Store)(nil)
	_ auth.WebhookAdminStore   = (*Store)(nil)
	_ auth.InboundWebhookStore = (*Store)(nil)
)

// FindByEvent returns every configuration that should receive event on behalf of
// tenantID.
//
// A coarse Query over the whole directory, then WebhookConfig.Matches. See the
// file header for why the filter is in memory and why it is the core's helper
// rather than three conditions written here.
//
// Eventually consistent would have been defensible for a delivery path; this
// reads the main table, so it is strongly consistent for free.
func (s *Store) FindByEvent(ctx context.Context, event, tenantID string) ([]auth.WebhookConfig, error) {
	configs, err := s.webhookDirectory(ctx, "find webhooks by event")
	if err != nil {
		return nil, err
	}
	out := make([]auth.WebhookConfig, 0, len(configs))
	for _, c := range configs {
		if c.Matches(event, tenantID) {
			out = append(out, c)
		}
	}
	return out, nil
}

// ListWebhooks returns one page of every configuration the store holds, active
// or not, in id order.
//
// Paged in memory rather than by a Query window, because the directory is
// already drained whole for FindByEvent and is bounded by webhookDirectoryCap:
// pushing limit/offset into the Query would add a second code path over a set
// that fits in one page, and the offset would still be positional. The paging
// rules are pageWindow's, which are the core's.
func (s *Store) ListWebhooks(ctx context.Context, limit, offset int) ([]auth.WebhookConfig, error) {
	limit, offset, work, err := s.pageWindow(limit, offset)
	if err != nil {
		return nil, err
	}
	if !work {
		return []auth.WebhookConfig{}, nil
	}
	configs, err := s.webhookDirectory(ctx, "list webhooks")
	if err != nil {
		return nil, err
	}
	if offset >= len(configs) {
		return []auth.WebhookConfig{}, nil
	}
	end := min(offset+limit, len(configs))
	return configs[offset:end], nil
}

// AddWebhook stores a new configuration and returns it with the id the store
// assigned. config.ID is ignored, which is what the core's Omit<WebhookConfig,
// "id"> spells in a language that has it.
//
// Nothing is defaulted on the way in: Active, Retries and RetryDelay resolve nil
// at the point of use, and the reference's own defaulting of events to ["*"] and
// isActive to true happens in the admin route the console mounts (core
// admin_credentials.go reproduces `events ?? ['*']` and `isActive ?? true`). That
// is why the encoding below writes an absent optional as an absent attribute
// rather than as its resolved value — a configuration stored without
// allowedActions must not come back with [], and one stored without isActive
// must not come back false, which would silence it.
//
// The write is conditional on the id being free. Ids are 128 bits of randomness
// so a collision is not a case that arises; the condition is there because a Put
// that silently replaced a live subscription would be the one failure nobody
// would look for.
func (s *Store) AddWebhook(ctx context.Context, config auth.WebhookConfig) (auth.WebhookConfig, error) {
	id, err := newWebhookID()
	if err != nil {
		return auth.WebhookConfig{}, err
	}
	config.ID = id

	it, err := webhookItem(config)
	if err != nil {
		return auth.WebhookConfig{}, err
	}
	if n := itemBytes(it); n > MaxWebhookBytes {
		return auth.WebhookConfig{}, wrapSize(ErrWebhookTooLarge, id, n, MaxWebhookBytes)
	}
	if _, err := s.api.PutItem(ctx, &awsddb.PutItemInput{
		TableName:                aws.String(s.table),
		Item:                     it,
		ConditionExpression:      aws.String("attribute_not_exists(#SK)"),
		ExpressionAttributeNames: exprNames(attrSK),
	}); err != nil {
		return auth.WebhookConfig{}, wrap("add webhook", err)
	}
	return config, nil
}

// UpdateWebhook applies a partial update. An id the store does not hold is not
// an error — the core says so, and the admin route answers success without
// asking whether anything changed.
//
// A read-modify-write behind a condition, the shape UpdateMailTemplate and
// UpdateSettings already use and for the same reason: the patch names only the
// fields it changes, the interface carries nothing else, so the rest is read —
// and the read decides nothing, because the write re-asserts the updatedAt it
// observed. Two administrators patching different fields both land, and a patch
// whose observation went stale is retried from the pre-image the failure
// returned rather than applied over the top of what it never saw.
//
// WebhookPatch's own rule is preserved exactly: a nil pointer leaves the stored
// field alone, a pointer to a zero value sets that zero — *IsActive = false is
// how the admin toggle turns a webhook off and must be distinguishable from
// "not in this patch" — and a non-nil slice replaces the stored one whole.
// applyTo is unexported in the core, so the same rule is written out here; the
// test pins it against WebhookPatch's documented behaviour field by field.
func (s *Store) UpdateWebhook(ctx context.Context, id string, patch auth.WebhookPatch) error {
	if err := checkOpaque("webhook id", id, maxRoleNameLen); err != nil {
		return nil
	}
	current, err := s.webhookItem(ctx, id)
	if err != nil {
		return err
	}
	for attempt := 0; ; attempt++ {
		if current == nil {
			return nil
		}
		stored, err := webhookFromItem(current)
		if err != nil {
			return err
		}
		observed := getS(current, attrUpdatedAt)
		applyWebhookPatch(&stored, patch)

		it, err := webhookItem(stored)
		if err != nil {
			return err
		}
		it = it.sAlways(attrUpdatedAt, s.nextStamp(observed))
		if n := itemBytes(it); n > MaxWebhookBytes {
			return wrapSize(ErrWebhookTooLarge, id, n, MaxWebhookBytes)
		}

		err = s.putIfUnchanged(ctx, it, observed)
		if err == nil {
			return nil
		}
		pre, lost := conditionFailedItem(err)
		if !lost {
			return wrap("update webhook", err)
		}
		if attempt == webhookPatchAttempts-1 {
			return fmt.Errorf("%w: %q", ErrWebhookConflict, id)
		}
		current = pre
		if len(current) == 0 {
			// No pre-image: either the subscription was removed under us, which
			// UpdateWebhook answers with success, or the endpoint did not honour
			// ALL_OLD. A read tells the two apart.
			if current, err = s.webhookItem(ctx, id); err != nil {
				return err
			}
		}
	}
}

// webhookPatchAttempts bounds the compare-and-set loop, for
// templatePatchAttempts' reasons and with its number: a writer loses at most
// once per concurrent writer, and the writers here are administrators rather
// than requests, so reaching the bound is a fault rather than contention.
const webhookPatchAttempts = 16

// ErrWebhookConflict means UpdateWebhook lost its compare-and-set
// webhookPatchAttempts times in a row.
var ErrWebhookConflict = errors.New("dynamodb: webhook was patched concurrently too many times")

// RemoveWebhook permanently deletes a configuration. An id the store does not
// hold is not an error: the core's remove returns void and its route answers
// success without asking whether anything was deleted, so a second DELETE of the
// same id succeeds.
func (s *Store) RemoveWebhook(ctx context.Context, id string) error {
	if err := checkOpaque("webhook id", id, maxRoleNameLen); err != nil {
		return nil
	}
	if _, err := s.api.DeleteItem(ctx, &awsddb.DeleteItemInput{
		TableName: aws.String(s.table),
		Key:       key(webhooksPK, webhookSK(id)),
	}); err != nil {
		return wrap("remove webhook", err)
	}
	return nil
}

// FindByProvider returns the inbound configuration registered for provider, and
// false when there is none.
//
// **It deliberately does not filter on IsActive.** FindByEvent's contract is
// "active configurations only" and this one's is not, because the reference's
// only caller tests the result for a jsScript and nothing else: deactivating a
// webhook stops outgoing deliveries and does not stop an inbound script from
// running. That is the reference's behaviour, it is reproduced rather than
// corrected, and a store must not quietly fix it by filtering here — which is
// why this method does not go anywhere near Matches.
//
// An empty provider never matches: every outgoing-only configuration leaves the
// field unset, so matching on "" would hand the router one of those.
//
// The first match in id order, where MemoryWebhookStore returns the first in
// insertion order. Same registered deviation as the listing; with more than one
// configuration per provider it is a different answer, and nothing in the
// reference prevents a deployment from having two.
func (s *Store) FindByProvider(ctx context.Context, provider string) (auth.WebhookConfig, bool, error) {
	if provider == "" {
		return auth.WebhookConfig{}, false, nil
	}
	configs, err := s.webhookDirectory(ctx, "find webhook by provider")
	if err != nil {
		return auth.WebhookConfig{}, false, err
	}
	for _, c := range configs {
		if c.Provider == provider {
			return c, true, nil
		}
	}
	return auth.WebhookConfig{}, false, nil
}

// webhookDirectory drains the whole partition, decoded and in id order. Every
// reader goes through it, so all three answer in the same order by construction.
func (s *Store) webhookDirectory(ctx context.Context, op string) ([]auth.WebhookConfig, error) {
	items, err := s.queryAll(ctx, &awsddb.QueryInput{
		TableName:                aws.String(s.table),
		KeyConditionExpression:   aws.String("#PK = :pk AND begins_with(#SK, :prefix)"),
		ExpressionAttributeNames: exprNames(attrPK, attrSK),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk":     avS(webhooksPK),
			":prefix": avS(skWebhookPrefix),
		},
		ConsistentRead: aws.Bool(true),
	}, webhookDirectoryCap)
	if err != nil {
		if errors.Is(err, ErrResultTooLarge) {
			return nil, err
		}
		return nil, wrap(op, err)
	}
	out := make([]auth.WebhookConfig, 0, len(items))
	for _, m := range items {
		c, err := webhookFromItem(m)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// webhookItem reads one subscription by id. nil means absent.
func (s *Store) webhookItem(ctx context.Context, id string) (map[string]types.AttributeValue, error) {
	out, err := s.api.GetItem(ctx, &awsddb.GetItemInput{
		TableName:      aws.String(s.table),
		Key:            key(webhooksPK, webhookSK(id)),
		ConsistentRead: aws.Bool(true),
	})
	if err != nil {
		return nil, wrap("get webhook", err)
	}
	if len(out.Item) == 0 {
		return nil, nil
	}
	return out.Item, nil
}

// applyWebhookPatch is auth.WebhookPatch's documented semantics, written out
// because the core's own applyTo is unexported.
//
// Every rule here is the core's: a nil pointer leaves the stored field alone; a
// pointer to a zero value sets that zero; a nil slice leaves the stored slice
// alone and a non-nil one replaces it whole, a non-nil empty one clearing it. A
// patch cannot put an optional field back to absent — nil is already spent on
// "leave alone" — which is the core's limitation too, and the way out is to read
// the config, remove the field and add it back.
func applyWebhookPatch(c *auth.WebhookConfig, p auth.WebhookPatch) {
	if p.URL != nil {
		c.URL = *p.URL
	}
	if p.Events != nil {
		c.Events = copyStrings(p.Events)
	}
	if p.Secret != nil {
		c.Secret = *p.Secret
	}
	if p.IsActive != nil {
		v := *p.IsActive
		c.IsActive = &v
	}
	if p.TenantID != nil {
		c.TenantID = *p.TenantID
	}
	if p.MaxRetries != nil {
		v := *p.MaxRetries
		c.MaxRetries = &v
	}
	if p.RetryDelayMs != nil {
		v := *p.RetryDelayMs
		c.RetryDelayMs = &v
	}
	if p.Provider != nil {
		c.Provider = *p.Provider
	}
	if p.AllowedActions != nil {
		c.AllowedActions = copyStrings(p.AllowedActions)
	}
	if p.JSScript != nil {
		c.JSScript = *p.JSScript
	}
}

// copyStrings is the core's own copySlice (settings_store.go), reproduced
// because it is unexported there and because the obvious idiom is wrong for
// exactly the case this type cares about: `append([]string(nil), in...)` returns
// **nil** for a non-nil empty input, which would turn "the administrator cleared
// the event list" back into "the key is absent" — and an absent events key is
// what the defaults are applied to.
func copyStrings(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}

// webhookItem encodes a subscription (data-model.md §5, "Webhook
// subscription").
//
// Every optional field is written only when it is set, because absent is a value
// here and not a default — the settings document's rule, and load-bearing for
// the same reason. IsActive nil defaults to true at the point of use, so a nil
// written as false would silence a webhook; MaxRetries and RetryDelayMs are
// resolved with ?? in the sender, which keeps 0 as 0, so maxRetries: 0 ("deliver
// once, never retry") must not decay into "retry three times".
//
// The two slices are written as an L, an empty one included, so that nil (the
// key is absent) stays distinct from empty (the administrator cleared it). An
// empty events list matches nothing, which is the opposite of the in-code
// endpoint list's rule and is deliberate on both sides.
func webhookItem(c auth.WebhookConfig) (item, error) {
	if c.ID == "" {
		return nil, errors.New("dynamodb: webhook id is required")
	}
	it := item{}.
		sAlways(attrPK, webhooksPK).
		sAlways(attrSK, webhookSK(c.ID)).
		stamp(typeWebhook).
		// sAlways rather than s: the url is what a subscription *is*, and an
		// absent one should read back as the empty string the caller stored
		// rather than as a missing attribute nobody can tell from a decode bug.
		sAlways(attrWebhookURL, c.URL).
		avIf(attrWebhookEvents, c.Events != nil, func() types.AttributeValue { return stringListAV(c.Events) }).
		s(attrWebhookSecret, c.Secret).
		s(attrTenantID, c.TenantID).
		s(attrWebhookProv, c.Provider).
		avIf(attrAllowedActions, c.AllowedActions != nil, func() types.AttributeValue { return stringListAV(c.AllowedActions) }).
		s(attrJSScript, c.JSScript)
	if c.IsActive != nil {
		it = it.b(attrIsActive, *c.IsActive)
	}
	if c.MaxRetries != nil {
		it = it.n(attrMaxRetries, int64(*c.MaxRetries))
	}
	if c.RetryDelayMs != nil {
		it = it.n(attrRetryDelayMs, int64(*c.RetryDelayMs))
	}
	return it, nil
}

func webhookFromItem(m map[string]types.AttributeValue) (auth.WebhookConfig, error) {
	if err := checkVersion(m, typeWebhook); err != nil {
		return auth.WebhookConfig{}, err
	}
	id, ok := webhookIDFromSK(getS(m, attrSK))
	if !ok {
		return auth.WebhookConfig{}, fmt.Errorf("dynamodb: %q is not a webhook sort key", getS(m, attrSK))
	}
	return auth.WebhookConfig{
		ID:             id,
		URL:            getS(m, attrWebhookURL),
		Events:         stringListFromAV(m[attrWebhookEvents]),
		Secret:         getS(m, attrWebhookSecret),
		IsActive:       getBoolPtr(m, attrIsActive),
		TenantID:       getS(m, attrTenantID),
		MaxRetries:     getIntPtr(m, attrMaxRetries),
		RetryDelayMs:   getIntPtr(m, attrRetryDelayMs),
		Provider:       getS(m, attrWebhookProv),
		AllowedActions: stringListFromAV(m[attrAllowedActions]),
		JSScript:       getS(m, attrJSScript),
	}, nil
}

// newWebhookID mints the id AddWebhook assigns, in the shape the core's own
// newID produces: a three-letter kind, an underscore and 32 hex characters.
//
// Minted here rather than taken from the core because newID is unexported there.
// The shape is copied so that an id this store assigns is indistinguishable from
// one MemoryWebhookStore would have, which matters the day a deployment migrates
// between the two — and so that it satisfies idPattern, which is what keeps
// WHK#<id> unambiguous.
func newWebhookID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("dynamodb: mint webhook id: %w", err)
	}
	return "whk_" + hex.EncodeToString(b), nil
}

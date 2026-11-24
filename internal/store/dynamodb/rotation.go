package dynamodb

import (
	"context"
	"sync"
)

// rotationScope is the request-scoped hand-off between
// GetSessionByRefreshTokenHash and UpdateSession.
//
// It exists because SessionStore.UpdateSession(ctx, Session) is a whole-struct
// write with no precondition token: the store is handed the *new* refresh hash
// and never learns the old one, and auth.Session has no generation field
// (models.go:49-57). Without the old hash there is nothing to condition a
// rotation on, so two concurrent refreshes of the same token both succeed.
//
// Service.Refresh passes one ctx to both calls (service.go:129 and :159), so a
// value installed per request is a correct and correctly-scoped carrier for the
// hash the read observed. A ctx cannot be mutated by the callee, hence the
// pointer: the HTTP layer installs an empty scope, the read fills it, the write
// consumes it.
//
// This is the interim of data-model.md §4.3. The durable fix is the upstream
// SessionRotationStore optional interface, which RotateSession already
// implements — when that lands, the scope becomes dead code.
type rotationScope struct {
	mu      sync.Mutex
	set     bool
	pre     rotationPrecondition
	session string
}

// rotationPrecondition is what a rotation can be made conditional on.
type rotationPrecondition struct {
	oldHash string
	gen     int64
	hasGen  bool

	// epoch is the session's stamp as the read found it, for the check
	// rotate makes against the account's session epoch once it has committed
	// (session_epoch.go). Without it the check reads the stamp itself.
	epoch    int64
	hasEpoch bool
}

type rotationScopeKey struct{}

// WithRotationScope prepares ctx to carry a refresh rotation's precondition. The
// HTTP layer must call it once per request, before invoking the auth service;
// without it the store still rotates, but only under
// attribute_not_exists(revokedAt), and a replayed token is caught one request
// later instead of immediately.
//
// Calling it twice on the same ctx is a no-op, so nesting middleware is safe.
func WithRotationScope(ctx context.Context) context.Context {
	if rotationScopeFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, rotationScopeKey{}, &rotationScope{})
}

func rotationScopeFrom(ctx context.Context) *rotationScope {
	scope, _ := ctx.Value(rotationScopeKey{}).(*rotationScope)
	return scope
}

func (r *rotationScope) record(sessionID string, pre rotationPrecondition) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.session = sessionID
	r.pre = pre
	r.set = true
}

// take returns the precondition recorded for sessionID and clears it. Clearing
// matters: a second UpdateSession on the same ctx must not reuse a stale hash,
// which would either fail spuriously or, worse, pin the wrong generation.
func (r *rotationScope) take(sessionID string) (rotationPrecondition, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.set || r.session != sessionID {
		return rotationPrecondition{}, false
	}
	pre := r.pre
	r.set = false
	r.pre = rotationPrecondition{}
	return pre, true
}

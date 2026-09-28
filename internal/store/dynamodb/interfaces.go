package dynamodb

// This file used to hold every compile-time interface assertion this package
// makes, in one block. It now holds none of them: each assertion lives in the
// file that implements the interface it pins, immediately above the methods it
// is about, and the prose that explains why a particular one matters travels
// with it.
//
// What is left here is the argument for having the assertions at all, which is
// the same for all of them and belonged in one place even when the list did,
// plus the register of what this package deliberately does not implement.
//
// # Why every interface is pinned
//
// The auth core discovers most of its optional capabilities by type assertion on
// the concrete store (Service.ListSessions asserts SessionAdminStore,
// Service.ListUsers asserts AdminUserStore, and so on). A method whose signature
// drifts out of shape therefore does not fail to build: the assertion simply
// stops succeeding, Service stops offering the feature, and the route answers
// ErrFeatureNotSupported — a 501 on the wire, from a binary that compiled
// cleanly and whose store tests all passed. The assertion is what turns that
// into a build failure.
//
// Three capabilities are worse than that, because the core does not even
// type-assert them: TemplateStore, SettingsStore and AuthCodeStore are handed
// over explicitly (auth.WithTemplateStore, auth.WithSettingsStore,
// IDPConfig.Codes). A drifted signature there is not a failed assertion but a
// composition root that no longer compiles — if it names the interface — or, if
// it does not, a nil capability that silently selects the core's in-process
// default. Each of those three is pinned in its own file and reached through an
// accessor (Templates(), Settings(), AuthCodes()) that cmd/auth pins as well.
//
// # Why one per file rather than one block
//
// A central block is a file every store touches. This package gains a store per
// roadmap block, each on its own branch, and the block made every one of them
// conflict with every other for a reason that has nothing to do with the code:
// two assertions appended to one list. Beside the implementation there is no
// shared line to contend for, and the explanatory paragraph — which is the
// valuable half — sits next to the methods it explains instead of a screen away
// from them.
//
// The convention, so a later block does not have to infer it: put
//
//	var _ auth.SomethingStore = (*Store)(nil)
//
// directly above the first method of the group, in the file that implements it,
// with the paragraph that says what breaks if the signature drifts. Nothing
// collects them; `go build` does.
//
// # Interfaces deliberately NOT implemented
//
// Listed so their absence reads as a decision rather than an omission.
//
//   - auth.APIKeyAuditStore — the reference's optional `logUsage?`. Nothing in
//     the core calls it: the caller is the API key strategy's audit hook, which
//     arrives with the admin API-key surface in M8 (v0.10.0). Implementing it
//     would mean choosing a partition key, a retention and a write amplification
//     for a table whose only consumer does not exist yet, and the wrong choice
//     would be a schema to migrate rather than a method to add. The item shape
//     is sketched in data-model.md §1.5; the store lands with its reader.
//
// Everything else the core declares is now implemented here. The five that this
// list used to name — UserMetadataStore, RolesPermissionsStore, TenantStore,
// APIKeyStore, TelemetryStore — landed in D6 together with the three v0.8.0
// admin listers (AdminUserStore, SessionLister, RoleLister), the four narrow
// API-key companions, and the three webhook stores. The two one-flag profile
// writers the console needs — UserAdminFlagStore and UserTwoFactorPolicyStore
// — landed with the admin surface (user_flags.go), because that is the first
// block with a route that writes either flag.
//
// The rule they were listed under still stands and is why this register is kept
// rather than deleted: a stub returning "not implemented" would be worse than an
// absent method, because the core's type assertion would then succeed and
// Service would advertise a feature that fails on the wire, where an absent
// method makes it answer ErrFeatureNotSupported and the route turn that into the
// reference's own 501.

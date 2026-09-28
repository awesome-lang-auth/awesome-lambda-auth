package dynamodb

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsddb "github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

	auth "github.com/nik2208/awesome-go-auth"
)

// The two one-flag profile writers the admin console needs and nothing else
// asks for: User.IsAdmin, behind POST <admin>/users/{id}/promote with
// method=flag, and User.Require2FA, behind PATCH <admin>/api/users/{id}/2fa-policy.
//
// Both flags have been on the profile item since the codec learned them
// (attrIsAdmin, attrRequire2FA in users.go) and both were readable long before
// this file existed; what was missing was a writer. That mattered more for the
// first than it looks. User.IsAdmin is the whole of the 'is-admin-flag' access
// policy (core admin.go, AdminPolicyIsAdminFlag), and with no writer on this
// driver the policy admitted exactly the users somebody had flagged by editing
// the table by hand — the promote route answered the reference's own 501 and
// the console could never grant itself to anyone. A policy an operator can name
// in the document but cannot satisfy through any route is the shape of silent
// misconfiguration this product refuses everywhere else, so the writer lands
// with the surface that first needs it.
//
// The core discovers both by type assertion on the user store (adminFeatures'
// twoFAWriter, and adminPromoteUser's assertion of UserAdminFlagStore), which
// is why the assertions below are load-bearing: a drifted signature would not
// fail to build, it would turn the promote route back into a 501 and switch the
// console's 2FA-policy tab off. See interfaces.go for the convention.
var (
	_ auth.UserAdminFlagStore       = (*Store)(nil)
	_ auth.UserTwoFactorPolicyStore = (*Store)(nil)
)

// UpdateIsAdmin implements auth.UserAdminFlagStore: write User.IsAdmin on one
// profile, and nothing else on it.
//
// "Nothing else" is the contract the core states for this seam and it is kept
// literally: no role is granted, no role is cleared, and the write names the
// one attribute plus updatedAt. The 'is-admin-flag' policy reads this field and
// the RBAC-backed policies read the role store, and a writer that touched both
// would be making an authorisation decision the route did not ask for.
//
// The bool is written whichever way it points, because profileItem writes it
// whichever way it points — b() has no omission rule the way s() has — so a
// false here and a false at registration decode identically, and the mechanism
// that will one day clear the flag (neither tree has a route for it yet) is one
// call with the other argument rather than a REMOVE nobody has written.
//
// It is an UpdateItem on the profile item and touches no indexed attribute, so
// it costs one write unit and no GSI write; the busiest item in the table keeps
// paying for its index exactly once, at registration (see profileItem).
func (s *Store) UpdateIsAdmin(ctx context.Context, userID, tenantID string, isAdmin bool) error {
	return s.updateProfileFlag(ctx, userID, tenantID, attrIsAdmin, isAdmin, "update admin flag")
}

// UpdateRequire2FA implements auth.UserTwoFactorPolicyStore: write
// User.Require2FA on one profile.
//
// It is the per-user half of the second-factor policy; the deployment-wide half
// is AuthSettings.Require2FA on the settings singleton (settings.go), and the
// core consults both (Auth.TwoFactorPolicy). The console's 2FA-policy tab is
// drawn only when this writer and a user lister are both present
// (adminFeatures.TwoFAPolicy), because its route walks the table and sets the
// flag on each row — so on this driver the tab appears the moment this method
// does, and disappears if the signature ever drifts.
func (s *Store) UpdateRequire2FA(ctx context.Context, userID, tenantID string, required bool) error {
	return s.updateProfileFlag(ctx, userID, tenantID, attrRequire2FA, required, "update 2fa policy")
}

// updateProfileFlag is the shared write: one BOOL attribute and updatedAt on
// an existing profile.
//
// The condition is the same one every other profile writer carries and for the
// same reason UpdateTOTPSecret spells out: UpdateItem creates a missing item, so
// without it a flag set on an id nobody registered would manufacture a
// profile-shaped item holding nothing but a boolean — and, for isAdmin, one that
// GetUserByID could never resolve but that a hand-written GSI entry could make
// look like an administrator. Refusing with ErrUserNotFound is what
// MemoryUserStore answers for the same call (memory_store.go:291-300).
func (s *Store) updateProfileFlag(ctx context.Context, userID, tenantID, attr string, value bool, op string) error {
	if err := s.checkTenant(tenantID); err != nil {
		return err
	}
	if err := checkID("user id", userID); err != nil {
		return err
	}

	_, err := s.api.UpdateItem(ctx, &awsddb.UpdateItemInput{
		TableName:                aws.String(s.table),
		Key:                      key(userPK(tenantID, userID), skProfile),
		UpdateExpression:         aws.String("SET #" + attr + " = :flag, #" + attrUpdatedAt + " = :now"),
		ConditionExpression:      aws.String("attribute_exists(#" + attrPK + ")"),
		ExpressionAttributeNames: exprNames(attrPK, attr, attrUpdatedAt),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":flag": &types.AttributeValueMemberBOOL{Value: value},
			":now":  avS(formatTime(s.nowUTC())),
		},
	})
	if err != nil {
		if isConditionFailed(err) {
			return ErrUserNotFound
		}
		return wrap(op, err)
	}
	return nil
}

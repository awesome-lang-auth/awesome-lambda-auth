package main

import (
	"fmt"
	"log/slog"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// invitations.* — staff invitations (awesome-go-auth v0.15.0; core deviation
// invitations-are-an-addition). With invitations.enabled the core is handed
// the driver's InvitationStore, and with it the four routes exist:
// POST/GET <admin>/api/users/invitations and DELETE
// <admin>/api/users/invitations/{id} behind the admin guard — so
// admin.machineAccess and the session policy decide them as they decide every
// admin route — and the public POST <prefix>/invitations/accept, which the
// adapter mounts under registration.closed too.
//
// The three other halves live where their kind already lives: the sender in
// deliveryOptions (the transport that carries the other credential mails, so
// the invitation can never travel by a different one), the reveal flag in
// adminHTTPOptions (AdminOptions.RevealInvitationToken), and the refusals in
// internal/config validateInvitations.

// invitationStoreProvider is the accessor both drivers expose: the DynamoDB
// store's Invitations() (internal/store/dynamodb/invitations.go, promoted
// through the migration wrapper, which embeds it) and the memory bundle's.
type invitationStoreProvider interface {
	Invitations() auth.InvitationStore
}

// invitationOptions is the `invitations` slot of coreOptionSets. No I/O. It
// refuses only for a driver whose store offers no invitation store, the
// guard behind the loader's own refusals.
func invitationOptions(cfg *config.Config, users auth.UserStore, log *slog.Logger) ([]auth.Option, error) {
	if !cfg.Invitations.Enabled {
		return nil, nil
	}
	provider, ok := users.(invitationStoreProvider)
	if !ok || provider.Invitations() == nil {
		return nil, fmt.Errorf(
			"config: refusing to start: invitations.enabled is on, but the %s driver does not provide an invitation store in this build, "+
				"so POST <prefix>/invitations/accept could not spend a token any other instance minted -- turn it off until the driver grows one",
			cfg.Stores.Driver)
	}
	log.Info("invitations wired",
		slog.String("store", cfg.Stores.Driver),
		slog.String("ttl", cfg.Invitations.TTL.Duration().String()),
		slog.Bool("reinvite", cfg.Invitations.Reinvite),
		slog.Bool("revealToken", cfg.Admin.RevealInvitationToken))
	return []auth.Option{
		auth.WithInvitationStore(provider.Invitations()),
		auth.WithInvitationTTL(cfg.Invitations.TTL.Duration()),
		auth.WithInvitationReinvite(cfg.Invitations.Reinvite),
	}, nil
}

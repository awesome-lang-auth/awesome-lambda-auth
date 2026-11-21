package config

import (
	"strings"
	"testing"
)

// invitationsDoc is baseDoc with the console on (the invite route's home) and
// invitations switched on; each case below then breaks exactly one thing.
func invitationsDoc() Document {
	doc := baseDoc()
	set(doc, "admin.enabled", true)
	set(doc, "admin.accessPolicy", AdminAccessPolicyIsAdmin)
	set(doc, "invitations.enabled", true)
	return doc
}

func withMailer(doc Document) {
	set(doc, "email.mailer.endpoint", "https://mail.example.com/send")
	set(doc, "email.mailer.from", "auth@example.com")
}

func withWebhook(doc Document, env map[string]string) {
	set(doc, "email.deliveryWebhook.url", "https://delivery.example.com/hook")
	env["AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_SECRET"] = strings.Repeat("w", 40)
}

func TestInvitationsOffByDefault(t *testing.T) {
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(baseEnv()), AllowUnimplemented: true})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Invitations.Enabled || cfg.Invitations.Reinvite || cfg.Admin.RevealInvitationToken {
		t.Fatalf("an invitation knob is on by default: %+v, reveal=%v", cfg.Invitations, cfg.Admin.RevealInvitationToken)
	}
	if cfg.Invitations.TTL.String() != "72h" {
		t.Fatalf("invitations.ttl defaults to %q, want 72h", cfg.Invitations.TTL.String())
	}
}

func TestInvitationsLoadFromTheEnvironment(t *testing.T) {
	env := baseEnv()
	env["AWESOME_AUTH_ADMIN_ENABLED"] = "true"
	env["AWESOME_AUTH_ADMIN_ACCESS_POLICY"] = AdminAccessPolicyIsAdmin
	env["AWESOME_AUTH_INVITATIONS_ENABLED"] = "true"
	env["AWESOME_AUTH_INVITATIONS_TTL"] = "3d"
	env["AWESOME_AUTH_INVITATIONS_REINVITE"] = "true"
	env["AWESOME_AUTH_ADMIN_REVEAL_INVITATION_TOKEN"] = "true"
	cfg, err := Load(t.Context(), Options{Document: baseDoc(), Getenv: getenvFrom(env), AllowUnimplemented: true})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Invitations.Enabled || !cfg.Invitations.Reinvite || !cfg.Admin.RevealInvitationToken || cfg.Invitations.TTL.Duration().Hours() != 72 {
		t.Fatalf("loaded %+v reveal=%v", cfg.Invitations, cfg.Admin.RevealInvitationToken)
	}
	found := false
	for _, w := range cfg.Warnings() {
		if w.Path == "admin.revealInvitationToken" && strings.Contains(w.Problem, "verified") {
			found = true
		}
	}
	if !found {
		t.Fatalf("revealInvitationToken loaded without its warning: %v", cfg.Warnings())
	}
}

func TestInvitationsRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(Document, map[string]string)
		path   string
	}{
		{"no sender and no reveal", func(Document, map[string]string) {}, "invitations.enabled"},
		{"without the console", func(doc Document, _ map[string]string) {
			withMailer(doc)
			set(doc, "admin.enabled", false)
		}, "invitations.enabled"},
		{"a ttl over 30d", func(doc Document, _ map[string]string) {
			withMailer(doc)
			set(doc, "invitations.ttl", "31d")
		}, "invitations.ttl"},
		{"reveal beside the mailer", func(doc Document, _ map[string]string) {
			withMailer(doc)
			set(doc, "admin.revealInvitationToken", true)
		}, "admin.revealInvitationToken"},
		{"reveal beside the delivery webhook", func(doc Document, env map[string]string) {
			withWebhook(doc, env)
			set(doc, "admin.revealInvitationToken", true)
		}, "admin.revealInvitationToken"},
		{"reveal with invitations off", func(doc Document, _ map[string]string) {
			set(doc, "invitations.enabled", false)
			set(doc, "admin.revealInvitationToken", true)
		}, "admin.revealInvitationToken"},
		{"reinvite with invitations off", func(doc Document, _ map[string]string) {
			set(doc, "invitations.enabled", false)
			set(doc, "invitations.reinvite", true)
		}, "invitations.reinvite"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, env := invitationsDoc(), baseEnv()
			tc.mutate(doc, env)
			_, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env), AllowUnimplemented: true})
			requireRule(t, err, "", tc.path)
		})
	}
}

func TestInvitationsAcceptedShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(Document, map[string]string)
	}{
		{"by the mailer", func(doc Document, _ map[string]string) { withMailer(doc) }},
		{"by the delivery webhook", func(doc Document, env map[string]string) { withWebhook(doc, env) }},
		{"revealed to a back office with no sender", func(doc Document, _ map[string]string) {
			set(doc, "admin.revealInvitationToken", true)
		}},
		{"a 30d ttl and reinvite", func(doc Document, _ map[string]string) {
			withMailer(doc)
			set(doc, "invitations.ttl", "30d")
			set(doc, "invitations.reinvite", true)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc, env := invitationsDoc(), baseEnv()
			tc.mutate(doc, env)
			if _, err := Load(t.Context(), Options{Document: doc, Getenv: getenvFrom(env), AllowUnimplemented: true}); err != nil {
				t.Fatalf("load: %v", err)
			}
		})
	}
}

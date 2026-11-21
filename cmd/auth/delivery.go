package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
	awsintegration "github.com/nik2208/awesome-lambda-auth/internal/integration/aws"
)

// Credential delivery: how a minted magic link, reset token, verification
// token, email-change token or SMS code leaves this deployment.
//
// awesome-go-auth (v0.4.0) exposes five senders as func types on its Config,
// each wired by a With*Sender option that rejects nil, plus a sixth for the
// notice /change-email/confirm mails to the address an account moved away
// from. This file turns three blocks of configuration into those functions,
// and nothing else in the binary knows that mail is SES, that a text message
// is SNS, or that a delivery webhook exists.
//
// ── which sender ─────────────────────────────────────────────────────────────
//
// email.deliveryWebhook.url, when set, is THE sender for the five credential
// seams: every minted credential is POSTed, signed, to that receiver and
// nothing goes through SES or SNS for those routes (decision D-11). It replaces
// the reference's five send-callback functions, which are in-process code a
// configuration document cannot express (config-schema.md §3.8), and it is what
// a deployment whose transport is neither mail nor SMS — or is not reachable
// from a Lambda — wires. The mailer and sms blocks then cover only what the
// webhook has no seam for: the email-changed notice and the OAuth link-token
// mail, both of which still go through the mailer when one is configured.
//
// Without a webhook, the mailer block selects SES for the four mail seams and
// the notice, and the sms block selects SNS for the fifth.
//
// ── transports or closures ───────────────────────────────────────────────────
//
// Upstream offers both: write five closures, or implement the two one-method
// transport interfaces (auth.MailerTransport, auth.SMSTransport) and let the
// ready-made bridges — MagicLinkMailer, PasswordResetMailer,
// EmailVerificationMailer, EmailChangeMailer, SMSTransportSender — do the rest.
// This port implements the transports, for three reasons:
//
//  1. Four of the five mail senders differ only in a template name and a URL
//     builder. Five closures would restate that mapping five times here, and
//     upstream itself factored TokenMailer out of exactly that duplication —
//     copying it back into a downstream port is how a template name or a
//     Content-Type quietly drifts from the rest of the family.
//  2. The URL shapes are upstream's to own. MagicLinkURL, PasswordResetURL,
//     EmailVerificationURL and EmailChangeConfirmURL are the links the verify
//     routes and the shipped clients expect; a closure that built them here
//     would be a second definition of a wire detail, free to diverge.
//  3. auth.MailerTransport is precisely SES's job description — put this
//     rendered message on the wire — and auth.SMSTransport is precisely SNS's.
//     Neither transport has to know what a magic link is, so neither does.
//
// The one thing a bridge cannot do is the OAuth link token, whose URL upstream
// builds itself and hands over ready-made; that one is a closure, below, and it
// still renders through the same templater.
//
// ── where a link points ──────────────────────────────────────────────────────
//
// Every bridge mailer takes a static BaseURL, but since v0.4.0 the adapters
// resolve the base per request — the request's Origin or Referer when it is
// allowlisted, else the canonical site URL — and put it on the delivery as
// LinkBase, which wins over the static base. The static one is therefore the
// fallback for a service called outside a request, and it is built from the
// same canonical site URL (siteURLs, email.go) and the same HTTPConfig.UILink
// shape the adapters use, so the two can never disagree about a link.
//
// ── what an unconfigured deployment does ─────────────────────────────────────
//
// Nothing changes, and that is deliberate rather than incidental. With no
// email.mailer block the four mail senders stay nil, so POST /magic-link/send
// answers 500 EMAIL_NOT_CONFIGURED while /forgot-password,
// /send-verification-email and /change-email/request answer 200 and mail
// nothing. With no sms block POST /sms/send answers 500 SMS_NOT_CONFIGURED.
// That split is the reference's own — its magic-link strategy checks the email
// configuration up front and throws, its three token routes check nothing and
// succeed silently (wire-contract §2, "if neither exists, no email is sent and
// the route still succeeds") — and reproducing it is the whole point of being a
// port. It is also the safer half of the two: the routes that stay silent mint
// a token that is unguessable, single-use and expiring, so an undelivered one
// costs the caller a mail that never arrives and nothing else.
//
// What this port must NOT do is invent a third behaviour, such as refusing to
// start without a mailer. A deployment serving bearer clients that never touch
// a passwordless route is legitimate, and upstream's Config.validate agrees: it
// does not ask for a sender either.
//
// ── under twoFactor.required ─────────────────────────────────────────────────
//
// Two of the five seams are not handed to the core at all: the magic link and
// the SMS code. The core counts each as a second factor wherever it can
// deliver one — availableTwoFactorMethods offers "magic-link" to every
// challenged account when Config.SendMagicLink is set, and "sms" to every one
// with a number when Config.SendSMSCode is — and the same mailbox receives the
// password-reset link, so with the seams wired a mailbox alone (reset, then the
// emailed step-up) or a phone number would answer both steps. Under the policy
// a TOTP code is the only second factor: without the two senders the challenge
// lists "totp" alone, an account with no TOTP is answered 2FA_SETUP_REQUIRED
// (and enrols, under twoFactor.enrolOnLogin) instead of being challenged for a
// link, and GET <prefix>/ui/config reports features.magicLink and features.sms
// false, so the hosted page offers neither. The four routes stay mounted and
// secondFactorGate answers them 403 2FA_REQUIRED in every mode before the core
// sees them, which also covers a link or a code minted before the policy was
// switched on. The other three seams — reset, verification, email change —
// and the email-changed notice are wired as ever: a reset changes a password
// and opens no session, so the next login still asks for TOTP — except that
// under twoFactor.enrolOnLogin an account that has not enrolled yet then
// enrols one of the resetter's choosing (trust on first use, warned).

// delivery holds the transports a cold start could build, plus everything the
// upstream mailers need to render with. A nil transport means "this deployment
// did not configure that half", and every use of it is gated on that.
type delivery struct {
	// mail is nil unless email.mailer is configured.
	mail auth.MailerTransport

	// sms is nil unless the sms block is configured.
	sms auth.SMSTransport

	// webhook is nil unless email.deliveryWebhook.url is set. When it is set it
	// is the sender for every credential seam, and mail and sms serve only the
	// two mails it has no seam for.
	webhook *auth.DeliveryWebhook

	// templates renders subject and body for the link-token closure. The four
	// bridge mailers hold their own equivalent; this one exists because
	// DeliverLinkToken has no bridge. emailOptions points its Store at the
	// template store when one is enabled, because the closure renders outside a
	// service call and cannot find the store on the context.
	templates *auth.MailTemplater

	appName string
	baseURL string
	locale  string

	// passwordlessWithheld is twoFactor.required: the magic-link and SMS-code
	// senders are not handed to the core, whatever transports exist. See the
	// file header, "under twoFactor.required".
	passwordlessWithheld bool

	// invitations is invitations.enabled: the invitation sender is handed to
	// the core only then, by the transport that carries the other credential
	// mails. Not withheld under twoFactor.required: the invitation is how a
	// closed realm's accounts are made, and accepting one opens no session
	// without the second factor the policy demands.
	invitations bool
}

// webhookConfigured is the third enable signal, and like the other two it is
// validation's own: validate.go refuses a delivery webhook url without its
// signing secret and a secret without a url, so a non-empty url is exactly "the
// operator configured a signed receiver and it passed validation". It is
// config.DeliveryWebhookConfigured, which the loader's twoFactor.required
// warning reads too.
func webhookConfigured(cfg *config.Config) bool { return cfg.DeliveryWebhookConfigured() }

// mailConfigured and smsConfigured are the enable signals, and they are the
// schema's own rather than a new knob.
//
// internal/config/validate.go refuses a mailer block that has no `from`, and
// refuses an sms block that has no `endpoint`; both are required the moment any
// key of their block is set. So a non-empty from is exactly "the operator
// configured a mailer and it passed validation", and a non-empty sms endpoint is
// exactly the same statement about SMS. Deriving the signal from validation
// instead of re-implementing "is this block non-default" means the two can never
// disagree about whether a deployment sends mail. Both are the config package's
// own predicates, which the loader's twoFactor.required warning reads too.
func mailConfigured(cfg *config.Config) bool { return cfg.MailerConfigured() }
func smsConfigured(cfg *config.Config) bool  { return cfg.SMSConfigured() }

// newDelivery builds the transports this configuration asks for.
//
// It performs no I/O: both transports defer their SDK client to the first
// message they carry (internal/integration/aws lazy.go), so a deployment that
// configures mail and never sends any pays nothing for it at init — which
// matters because startTimeout gives the whole cold start 8 seconds.
//
// A bad from address is one failure, and a delivery webhook url the core
// refuses is the other; both abort the cold start. That is the right place for
// them: an unverified or malformed sender is a deployment fault that would
// otherwise surface as a 500 on somebody's first password reset.
//
// mail, sms and client override the transports without changing the gating;
// all nil is the binary's own path.
func newDelivery(cfg *config.Config, mail auth.MailerTransport, sms auth.SMSTransport, client *http.Client, log *slog.Logger) (*delivery, error) {
	canonical, _ := siteURLs(cfg)
	d := &delivery{
		// The static fallback base, in the exact shape the adapters resolve per
		// request: the canonical site URL and the mount prefix, through
		// HTTPConfig.UILink so that ui.enabled — when it lands — moves both
		// the same way. With no canonical site the base is the bare prefix and
		// the link is relative, which is the reference's behaviour with no
		// siteUrl and is warned about below.
		baseURL: strings.TrimSuffix(httpConfig(cfg).UILink(canonical, ""), "/"),
		locale:  cfg.Email.Mailer.DefaultLang,

		passwordlessWithheld: cfg.TwoFactor.Required,
		invitations:          cfg.Invitations.Enabled,
	}

	if mailConfigured(cfg) {
		d.appName = mailerAppName(cfg)
		d.mail = mail
		if d.mail == nil {
			transport, err := awsintegration.NewSESTransport(awsintegration.SESOptions{
				From:     cfg.Email.Mailer.From,
				FromName: cfg.Email.Mailer.FromName,
			})
			if err != nil {
				return nil, err
			}
			d.mail = transport
		}
		d.templates = auth.NewMailTemplater(d.appName)
	}

	if smsConfigured(cfg) {
		d.sms = sms
		if d.sms == nil {
			d.sms = awsintegration.NewSNSTransport(awsintegration.SNSOptions{})
		}
	}

	if webhookConfigured(cfg) {
		hookURL := strings.TrimSpace(cfg.Email.DeliveryWebhook.URL)
		hook, err := auth.NewDeliveryWebhook(hookURL, cfg.SecretValue("email.deliveryWebhook.secret"))
		if err != nil {
			// Unreachable — validate.go refuses everything the core's parser
			// would — but the core's message quotes the url it rejected, and a
			// cold-start failure is written to CloudWatch like any other line.
			return nil, scrubbedWebhookError(err, hookURL)
		}
		// timeoutMs bounds one request through the request context, connect to
		// last byte; validate.go guarantees it is positive and no larger than
		// its ceiling. The route waiting on the answer is itself bounded by the
		// Lambda timeout, so this is what keeps a slow receiver from turning
		// every password reset into a function timeout.
		hook.Timeout = time.Duration(cfg.Email.DeliveryWebhook.TimeoutMs) * time.Millisecond
		hook.Client = client
		d.webhook = hook
	}

	if canonical == "" && (d.mail != nil || d.webhook != nil) {
		// Not fatal — RS-2 already decides when a missing public URL is a
		// refusal, and a stack can legitimately run without one — but a
		// relative link in a mailbox is a dead link, and upstream calls the
		// empty base a misconfiguration in both ports. Better said once here
		// than discovered from a user who could not click through.
		log.Warn("credential delivery is configured but neither email.siteUrls nor deployment.publicUrl is set, so every emailed link is relative and unusable from a mailbox",
			slog.String("path", "email.siteUrls"),
			slog.String("remedy", "set email.siteUrls to the front end the links should point at, or deployment.publicUrl to the origin clients reach"))
	}

	return d, nil
}

// mailerAppName is what the built-in templates greet the recipient with and
// prefix every subject with.
//
// email.mailer.fromName is the knob for it: it is already the human-readable
// name of the sender, and using it means the name in the From header and the
// name in the body cannot disagree. When it is unset the sender's domain stands
// in, because MailTemplater renders an empty app name as a subject beginning
// with " - " and a deployment should not have to configure a display name to
// avoid that.
func mailerAppName(cfg *config.Config) string {
	if name := strings.TrimSpace(cfg.Email.Mailer.FromName); name != "" {
		return name
	}
	if i := strings.LastIndex(cfg.Email.Mailer.From, "@"); i >= 0 && i+1 < len(cfg.Email.Mailer.From) {
		return cfg.Email.Mailer.From[i+1:]
	}
	return ""
}

// deliveryOptions returns the sender options the core accepts, appending each
// one only when something exists to send through.
//
// The gating cannot be "append a possibly-nil sender": every With*Sender option
// rejects nil with an error, so a nil transport handed to one of them would
// abort the cold start of a deployment that simply does not send mail.
//
// A delivery webhook takes all five credential seams: one value, five methods
// with the five sender signatures (auth.DeliveryWebhook), and no SES or SNS
// call is made for those routes even when the mailer or sms block is also
// configured. Those blocks still serve the email-changed notice — the webhook
// has no seam for it — and, through oauthOptions, the link-token mail.
//
// Under twoFactor.required the magic-link and SMS-code seams are left unwired
// whichever transport would have carried them (d.passwordlessWithheld; the
// file header says why), and the line below says so.
func deliveryOptions(d *delivery, log *slog.Logger) []auth.Option {
	var opts []auth.Option

	switch {
	case d.webhook != nil:
		// Every one of the five is wrapped rather than passed, and the wrapper
		// does one thing: keep the receiver's URL out of the error the core
		// logs. See scrubbedWebhookError.
		receiver := d.webhook.URL
		if !d.passwordlessWithheld {
			opts = append(opts,
				auth.WithMagicLinkSender(scrubbedSender(d.webhook.SendMagicLink, receiver)),
				auth.WithSMSCodeSender(scrubbedSender(d.webhook.SendSMSCode, receiver)),
			)
		}
		opts = append(opts,
			auth.WithPasswordResetSender(scrubbedSender(d.webhook.SendPasswordReset, receiver)),
			auth.WithEmailVerificationSender(scrubbedSender(d.webhook.SendEmailVerification, receiver)),
			auth.WithEmailChangeSender(scrubbedSender(d.webhook.SendEmailChange, receiver)),
		)
	default:
		if d.mail != nil {
			reset := auth.NewPasswordResetMailer(d.mail, d.appName, d.baseURL)
			reset.Locale = d.locale
			verify := auth.NewEmailVerificationMailer(d.mail, d.appName, d.baseURL)
			verify.Locale = d.locale
			change := auth.NewEmailChangeMailer(d.mail, d.appName, d.baseURL)
			change.Locale = d.locale

			if !d.passwordlessWithheld {
				magic := auth.NewMagicLinkMailer(d.mail, d.appName, d.baseURL)
				magic.Locale = d.locale
				opts = append(opts, auth.WithMagicLinkSender(magic.Send))
			}
			opts = append(opts,
				auth.WithPasswordResetSender(reset.Send),
				auth.WithEmailVerificationSender(verify.Send),
				auth.WithEmailChangeSender(change.Send),
			)
		}
		if d.sms != nil && !d.passwordlessWithheld {
			opts = append(opts, auth.WithSMSCodeSender(auth.SMSTransportSender(d.sms)))
		}
	}

	// The invitation (core v0.15.0), by the transport the other credential
	// mails take: the webhook posts kind "invitation", the mailer renders the
	// reference's `invitation` template with {link} — the template store's
	// override when one is enabled, found on the context as the four bridge
	// mailers find it. With neither, admin.revealInvitationToken is the only
	// delivery, which internal/config has already required.
	if d.invitations {
		switch {
		case d.webhook != nil:
			opts = append(opts, auth.WithInvitationSender(scrubbedSender(d.webhook.SendInvitation, d.webhook.URL)))
		case d.mail != nil:
			invite := auth.NewInvitationMailer(d.mail, d.appName, d.baseURL)
			invite.Locale = d.locale
			opts = append(opts, auth.WithInvitationSender(invite.Send))
		}
	}

	if d.mail != nil {
		// The notice POST /change-email/confirm mails to the OLD address once
		// the change is applied (auth.router.ts:1060-1066). It carries no
		// credential, so the webhook has nothing to sign for it and the mailer
		// is its only transport; the route passes no language, so the mailer's
		// Locale is the rule here rather than the default.
		changed := auth.NewEmailChangedMailer(d.mail, d.appName)
		changed.Locale = d.locale
		opts = append(opts, auth.WithEmailChangedSender(changed.Send))
	}

	// One line an operator can read the whole delivery posture off, including
	// the two routes that answer a coded 500 when their half is absent. The
	// transport name appears only when that half is actually on, so the line
	// cannot be misread as "mail is wired" by someone skimming for "ses".
	mailTransport, smsTransport := "none — POST /magic-link/send answers 500 EMAIL_NOT_CONFIGURED", "none — POST /sms/send answers 500 SMS_NOT_CONFIGURED"
	if d.passwordlessWithheld {
		// Neither route reaches the core under the policy, so neither answers
		// the coded 500: the gate answers both 403 2FA_REQUIRED first.
		mailTransport, smsTransport = "none", "none"
	}
	if d.mail != nil {
		mailTransport = "ses"
	}
	if d.sms != nil {
		smsTransport = "sns"
	}
	noticeTransport := "none — POST /change-email/confirm applies the change and mails no notice"
	if d.mail != nil {
		noticeTransport = "ses"
	}
	webhook := "none"
	if d.webhook != nil {
		// The webhook takes every credential seam, and the line says so in the
		// transport fields themselves: an operator who set both a mailer and a
		// webhook must not read "ses" and conclude the reset mail went by mail.
		mailTransport, smsTransport = "webhook", "webhook"
		webhook = webhookOrigin(d.webhook.URL)
	}
	attrs := []any{slog.String("mailTransport", mailTransport)}
	if d.passwordlessWithheld {
		// The texted code is the SMS half's one credential seam, so under the
		// policy that half carries no credential whatever is configured, and
		// the field must not read "sns" or "webhook". The mail half carries the
		// reset, verification and change mails, and no magic link.
		if smsTransport != "none" {
			smsTransport = "withheld — " + smsTransport + " is configured, and the texted code, its one credential seam, is not handed to the core under twoFactor.required"
		}
		attrs = append(attrs,
			slog.String("smsTransport", smsTransport),
			slog.String("magicLinkAndSMSCode", "withheld under twoFactor.required: a TOTP code is the only second factor, so no link or code is minted or sent, "+
				"the login challenge offers totp alone, and POST /magic-link/{send,verify} and /sms/{send,verify} answer 403 2FA_REQUIRED in every mode"))
	} else {
		attrs = append(attrs, slog.String("smsTransport", smsTransport))
	}
	log.Info("credential delivery wired", append(attrs,
		slog.String("emailChangedNotice", noticeTransport),
		slog.String("deliveryWebhook", webhook),
		slog.String("linkBase", d.baseURL),
		slog.String("locale", d.locale))...)

	return opts
}

// webhookOrigin is the part of the receiver's URL the cold-start log names:
// scheme and host, never the path or query, because a receiver's path is where
// an operator puts a capability token when the receiver cannot check a
// signature on its own.
func webhookOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "configured"
	}
	return u.Scheme + "://" + u.Host
}

// scrubbedWebhookError is what both webhooks' errors pass through on their way
// back into the core, and the only thing it changes is the text.
//
// The leak it closes is not the product's own logging — the cold-start line
// already names webhookOrigin and validate.go already refuses a bad url without
// quoting it (absoluteURLOrigin). It is the core's. Both webhooks wrap a
// transport failure as fmt.Errorf("%s: %w", where, err) around the *url.Error
// net/http returns, and a *url.Error renders as `Post "<the whole URL>":
// <cause>` — path and query included, as the core's own comment says. Three
// paths then write that error to a log rather than to the caller: a claims
// builder failing under Service.Me (the read does not fail closed, it logs and
// drops the claims), a delivery failing under Auth.ForgotPassword (the route
// must answer 200 whatever happened, so the log is the only report) and one
// under Auth.LinkStart. All three arrive here through Config.Logger, which
// coreOptions funnels into slog. So a receiver at
// https://gw.example.test/hook/<capability-token> would write that token to
// CloudWatch on every login for as long as it was slow or down — the exact
// value the origin-only machinery exists to keep out of there, arriving by the
// back door and at request rate rather than once.
//
// The message is rebuilt instead of re-wrapped because fmt.Errorf formats
// eagerly: by the time an error reaches this function the URL is already inside
// the text of the core's wrapper, and mutating the *url.Error underneath it
// would change nothing that is ever printed. The chain stays reachable to
// errors.Is and errors.As — the core tests a delivery failure with errors.Is,
// and sentinels have to survive — and the *url.Error's own URL field is cut
// down too, for anything that reads the field rather than the string.
func scrubbedWebhookError(err error, configured string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	// The configured value first: a redirect can land the request somewhere
	// else entirely, so the two are not necessarily the same string and both
	// have to go.
	if configured != "" {
		msg = strings.ReplaceAll(msg, configured, webhookOrigin(configured))
	}
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.URL != "" {
		origin := webhookOrigin(uerr.URL)
		msg = strings.ReplaceAll(msg, uerr.URL, origin)
		uerr.URL = origin
	}
	if msg == err.Error() {
		return err
	}
	return &scrubbedError{msg: msg, err: err}
}

// scrubbedError is an error whose text has been rewritten and whose cause is
// still reachable. Error is what a log writes; Unwrap is what errors.Is and
// errors.As walk.
type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }

// scrubbedSender wraps one of the delivery webhook's five sender methods. The
// signatures differ only in the delivery type, which is what the parameter is
// for: five hand-written wrappers would be five places for the next one to be
// forgotten.
func scrubbedSender[T any](send func(context.Context, T) error, configured string) func(context.Context, T) error {
	return func(ctx context.Context, in T) error {
		return scrubbedWebhookError(send(ctx, in), configured)
	}
}

// deliverLinkToken is the OAuth account-linking mail, POST /link-request.
//
// It is a closure rather than a bridge because upstream has no bridge for it:
// LinkTokenDelivery arrives with the URL already built — the route resolves it
// per request from the caller's Origin against the redirect allowlist, which no
// static BaseURL could reproduce — so there is nothing for a TokenMailer to
// construct.
//
// The verify-email template is the deliberate choice. The reference sends this
// mail through the same sendVerificationEmail callback its verification route
// uses (auth.router.ts:1530-1535) and has no template of its own for it, so
// reusing the verification template is what keeps the family consistent;
// inventing a link-specific one here would be a port-only divergence in
// something a user reads. A stored override of that id applies here too,
// through the templater's Store.
//
// EmailLang is honoured because upstream forwards the request's emailLang field
// verbatim for exactly this, and MailTemplater falls back to English on an
// unknown locale — the same resolution the four bridge mailers apply to a
// delivery's Lang.
func (d *delivery) deliverLinkToken(ctx context.Context, in auth.LinkTokenDelivery) error {
	locale := in.EmailLang
	if locale == "" {
		locale = d.locale
	}
	rendered, err := d.templates.RenderMail(ctx, locale, auth.TemplateVerifyEmail, auth.MailTemplateData{
		UserName: in.Email,
		Token:    in.Token,
		URL:      in.URL,
	})
	if err != nil {
		return err
	}
	return d.mail.Send(ctx, auth.MailMessage{
		To:      in.Email,
		Subject: rendered.Subject,
		Body:    rendered.HTML,
		IsHTML:  true,
		Text:    rendered.Text,
	})
}

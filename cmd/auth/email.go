package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The email flows: where an emailed link points, which template renders it, and
// where the deployment's own templates come from. Together with the delivery
// webhook in delivery.go this is the P2 block of the schema — email.siteUrls,
// email.templatesDir and email.deliveryWebhook — which internal/config/phases.go
// no longer refuses.
//
// ── site URLs ────────────────────────────────────────────────────────────────
//
// The reference builds every emailed link per request: the Origin or Referer of
// the request that asked for it, when that origin is allowlisted, else the
// canonical site URL (resolveSiteUrl, auth.router.ts:233-246). The allowlist is
// email.siteUrl merged with cors.origins (buildAllowedOrigins, :213-219) and the
// canonical site is the first siteUrl entry (getDefaultSiteUrl, :202-206). The
// core does all of that itself (Auth.ResolveSiteURL, HTTPConfig.LinkBase); this
// file only derives the two inputs from the configuration, in one place, so
// that emailed links and OAuth redirects cannot disagree about either.
//
// One product addition over the reference: with no email.siteUrls at all the
// canonical site is deployment.publicUrl rather than the empty string, because
// a relative link is dead in a mailbox and this deployment always knows the
// origin it is reached at. It is what the mailers used as their static base
// before the site-URL knob was wired, so an existing deployment keeps the links
// it had.
//
// ── template store ───────────────────────────────────────────────────────────
//
// stores.enable.templates hands the core a TemplateStore, which its ready-made
// mailers consult before the built-in templates (MailTemplater.RenderMail). The
// store is a view on the user store, obtained by structural assertion exactly as
// the two OAuth stores are (oauthStoreProvider in oauth.go): the composition root
// is the only place that knows which driver is in play, and a driver that lacks
// the view refuses to start rather than advertising a store its routes cannot
// reach.
//
// email.templatesDir seeds that store at cold start from JSON files baked into
// the artifact (scripts/build-lambda.sh TEMPLATES_DIR=…). A Lambda has no
// writable filesystem and no deploy step that runs code, so cold start is the
// only moment the directory can be read; and a runtime edit through the store
// must survive the next cold start, so the directory never overwrites: a file
// whose id the store already holds is skipped. That precedence is registered
// as the product deviation templates-dir-only-seeds-absent-ids (deviations.go).

// siteURLs derives the canonical site URL and the origin allowlist the email
// flows and the OAuth redirects share.
//
// canonical is the first email.siteUrls entry, else deployment.publicUrl, with
// one trailing slash removed so that the prefix concatenates cleanly. allowlist
// is email.siteUrls followed by http.cors.origins, deduplicated with the first
// occurrence's position kept — the reference's [...new Set([...siteUrls,
// ...corsOrigins])] (auth.router.ts:213-219). Entries are kept exactly as
// written, because the core matches a request's Origin against them with an
// exact comparison, as the reference's includes does.
func siteURLs(cfg *config.Config) (canonical string, allowlist []string) {
	// The merge itself lives in internal/config, because RS-11 has to ask the
	// same question at validation time: a configured OAuth provider with an
	// empty allowlist is refused, and it would be refused against a different
	// list if this file kept its own copy of the rule.
	allowlist = cfg.RedirectOrigins()
	for _, u := range cfg.Email.SiteURLs {
		if u != "" {
			canonical = u
			break
		}
	}
	if canonical == "" {
		canonical = strings.TrimSpace(cfg.Deployment.PublicURL)
	}
	return strings.TrimSuffix(canonical, "/"), allowlist
}

// templateStoreProvider is what this binary needs from a store to back
// stores.enable.templates: a TemplateStore view, handed to the core through
// auth.WithTemplateStore. A structural assertion on the user store rather than
// a wider StoreFactory signature, for the reasons oauthStoreProvider gives.
type templateStoreProvider interface {
	Templates() auth.TemplateStore
}

// emailOptions wires the site-URL allowlist and the template store, seeding the
// latter from email.templatesDir when one is named.
//
// It is appended after deliveryOptions and before oauthOptions in New. The
// enable signals are derived, never a new knob: a non-empty allowlist, and
// stores.enable.templates — the schema's own switch for "this feature has a
// store". A directory that cannot be read is a cold-start failure in
// production, where the artifact is supposed to contain what the document
// names, and a warning in development, where a stack is allowed to come up
// without its templates and render the built-ins.
//
// The allowlist is handed to the core only when a canonical site exists, and
// that condition is load-bearing rather than tidiness. The core derives its
// default site URL from OAuthWiring.SiteURL — which oauthOptions sets to the
// same canonical — and falls back to Config.SiteURLs[0] when that is empty
// (defaultSiteURL, wire.go). With no email.siteUrls and no deployment.publicUrl
// the merged allowlist is exactly http.cors.origins, so passing it would make a
// CORS origin the site every emailed link is built on, which is neither what the
// operator wrote nor what the reference does: getDefaultSiteUrl reads
// email.siteUrl alone (auth.router.ts:202-206) and returns nothing when it is
// empty. Skipping the option costs no allowlisting — the same merged list
// reaches the core through OAuthWiring.AllowedOrigins, which is the other half
// of dedupeOrigins — so a request's Origin is still honoured, while the default
// stays empty and newDelivery's warning about relative links stays true.
func emailOptions(ctx context.Context, cfg *config.Config, users auth.UserStore, deliver *delivery, log *slog.Logger) ([]auth.Option, error) {
	var opts []auth.Option

	canonical, allowlist := siteURLs(cfg)
	if canonical != "" && len(allowlist) > 0 {
		opts = append(opts, auth.WithSiteURLs(allowlist...))
	}

	templateStore := "none — the built-in en/it templates render"
	seed := templateSeed{}
	if cfg.Stores.Enable.Templates {
		provider, ok := users.(templateStoreProvider)
		if !ok || provider.Templates() == nil {
			return nil, fmt.Errorf(
				"config: refusing to start: stores.enable.templates is on, but the %s driver does not provide a template store in this build, so every stored template would be unreachable -- turn it off until the driver grows one",
				cfg.Stores.Driver)
		}
		store := provider.Templates()
		templateStore = cfg.Stores.Driver

		if dir := strings.TrimSpace(cfg.Email.TemplatesDir); dir != "" {
			var err error
			seed, err = seedTemplateDir(ctx, dir, store)
			if err != nil {
				if cfg.IsProduction() {
					return nil, err
				}
				// A development stack may come up without its templates; the
				// built-ins render and the operator is told why. In production
				// the artifact is supposed to contain what the document names.
				log.Warn("email.templatesDir could not be seeded; the built-in templates render until it is fixed",
					slog.String("path", "email.templatesDir"),
					slog.String("error", err.Error()))
			}
			for _, id := range seed.mailSeeded {
				if !referenceTemplateIDs[id] {
					log.Warn("seeded a mail template no route renders",
						slog.String("path", "email.templatesDir"),
						slog.String("id", id),
						slog.String("remedy", "the mail routes ask the store for "+strings.Join(sortedReferenceTemplateIDs(), ", ")+
							"; a stored template under any other id -- the deprecated reset_password, magic_link, verify_email and email_change included -- is never rendered"))
				}
			}
		}

		// The link-token closure renders outside a service call, so the store the
		// service puts on the context never reaches its templater; it is given the
		// store directly. The four bridge mailers find it on the context.
		if deliver != nil && deliver.templates != nil {
			deliver.templates.Store = store
		}
		opts = append(opts, auth.WithTemplateStore(store))
	}

	// The two forgot-password and mail-language knobs of core v0.16.0, passed
	// whatever their value: an empty language list and a zero floor are the
	// core's own off, so the mapping is total and a default document builds
	// the core it always built. Neither can refuse here — the loader has
	// already refused every entry that is not a language tag and every floor
	// outside 0..MaxForgotPasswordMinResponseMs, which are within what the
	// core accepts (TestTheLoaderAcceptsOnlyWhatTheCoreAccepts).
	floor := time.Duration(cfg.Security.ForgotPassword.MinResponseMs) * time.Millisecond
	opts = append(opts,
		// email.languages: the languages a request's emailLang may select.
		auth.WithEmailLangs(cfg.Email.Languages...),
		// security.forgotPassword.minResponseMs: the floor every answer of
		// POST <prefix>/forgot-password is held to.
		auth.WithForgotPasswordMinResponseTime(floor),
	)

	languages := "as sent (email.languages unset)"
	if len(cfg.Email.Languages) > 0 {
		languages = strings.Join(cfg.Email.Languages, ",")
	}
	log.Info("email flows wired",
		slog.String("canonicalSiteUrl", canonical),
		slog.Int("allowedOrigins", len(allowlist)),
		slog.String("templateStore", templateStore),
		slog.String("templatesDir", cfg.Email.TemplatesDir),
		slog.Int("mailTemplatesSeeded", len(seed.mailSeeded)),
		slog.Int("mailTemplatesKept", len(seed.mailKept)),
		slog.Int("uiTranslationsSeeded", len(seed.uiSeeded)),
		slog.Int("uiTranslationsKept", len(seed.uiKept)),
		slog.String("emailLanguages", languages),
		slog.Duration("forgotPasswordMinResponseTime", floor))

	return opts, nil
}

// referenceTemplateIDs are the six ids the core's mailers ask a store for.
// Anything else can be stored, and is rendered by nothing in this binary.
var referenceTemplateIDs = map[string]bool{
	auth.TemplatePasswordReset: true,
	auth.TemplateMagicLink:     true,
	auth.TemplateWelcome:       true,
	auth.TemplateVerifyEmail:   true,
	auth.TemplateEmailChanged:  true,
	auth.TemplateInvitation:    true,
}

func sortedReferenceTemplateIDs() []string {
	ids := make([]string, 0, len(referenceTemplateIDs))
	for id := range referenceTemplateIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// templateSeed reports what seeding did, by id: seeded is what the directory
// wrote because the store had no entry, kept is what the store already held and
// the directory therefore left alone.
type templateSeed struct {
	mailSeeded, mailKept []string
	uiSeeded, uiKept     []string
}

// seedTemplateDir reads a directory on disk and seeds the store from it. The
// directory has to exist and be a directory; both failures name the path and
// nothing else, since the error is logged.
func seedTemplateDir(ctx context.Context, dir string, store auth.TemplateStore) (templateSeed, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return templateSeed{}, fmt.Errorf("email.templatesDir: %w", err)
	}
	if !info.IsDir() {
		return templateSeed{}, fmt.Errorf("email.templatesDir: %s is not a directory", dir)
	}
	return seedTemplates(ctx, os.DirFS(dir), store)
}

// maxSeedFileBytes caps one file in email.templatesDir.
//
// A mail template is a subject and two bodies in a handful of languages —
// kilobytes — and the whole directory is read into a Lambda with a fixed memory
// limit inside the 8 second startTimeout. The directory is artifact-baked, so
// the input is the operator's rather than an attacker's; the failure this
// guards against is a mistake, not an attack, and the point of the cap is that
// a file somebody copied the wrong thing into is refused by name instead of
// turning into an init failure with nothing to read.
const maxSeedFileBytes = 256 << 10

// pendingMailTemplate and pendingUITranslation are one validated seed file each,
// decoded in the first pass and written in the second.
type pendingMailTemplate struct {
	name string // the file, for diagnostics
	id   string
	tpl  auth.MailTemplate
}

type pendingUITranslation struct {
	name string
	page string
	ui   auth.UITranslation
}

// seedTemplates writes every template in fsys that the store does not already
// hold.
//
// The layout is one file per template at the top level of the directory,
// nothing recursive: <id>.json is a mail template in the reference's JSON shape
// ({id, baseHtml, baseText, translations}, template-store.interface.ts:1-6)
// and <page>.ui.json is the translation set of one UI page ({page,
// translations}). Anything that is not a .json file is ignored, so a README can
// sit beside them. An id may be repeated inside the file; when it is, it has to
// agree with the file name, because two names for one template is exactly the
// kind of ambiguity a seed must not resolve silently.
//
// The store is consulted first for every id and wins when it has one: a
// template edited at runtime is never overwritten by a redeploy. The check and
// the write are two calls rather than one conditional write, because the
// TemplateStore interface has no create-if-absent; the window is a cold start
// racing an operator's edit of the same template, and the cost of losing it is
// one edit made during a deployment.
//
// A file whose template the core would ignore — a mail template with an empty
// baseHtml or baseText, which MailTemplater.RenderMail skips in favour of the
// built-in — is refused rather than stored: a seed that is silently inert is
// the failure mode this whole binary is arranged against.
//
// Two passes, and the split is what makes a refusal safe to act on. Because the
// store wins forever afterwards, a run that validated file 1, wrote it, and then
// refused file 2 would have pinned file 1's contents permanently: the corrected
// version of that same id is never applied, on this or any later cold start,
// because by then the store holds one. So nothing is written until the whole
// directory validates, and — following the config layer's convention of running
// every check to completion — the refusal names every bad file at once rather
// than making an operator fix them one redeploy at a time. The second pass can
// still stop half way, but only on a store failure, which is an outage rather
// than a document to correct.
func seedTemplates(ctx context.Context, fsys fs.FS, store auth.TemplateStore) (templateSeed, error) {
	var seed templateSeed

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return seed, fmt.Errorf("email.templatesDir: %w", err)
	}

	var (
		mails    []pendingMailTemplate
		pages    []pendingUITranslation
		problems []error
	)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || strings.HasPrefix(name, ".") || !strings.HasSuffix(name, ".json") {
			continue
		}
		raw, err := readSeedFile(fsys, name)
		if err != nil {
			problems = append(problems, err)
			continue
		}

		if page, ok := strings.CutSuffix(name, ".ui.json"); ok {
			pending, err := decodeUITranslation(name, page, raw)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			pages = append(pages, pending)
			continue
		}

		pending, err := decodeMailTemplate(name, strings.TrimSuffix(name, ".json"), raw)
		if err != nil {
			problems = append(problems, err)
			continue
		}
		mails = append(mails, pending)
	}
	if len(problems) > 0 {
		return seed, errors.Join(problems...)
	}

	for _, pending := range mails {
		kept, err := seedMailTemplate(ctx, store, pending)
		if err != nil {
			return seed, err
		}
		if kept {
			seed.mailKept = append(seed.mailKept, pending.id)
		} else {
			seed.mailSeeded = append(seed.mailSeeded, pending.id)
		}
	}
	for _, pending := range pages {
		kept, err := seedUITranslations(ctx, store, pending)
		if err != nil {
			return seed, err
		}
		if kept {
			seed.uiKept = append(seed.uiKept, pending.page)
		} else {
			seed.uiSeeded = append(seed.uiSeeded, pending.page)
		}
	}
	return seed, nil
}

// readSeedFile reads one seed file, bounded by maxSeedFileBytes. The read is
// one byte over the cap so that "exactly at the cap" and "too large" are
// distinguishable without stat'ing the file, which an fs.FS need not support
// consistently.
func readSeedFile(fsys fs.FS, name string) ([]byte, error) {
	f, err := fsys.Open(name)
	if err != nil {
		return nil, fmt.Errorf("email.templatesDir: %s: %w", name, err)
	}
	defer f.Close()

	raw, err := io.ReadAll(io.LimitReader(f, maxSeedFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("email.templatesDir: %s: %w", name, err)
	}
	if len(raw) > maxSeedFileBytes {
		return nil, fmt.Errorf(
			"email.templatesDir: %s: the file is larger than the %d KiB a seed file may be, and a mail template is a subject and two bodies; this is not a template, and reading it would cost the cold start its whole memory budget",
			name, maxSeedFileBytes>>10)
	}
	return raw, nil
}

// decodeSeed decodes one seed file strictly: an unknown key is a typo in a file
// nobody will look at again, so it is reported now.
func decodeSeed(name string, raw []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(into); err != nil {
		return fmt.Errorf("email.templatesDir: %s: %w", name, err)
	}
	if dec.More() {
		return fmt.Errorf("email.templatesDir: %s: trailing data after the JSON document", name)
	}
	return nil
}

// decodeMailTemplate is the first pass over one <id>.json: everything that can
// be decided from the file alone, and nothing that touches the store.
func decodeMailTemplate(name, id string, raw []byte) (pendingMailTemplate, error) {
	var tpl auth.MailTemplate
	if err := decodeSeed(name, raw, &tpl); err != nil {
		return pendingMailTemplate{}, err
	}
	if id == "" {
		return pendingMailTemplate{}, fmt.Errorf("email.templatesDir: %s: the file name carries no template id", name)
	}
	if tpl.ID != "" && tpl.ID != id {
		return pendingMailTemplate{}, fmt.Errorf("email.templatesDir: %s: the id field says %q but the file name says %q; make them agree or drop the field", name, tpl.ID, id)
	}
	if tpl.BaseHTML == "" || tpl.BaseText == "" {
		return pendingMailTemplate{}, fmt.Errorf("email.templatesDir: %s: baseHtml and baseText must both be non-empty, or the core keeps rendering the built-in template and the seed does nothing", name)
	}
	return pendingMailTemplate{name: name, id: id, tpl: tpl}, nil
}

// seedMailTemplate is the second pass: the store's own copy wins, and only an
// absent id is written.
func seedMailTemplate(ctx context.Context, store auth.TemplateStore, pending pendingMailTemplate) (kept bool, err error) {
	if _, found, err := store.GetMailTemplate(ctx, pending.id); err != nil {
		return false, fmt.Errorf("email.templatesDir: %s: template store: %w", pending.name, err)
	} else if found {
		return true, nil
	}
	if _, err := store.UpdateMailTemplate(ctx, pending.id, auth.MailTemplatePatch{
		BaseHTML:     &pending.tpl.BaseHTML,
		BaseText:     &pending.tpl.BaseText,
		Translations: pending.tpl.Translations,
	}); err != nil {
		return false, fmt.Errorf("email.templatesDir: %s: template store: %w", pending.name, err)
	}
	return false, nil
}

// decodeUITranslation is decodeMailTemplate for one <page>.ui.json.
func decodeUITranslation(name, page string, raw []byte) (pendingUITranslation, error) {
	var ui auth.UITranslation
	if err := decodeSeed(name, raw, &ui); err != nil {
		return pendingUITranslation{}, err
	}
	if page == "" {
		return pendingUITranslation{}, fmt.Errorf("email.templatesDir: %s: the file name carries no page", name)
	}
	if ui.Page != "" && ui.Page != page {
		return pendingUITranslation{}, fmt.Errorf("email.templatesDir: %s: the page field says %q but the file name says %q; make them agree or drop the field", name, ui.Page, page)
	}
	if len(ui.Translations) == 0 {
		return pendingUITranslation{}, fmt.Errorf("email.templatesDir: %s: translations is empty, so the seed would store nothing", name)
	}
	return pendingUITranslation{name: name, page: page, ui: ui}, nil
}

func seedUITranslations(ctx context.Context, store auth.TemplateStore, pending pendingUITranslation) (kept bool, err error) {
	if _, found, err := store.GetUITranslations(ctx, pending.page); err != nil {
		return false, fmt.Errorf("email.templatesDir: %s: template store: %w", pending.name, err)
	} else if found {
		return true, nil
	}
	if _, err := store.UpdateUITranslations(ctx, pending.page, pending.ui.Translations); err != nil {
		return false, fmt.Errorf("email.templatesDir: %s: template store: %w", pending.name, err)
	}
	return false, nil
}

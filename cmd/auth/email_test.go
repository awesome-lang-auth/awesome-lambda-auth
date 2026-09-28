package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// The email-flow tests: where an emailed link points, which template renders
// it, and where a credential goes when the deployment posts it instead of
// mailing it. Like the delivery tests they drive the real HTTP surface, because
// the interesting claims are all per-request — the link base is resolved from
// the request's Origin, and the template store is reached through the context
// the service builds — and none of them is observable from the option set.

const (
	// The front ends a deployment serves. testSiteURL is canonical (first
	// entry), testAltSiteURL is the second allowlisted one, testCORSOrigin is
	// allowlisted through http.cors.origins alone, and testEvilOrigin is
	// allowlisted by nobody.
	testSiteURL    = "https://app.example.test"
	testAltSiteURL = "https://alt.example.test"
	testCORSOrigin = "https://console.example.test"
	testEvilOrigin = "https://evil.example.test"
)

// loadTestConfig loads a configuration from an environment map alone, which is
// what most of this file needs: a *config.Config to hand a unit under test.
func loadTestConfig(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// storeFactory returns a StoreFactory handing out exactly these stores, for the
// tests that keep a handle on what the app was built over.
func storeFactory(users auth.UserStore, sessions auth.SessionStore) StoreFactory {
	return func(context.Context, *config.Config, *slog.Logger) (auth.UserStore, auth.SessionStore, error) {
		return users, sessions, nil
	}
}

// TestSiteURLsMergesTheAllowlistAndPicksTheCanonicalSite pins siteURLs, which is
// the single derivation every emailed link and every OAuth redirect resolves
// against. The allowlist is the reference's buildAllowedOrigins
// (auth.router.ts:213-219) — email.siteUrls then http.cors.origins, each origin
// kept where it first appeared — and the canonical site is the first
// email.siteUrls entry (getDefaultSiteUrl, :202-206) with deployment.publicUrl
// as this port's fallback.
func TestSiteURLsMergesTheAllowlistAndPicksTheCanonicalSite(t *testing.T) {
	t.Parallel()

	// baseEnv's deployment.publicUrl: the fallback canonical site.
	const publicURL = "https://auth.example.test"

	cases := []struct {
		name          string
		site, cors    string
		wantCanonical string
		wantAllowlist []string
	}{
		{
			name:          "neither: the deployment's own origin is canonical and nothing is allowlisted",
			wantCanonical: publicURL,
		},
		{
			name:          "site urls alone: the first is canonical, all are allowlisted",
			site:          testSiteURL + "," + testAltSiteURL,
			wantCanonical: testSiteURL,
			wantAllowlist: []string{testSiteURL, testAltSiteURL},
		},
		{
			name:          "a cors origin is allowlisted but never canonical",
			cors:          testCORSOrigin,
			wantCanonical: publicURL,
			wantAllowlist: []string{testCORSOrigin},
		},
		{
			name:          "both: site urls first, cors origins after",
			site:          testSiteURL,
			cors:          testCORSOrigin,
			wantCanonical: testSiteURL,
			wantAllowlist: []string{testSiteURL, testCORSOrigin},
		},
		{
			name:          "an origin in both lists is kept once, where it first appeared",
			site:          testAltSiteURL + "," + testSiteURL,
			cors:          testSiteURL + "," + testCORSOrigin,
			wantCanonical: testAltSiteURL,
			wantAllowlist: []string{testAltSiteURL, testSiteURL, testCORSOrigin},
		},
		{
			// The canonical site is concatenated with the api prefix, so a
			// trailing slash there would produce a double slash in every link.
			// An allowlist entry is compared, never concatenated, so it is kept
			// exactly as the operator wrote it — the reference's `includes`.
			name:          "a trailing slash is trimmed from the canonical site only",
			site:          testSiteURL + "/",
			wantCanonical: testSiteURL,
			wantAllowlist: []string{testSiteURL + "/"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := baseEnv()
			if tc.site != "" {
				env["AWESOME_AUTH_EMAIL_SITE_URLS"] = tc.site
			}
			if tc.cors != "" {
				env["AWESOME_AUTH_CORS_ORIGINS"] = tc.cors
			}

			canonical, allowlist := siteURLs(loadTestConfig(t, env))
			if canonical != tc.wantCanonical {
				t.Errorf("canonical = %q, want %q", canonical, tc.wantCanonical)
			}
			if strings.Join(allowlist, ",") != strings.Join(tc.wantAllowlist, ",") {
				t.Errorf("allowlist = %v, want %v", allowlist, tc.wantAllowlist)
			}
		})
	}
}

// TestEmailedLinksUseTheResolvedSiteURL is the same derivation seen from a
// mailbox: the link in the mail is built under the origin the request came
// from when that origin is allowlisted, and under the canonical site otherwise.
//
// The last case is the one that matters for security. A password-reset link is
// a credential; if any Origin a caller cared to send steered where it points,
// anyone could have a victim's reset link built against a host they control and
// wait for the click.
func TestEmailedLinksUseTheResolvedSiteURL(t *testing.T) {
	t.Parallel()

	d := newDeliveryApp(t, with(mailerEnv(baseEnv()),
		"AWESOME_AUTH_EMAIL_SITE_URLS", testSiteURL+","+testAltSiteURL,
		"AWESOME_AUTH_CORS_ORIGINS", testCORSOrigin))
	const owner = "sited@example.test"
	d.register(t, owner)

	cases := []struct {
		name, origin, wantBase string
	}{
		{"no origin at all: the canonical site", "", testSiteURL},
		{"an allowlisted site url", testAltSiteURL, testAltSiteURL},
		{"an origin allowlisted through http.cors.origins", testCORSOrigin, testCORSOrigin},
		{"an origin nobody allowlisted falls back to the canonical site", testEvilOrigin, testSiteURL},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d.mail.reset()
			headers := jsonHeaders()
			if tc.origin != "" {
				headers["origin"] = tc.origin
			}
			resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", headers, nil,
				fmt.Sprintf(`{"email":%q}`, owner))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("forgot-password status = %d (body %s)", resp.StatusCode, resp.Body)
			}
			assertRenderedMail(t, d.mail.only(t), subjectPasswordResetEN,
				tc.wantBase+"/auth"+auth.PasswordResetPath)
		})
	}
}

// TestACORSOriginNeverBecomesTheCanonicalSite is the corner where handing the
// merged allowlist to the core would change what a link is built on.
//
// The core's default site URL is OAuthWiring.SiteURL, and when that is empty it
// falls through to Config.SiteURLs[0] (defaultSiteURL, wire.go). This port
// merges http.cors.origins into the list it passes to auth.WithSiteURLs, so
// with neither email.siteUrls nor deployment.publicUrl set — the one case where
// the canonical site is empty — the first CORS origin would silently become the
// site every emailed link is built on. That is not what the operator wrote, and
// it is not the reference either: getDefaultSiteUrl reads email.siteUrl alone
// (auth.router.ts:202-206) and is empty when it is unset. emailOptions
// therefore skips the option entirely when there is no canonical site.
//
// Both halves are asserted, because skipping the option must not cost the
// allowlist: the same merged list still reaches the core through
// OAuthWiring.AllowedOrigins, so an allowlisted Origin is still honoured per
// request. Only the fallback changes, and it becomes the relative link
// newDelivery already warns about rather than a host nobody nominated.
func TestACORSOriginNeverBecomesTheCanonicalSite(t *testing.T) {
	t.Parallel()

	env := mailerEnv(baseEnv(),
		"AWESOME_AUTH_CORS_ORIGINS", testCORSOrigin,
		// RS-2 wants a public URL whenever cookie delivery is active; this is
		// the dev-stage escape it names, and it is what makes "no canonical
		// site at all" a loadable document to test.
		"AWESOME_AUTH_COOKIES_ALLOW_INSECURE_COOKIE_MODE", "true")
	delete(env, "AWESOME_AUTH_DEPLOYMENT_PUBLIC_URL")

	if canonical, allowlist := siteURLs(loadTestConfig(t, env)); canonical != "" || len(allowlist) != 1 {
		t.Fatalf("canonical = %q, allowlist = %v; the premise of this test is a CORS-only allowlist with no canonical site", canonical, allowlist)
	}

	d := newDeliveryApp(t, env)
	const owner = "corsless@example.test"
	d.register(t, owner)

	t.Run("no origin: the link is relative, not built on the cors origin", func(t *testing.T) {
		d.mail.reset()
		resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", jsonHeaders(), nil,
			fmt.Sprintf(`{"email":%q}`, owner))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("forgot-password status = %d (body %s)", resp.StatusCode, resp.Body)
		}
		link := linkIn(t, d.mail.only(t).Body)
		if strings.HasPrefix(link, testCORSOrigin) {
			t.Errorf("the emailed link is built on the cors origin nobody nominated as a site: %s", link)
		}
	})

	t.Run("an allowlisted origin is still honoured", func(t *testing.T) {
		d.mail.reset()
		headers := jsonHeaders()
		headers["origin"] = testCORSOrigin
		resp := invoke(t, d.app, http.MethodPost, "/auth/forgot-password", headers, nil,
			fmt.Sprintf(`{"email":%q}`, owner))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("forgot-password status = %d (body %s)", resp.StatusCode, resp.Body)
		}
		assertRenderedMail(t, d.mail.only(t), subjectPasswordResetEN,
			testCORSOrigin+"/auth"+auth.PasswordResetPath)
	})
}

// writeTemplateFiles writes files into a fresh directory and returns its path.
func writeTemplateFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

// templatesDirDoc is the configuration document that names a templates
// directory. email.templatesDir is file-only by design — a directory baked into
// the artifact is not something an environment variable should be able to move
// (config-schema.md §1.5) — so this is the only way to set it.
func templatesDirDoc(dir string) string {
	return fmt.Sprintf(`{"schemaVersion": 1, "email": {"templatesDir": %q}}`, dir)
}

// seedFile is one mail template as email.templatesDir holds it: the reference's
// JSON shape, with the two stored placeholder forms in the bodies.
func seedFile(marker string) string {
	return fmt.Sprintf(`{
  "baseHtml": "<p>%s {{T.intro}} <a href=\"{{link}}\">{{link}}</a></p>",
  "baseText": "%s {{T.intro}} {{link}}",
  "translations": {"en": {"subject": "%s subject", "intro": "please click"}}
}`, marker, marker, marker)
}

// TestTemplatesDirSeedsOnlyAbsentIds is the precedence the product deviation
// templates-dir-only-seeds-absent-ids records: the directory is a seed, not a
// source of truth. An id the store already holds is left exactly as it is, on
// this and on every later cold start, because the store is where a runtime edit
// through the admin API lands and a redeploy must not undo it.
func TestTemplatesDirSeedsOnlyAbsentIds(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	store := auth.NewMemoryTemplateStore()
	html, text := "<p>EDITED AT RUNTIME {{link}}</p>", "EDITED AT RUNTIME {{link}}"
	if _, err := store.UpdateMailTemplate(ctx, auth.TemplateVerifyEmail, auth.MailTemplatePatch{
		BaseHTML: &html, BaseText: &text,
	}); err != nil {
		t.Fatalf("UpdateMailTemplate: %v", err)
	}
	if _, err := store.UpdateUITranslations(ctx, "login", map[string]map[string]string{
		"en": {"title": "EDITED AT RUNTIME"},
	}); err != nil {
		t.Fatalf("UpdateUITranslations: %v", err)
	}

	dir := writeTemplateFiles(t, map[string]string{
		auth.TemplateVerifyEmail + ".json":   seedFile("FROM THE DIRECTORY"),
		auth.TemplatePasswordReset + ".json": seedFile("FROM THE DIRECTORY"),
		"login.ui.json":                      `{"translations": {"en": {"title": "FROM THE DIRECTORY"}}}`,
		"signup.ui.json":                     `{"translations": {"en": {"title": "FROM THE DIRECTORY"}}}`,
		// Not a template, and not an error either: a directory an operator
		// maintains by hand has a note in it.
		"README.md": "these are the shipped templates",
	})

	seed, err := seedTemplateDir(ctx, dir, store)
	if err != nil {
		t.Fatalf("seedTemplateDir: %v", err)
	}
	if got := strings.Join(seed.mailSeeded, ","); got != auth.TemplatePasswordReset {
		t.Errorf("mail templates seeded = %v, want only %q", seed.mailSeeded, auth.TemplatePasswordReset)
	}
	if got := strings.Join(seed.mailKept, ","); got != auth.TemplateVerifyEmail {
		t.Errorf("mail templates kept = %v, want only %q", seed.mailKept, auth.TemplateVerifyEmail)
	}
	if got := strings.Join(seed.uiSeeded, ","); got != "signup" {
		t.Errorf("ui pages seeded = %v, want only signup", seed.uiSeeded)
	}
	if got := strings.Join(seed.uiKept, ","); got != "login" {
		t.Errorf("ui pages kept = %v, want only login", seed.uiKept)
	}

	kept, _, err := store.GetMailTemplate(ctx, auth.TemplateVerifyEmail)
	if err != nil {
		t.Fatalf("GetMailTemplate: %v", err)
	}
	if !strings.Contains(kept.BaseHTML, "EDITED AT RUNTIME") {
		t.Errorf("the directory overwrote a template the store already held:\n%s", kept.BaseHTML)
	}
	seeded, found, err := store.GetMailTemplate(ctx, auth.TemplatePasswordReset)
	if err != nil || !found {
		t.Fatalf("GetMailTemplate(%s) found = %v, err = %v", auth.TemplatePasswordReset, found, err)
	}
	if !strings.Contains(seeded.BaseHTML, "FROM THE DIRECTORY") || seeded.Translations["en"]["subject"] == "" {
		t.Errorf("the absent id was not seeded from the directory: %+v", seeded)
	}
	page, found, err := store.GetUITranslations(ctx, "signup")
	if err != nil || !found {
		t.Fatalf("GetUITranslations(signup) found = %v, err = %v", found, err)
	}
	if page.Translations["en"]["title"] != "FROM THE DIRECTORY" {
		t.Errorf("the absent ui page was not seeded: %+v", page)
	}

	// Seeding again is what the next cold start does, and it must be a no-op
	// over everything the first run wrote.
	again, err := seedTemplateDir(ctx, dir, store)
	if err != nil {
		t.Fatalf("second seedTemplateDir: %v", err)
	}
	if len(again.mailSeeded) != 0 || len(again.uiSeeded) != 0 {
		t.Errorf("a second cold start rewrote %v and %v", again.mailSeeded, again.uiSeeded)
	}
}

// TestTemplatesDirRefusesAFileThatWouldBeInert: a seed file the core would
// ignore, or one whose name and contents disagree about what it is, fails the
// cold start instead of being stored and never rendered. A seed that silently
// does nothing is the failure mode this binary is arranged against.
func TestTemplatesDirRefusesAFileThatWouldBeInert(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, file, content, wantIn string
	}{
		{
			name:    "an empty text body, which MailTemplater skips in favour of the built-in",
			file:    auth.TemplateMagicLink + ".json",
			content: `{"baseHtml": "<p>{{link}}</p>", "baseText": ""}`,
			wantIn:  "baseHtml and baseText",
		},
		{
			name:    "an id that disagrees with the file name",
			file:    auth.TemplateMagicLink + ".json",
			content: `{"id": "password-reset", "baseHtml": "<p>x</p>", "baseText": "x"}`,
			wantIn:  "make them agree",
		},
		{
			name:    "a page that disagrees with the file name",
			file:    "login.ui.json",
			content: `{"page": "signup", "translations": {"en": {"title": "x"}}}`,
			wantIn:  "make them agree",
		},
		{
			name:    "ui translations that would store nothing",
			file:    "login.ui.json",
			content: `{"translations": {}}`,
			wantIn:  "translations is empty",
		},
		{
			name:    "a key nobody reads, which is a typo in a file nobody looks at again",
			file:    auth.TemplateMagicLink + ".json",
			content: `{"subject": "Hello", "baseHtml": "<p>x</p>", "baseText": "x"}`,
			wantIn:  "unknown field",
		},
		{
			name:    "a document that does not parse",
			file:    auth.TemplateMagicLink + ".json",
			content: `{"baseHtml": }`,
			wantIn:  auth.TemplateMagicLink + ".json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := writeTemplateFiles(t, map[string]string{tc.file: tc.content})
			_, err := seedTemplateDir(context.Background(), dir, auth.NewMemoryTemplateStore())
			if err == nil {
				t.Fatalf("the file was accepted, so a seed that renders nothing would ship silently")
			}
			if !strings.Contains(err.Error(), "email.templatesDir") {
				t.Errorf("the error does not name the knob that owns the file:\n%v", err)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("error = %v, want it to mention %q", err, tc.wantIn)
			}
		})
	}
}

// TestTemplatesDirValidatesEverythingBeforeWritingAnything is why seedTemplates
// has two passes, and it is a correctness claim rather than a tidiness one.
//
// The store wins over the directory forever afterwards. So a run that wrote the
// good file and then refused the bad one would have pinned that first template
// permanently: the id is now present, every later cold start skips it, and a
// corrected version of that same file is never applied — on a Lambda, where the
// only moment the directory can be read is a cold start, there is no second
// chance and no way to notice. Refusing before any write keeps a failed deploy
// a deploy that changed nothing.
//
// The second claim is the config layer's convention: every check runs to
// completion, so one redeploy tells the operator about every bad file rather
// than one of them.
func TestTemplatesDirValidatesEverythingBeforeWritingAnything(t *testing.T) {
	t.Parallel()

	dir := writeTemplateFiles(t, map[string]string{
		auth.TemplateMagicLink + ".json":     seedFile("PERFECTLY GOOD"),
		auth.TemplatePasswordReset + ".json": `{"baseHtml": "<p>x</p>", "baseText": ""}`,
		"login.ui.json":                      `{"translations": {}}`,
	})

	ctx := context.Background()
	store := auth.NewMemoryTemplateStore()
	_, err := seedTemplateDir(ctx, dir, store)
	if err == nil {
		t.Fatal("a directory with two inert files was accepted")
	}
	// Every bad file at once, not the first one.
	for _, want := range []string{auth.TemplatePasswordReset + ".json", "login.ui.json"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %s, so the operator fixes them one redeploy at a time:\n%v", want, err)
		}
	}
	// And nothing at all was written, including the file that was valid.
	if _, found, err := store.GetMailTemplate(ctx, auth.TemplateMagicLink); err != nil {
		t.Fatalf("GetMailTemplate: %v", err)
	} else if found {
		t.Errorf("the valid file was written before the directory was refused, and the store now wins over %s forever", auth.TemplateMagicLink+".json")
	}
}

// TestTemplatesDirRefusesAnOversizedFile: the directory is artifact-baked, so
// this is an operator's mistake rather than an attacker's input — but the cold
// start reads every file into a Lambda with a fixed memory limit inside an 8
// second startTimeout, so a file somebody copied the wrong thing into has to be
// refused by name instead of becoming an init failure with nothing to read.
func TestTemplatesDirRefusesAnOversizedFile(t *testing.T) {
	t.Parallel()

	const name = auth.TemplateMagicLink + ".json"
	dir := writeTemplateFiles(t, map[string]string{
		name: `{"baseHtml": "<p>` + strings.Repeat("x", maxSeedFileBytes) + `</p>", "baseText": "x"}`,
	})

	_, err := seedTemplateDir(context.Background(), dir, auth.NewMemoryTemplateStore())
	if err == nil {
		t.Fatal("an oversized file was read whole at cold start")
	}
	for _, want := range []string{"email.templatesDir", name} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name %q", err, want)
		}
	}
}

// TestUnreadableTemplatesDirRefusesInProductionAndWarnsInDevelopment: the
// directory is baked into the artifact, so in production a missing one means
// the artifact is not what the document says it is and the deployment should
// fail where that is visible. A development stack is allowed to come up without
// its templates and render the built-ins, as long as it says so.
func TestUnreadableTemplatesDirRefusesInProductionAndWarnsInDevelopment(t *testing.T) {
	t.Parallel()

	// Built directly rather than loaded, because the point here is the
	// environment branch alone and a production document drags in the whole
	// refuse-to-start set (RS-12 forbids the memory driver, for one).
	newCfg := func(environment string) *config.Config {
		cfg := config.Defaults()
		cfg.Deployment.Environment = environment
		cfg.Stores.Enable.Templates = true
		cfg.Email.TemplatesDir = filepath.Join(t.TempDir(), "not-baked-into-the-artifact")
		return cfg
	}

	t.Run("production refuses", func(t *testing.T) {
		t.Parallel()
		_, err := emailOptions(context.Background(), newCfg("production"), newMemoryStoreBundle(), nil, discardLogger())
		if err == nil {
			t.Fatalf("a production cold start came up with a templates directory it could not read")
		}
		if !strings.Contains(err.Error(), "email.templatesDir") {
			t.Errorf("the error does not name the knob:\n%v", err)
		}
	})

	t.Run("development warns and carries on", func(t *testing.T) {
		t.Parallel()
		// Written and read from one goroutine, so a plain buffer is enough.
		var buf bytes.Buffer
		_, err := emailOptions(context.Background(), newCfg("development"), newMemoryStoreBundle(), nil,
			newLogger(&buf, slog.LevelDebug))
		if err != nil {
			t.Fatalf("a development stack must come up without its templates: %v", err)
		}
		if !strings.Contains(buf.String(), "email.templatesDir") {
			t.Errorf("nothing in the log says the templates directory was not read:\n%s", buf.String())
		}
	})
}

// TestTemplateStoreWinsOverTemplatesDirOnTheWire is the same precedence seen
// from a mailbox, through the whole binary: two ids, one already in the store
// and one only in the directory, and the mail each route sends says which
// template rendered it.
func TestTemplateStoreWinsOverTemplatesDirOnTheWire(t *testing.T) {
	t.Parallel()

	dir := writeTemplateFiles(t, map[string]string{
		auth.TemplatePasswordReset + ".json": seedFile("FROM THE DIRECTORY"),
		auth.TemplateMagicLink + ".json":     seedFile("FROM THE DIRECTORY"),
	})

	bundle := newMemoryStoreBundle()
	html := `<p>FROM THE STORE <a href="{{link}}">{{link}}</a></p>`
	text := "FROM THE STORE {{link}}"
	if _, err := bundle.Templates().UpdateMailTemplate(context.Background(), auth.TemplatePasswordReset,
		auth.MailTemplatePatch{
			BaseHTML:     &html,
			BaseText:     &text,
			Translations: map[string]map[string]string{"en": {"subject": "FROM THE STORE subject"}},
		}); err != nil {
		t.Fatalf("UpdateMailTemplate: %v", err)
	}

	env := with(mailerEnv(baseEnv()),
		ConfigJSONEnv, templatesDirDoc(dir),
		"AWESOME_AUTH_STORES_ENABLE_TEMPLATES", "true")
	d := newDeliveryAppWith(t, env, func(o *Options) {
		o.Stores = storeFactory(bundle, auth.NewMemorySessionStore())
	})
	const owner = "templated@example.test"
	d.register(t, owner)

	for _, tc := range []struct {
		name, path, wantSubject, wantMarker string
	}{
		{"an id the store holds is not touched by the directory", "/auth/forgot-password",
			"FROM THE STORE subject", "FROM THE STORE"},
		{"an id only the directory has is seeded and rendered", "/auth/magic-link/send",
			"FROM THE DIRECTORY subject", "FROM THE DIRECTORY"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d.mail.reset()
			resp := invoke(t, d.app, http.MethodPost, tc.path, jsonHeaders(), nil,
				fmt.Sprintf(`{"email":%q}`, owner))
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s status = %d (body %s)", tc.path, resp.StatusCode, resp.Body)
			}
			msg := d.mail.only(t)
			if msg.Subject != tc.wantSubject {
				t.Errorf("Subject = %q, want %q", msg.Subject, tc.wantSubject)
			}
			if !strings.Contains(msg.Body, tc.wantMarker) || !strings.Contains(msg.Text, tc.wantMarker) {
				t.Errorf("the %q template did not render both bodies:\n%s\n%s", tc.wantMarker, msg.Body, msg.Text)
			}
			// The stored templates carry a {{T.intro}} placeholder; a rendered
			// mail that still shows one means the translations never arrived.
			if strings.Contains(msg.Body, "{{") || strings.Contains(msg.Body, "[intro]") {
				t.Errorf("a placeholder survived rendering:\n%s", msg.Body)
			}
			if token := tokenIn(t, linkIn(t, msg.Body)); token == "" {
				t.Errorf("the stored template rendered a link with no token")
			}
		})
	}
}

// TestTemplateStoreRefusesADriverWithoutOne: stores.enable.templates is a
// promise that the admin template routes work. A driver that cannot back it
// must fail the cold start rather than advertise a store whose every write goes
// nowhere.
func TestTemplateStoreRefusesADriverWithoutOne(t *testing.T) {
	t.Parallel()

	// A bare user store: no Templates() method, so the structural assertion in
	// emailOptions finds nothing.
	_, err := New(context.Background(), Options{
		Getenv: envFunc(with(baseEnv(), "AWESOME_AUTH_STORES_ENABLE_TEMPLATES", "true")),
		Logger: discardLogger(),
		Stores: storeFactory(auth.NewMemoryUserStore(), auth.NewMemorySessionStore()),
	})
	if err == nil {
		t.Fatal("the app came up advertising a template store the driver cannot back")
	}
	for _, want := range []string{"stores.enable.templates", config.StoreDriverMemory} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name %q", err, want)
		}
	}
}

// TestTemplatesAreBackedByEveryDriver pins the claim driverStores makes about
// the template store, and pins the diagnosis an operator gets when a claim like
// it is false.
//
// Both drivers back templates: internal/store/dynamodb keeps them on its
// TEMPLATES partition and the memory driver hangs the core's MemoryTemplateStore
// off the user store, so email.templatesDir is deployable on either. The
// refusal mechanism still has to work, because the claim and the store can
// drift apart again — so the second half enables a store no driver backs and
// requires the early, named refusal. Early matters: without it the cold start
// would get as far as building the real stores and then fail inside
// emailOptions with a structural assertion that reads like an internal error.
func TestTemplatesAreBackedByEveryDriver(t *testing.T) {
	t.Parallel()

	for _, driver := range []string{config.StoreDriverDynamoDB, config.StoreDriverMemory} {
		cfg := config.Defaults()
		cfg.Stores.Driver = driver
		cfg.Stores.Enable.Templates = true
		if err := checkStoreSupport(cfg); err != nil {
			t.Errorf("%s backs a template store and was refused one: %v", driver, err)
		}
	}

	// Telemetry is the counter-example: the DynamoDB store implements it, but
	// nothing hands it to the core until the tools block does, so the flag
	// would validate and change nothing. It must be refused before anything
	// is constructed, and the message must name both the key and the driver.
	// (RBAC used to stand here; the admin surface made it a real switch.)
	cfg := config.Defaults()
	cfg.Stores.Driver = config.StoreDriverDynamoDB
	cfg.Stores.Enable.Telemetry = true

	err := checkStoreSupport(cfg)
	if err == nil {
		t.Fatal("stores.enable.telemetry was accepted on dynamodb, but nothing hands the telemetry store to the core yet")
	}
	for _, want := range []string{"stores.enable.telemetry", config.StoreDriverDynamoDB} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %v, want it to name %q", err, want)
		}
	}
}

// ── the delivery webhook ─────────────────────────────────────────────────────

// webhookDelivery is one request the receiver took, kept whole: the signature
// is over the exact bytes, so nothing here may be re-encoded.
type webhookDelivery struct {
	body    []byte
	headers http.Header
	request auth.DeliveryWebhookRequest
}

// webhookReceiver is the deployment's own https receiver, standing in for
// whatever a real one forwards to. It is a TLS server because the schema
// refuses a delivery webhook that is not https — the body is a credential —
// which is also why Options.HTTPClient exists: the test trusts this
// certificate and nothing else does.
type webhookReceiver struct {
	srv *httptest.Server

	mu      sync.Mutex
	got     []webhookDelivery
	hangFor time.Duration
}

func newWebhookReceiver(t *testing.T) *webhookReceiver {
	t.Helper()
	r := &webhookReceiver{}
	r.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body := make([]byte, 0, 512)
		buf := make([]byte, 512)
		for {
			n, err := req.Body.Read(buf)
			body = append(body, buf[:n]...)
			if err != nil {
				break
			}
		}
		var decoded auth.DeliveryWebhookRequest
		_ = json.Unmarshal(body, &decoded)

		r.mu.Lock()
		hang := r.hangFor
		r.got = append(r.got, webhookDelivery{body: body, headers: req.Header.Clone(), request: decoded})
		r.mu.Unlock()

		if hang > 0 {
			select {
			case <-time.After(hang):
			case <-req.Context().Done():
				// The client gave up: its timeout is what this test is about.
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(r.srv.Close)
	return r
}

// setHang makes the handler sit on every later request for d before answering.
// It takes the mutex the handler reads the field under: no request is in flight
// when the only caller sets it, so -race stays quiet either way, but a test that
// posted first and set it after would otherwise be a real data race.
func (r *webhookReceiver) setHang(d time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hangFor = d
}

func (r *webhookReceiver) deliveries() []webhookDelivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]webhookDelivery(nil), r.got...)
}

// byKind indexes what arrived, failing when a kind arrived twice: every
// assertion below is about one delivery of each kind.
func (r *webhookReceiver) byKind(t *testing.T) map[string]webhookDelivery {
	t.Helper()
	out := make(map[string]webhookDelivery)
	for _, got := range r.deliveries() {
		if _, dup := out[got.request.Kind]; dup {
			t.Fatalf("kind %q was delivered twice", got.request.Kind)
		}
		out[got.request.Kind] = got
	}
	return out
}

// TestDeliveryWebhookReceivesEveryKind is the whole claim of the webhook
// branch: with email.deliveryWebhook.url set, every credential this deployment
// mints leaves as a signed POST to that receiver, and nothing is mailed or
// texted for those routes.
//
// The signature is verified here the way a receiver written against the
// family's convention verifies it — HMAC-SHA256 over the exact request bytes,
// "sha256=" and the hex digest (webhook-sender.ts:54-56) — rather than by
// asking the core what it computed, because a receiver that cannot check the
// signature independently cannot tell a forged delivery from a real one.
func TestDeliveryWebhookReceivesEveryKind(t *testing.T) {
	t.Parallel()

	rec := newWebhookReceiver(t)
	env := webhookEnv(baseEnv(), rec.srv.URL)
	d := newDeliveryAppWith(t, env, func(o *Options) { o.HTTPClient = rec.srv.Client() })

	const owner = "hooked@example.test"
	token := d.register(t, owner)

	for _, step := range []struct {
		path, body string
		headers    map[string]string
	}{
		{"/auth/magic-link/send", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders()},
		{"/auth/forgot-password", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders()},
		{"/auth/change-email/request", `{"newEmail":"rehooked@example.test"}`, bearer(token)},
		{"/auth/add-phone", fmt.Sprintf(`{"phoneNumber":%q}`, testPhone), bearer(token)},
		{"/auth/sms/send", fmt.Sprintf(`{"email":%q}`, owner), jsonHeaders()},
	} {
		if resp := invoke(t, d.app, http.MethodPost, step.path, step.headers, nil, step.body); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s status = %d (body %s)", step.path, resp.StatusCode, resp.Body)
		}
	}

	// The fifth kind has no route in this build — every account registers
	// already verified, see TestVerificationEmailUsesItsOwnTemplate — so it is
	// driven through the same composed core the app builds.
	core, users := newDeliveryCore(t, env, nil, nil, rec.srv.Client())
	user, err := users.CreateUser(context.Background(), auth.User{Email: "unhooked@example.test"})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if _, err := core.SendVerificationEmailToken(context.Background(), auth.EmailVerificationInput{
		UserID: user.ID, TenantID: user.TenantID,
	}); err != nil {
		t.Fatalf("SendVerificationEmailToken: %v", err)
	}

	// Nothing went through a transport: both fakes are injected on every app in
	// this file, and the webhook is supposed to have taken every seam.
	if msgs := d.mail.messages(); len(msgs) != 0 {
		t.Errorf("%d mail(s) were sent alongside the webhook: %+v", len(msgs), msgs)
	}
	if texts := d.sms.messages(); len(texts) != 0 {
		t.Errorf("%d text(s) were sent alongside the webhook: %+v", len(texts), texts)
	}

	got := rec.byKind(t)
	deliveryIDs := make(map[string]bool)
	for _, kind := range []string{
		auth.DeliveryKindMagicLink,
		auth.DeliveryKindPasswordReset,
		auth.DeliveryKindEmailChange,
		auth.DeliveryKindSMSCode,
		auth.DeliveryKindEmailVerification,
	} {
		t.Run(kind, func(t *testing.T) {
			delivery, ok := got[kind]
			if !ok {
				t.Fatalf("no %s delivery reached the receiver; the kinds seen were %v", kind, got)
			}

			// The envelope, header by header.
			if ct := delivery.headers.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if event := delivery.headers.Get("X-Webhook-Event"); event != "delivery."+kind {
				t.Errorf("X-Webhook-Event = %q, want %q", event, "delivery."+kind)
			}
			id := delivery.headers.Get("X-Webhook-Delivery")
			if id == "" {
				t.Error("X-Webhook-Delivery is empty, so a receiver cannot deduplicate")
			}
			if deliveryIDs[id] {
				t.Errorf("X-Webhook-Delivery %q was reused across deliveries", id)
			}
			deliveryIDs[id] = true
			if _, err := time.Parse("2006-01-02T15:04:05.000Z07:00", delivery.headers.Get("X-Webhook-Timestamp")); err != nil {
				t.Errorf("X-Webhook-Timestamp %q is not the family's ISO 8601 form: %v",
					delivery.headers.Get("X-Webhook-Timestamp"), err)
			}

			// The signature, computed here from the secret and the bytes.
			mac := hmac.New(sha256.New, []byte(testWebhookSecret))
			mac.Write(delivery.body)
			want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if got := delivery.headers.Get("X-Webhook-Signature"); got != want {
				t.Errorf("X-Webhook-Signature = %q, want %q — an independent HMAC over the body", got, want)
			}
			// The secret itself is never sent, only proof of it.
			if strings.Contains(string(delivery.body), testWebhookSecret) {
				t.Error("the signing secret appears in the request body")
			}
			for name, values := range delivery.headers {
				if strings.Contains(strings.Join(values, " "), testWebhookSecret) {
					t.Errorf("the signing secret appears in header %s", name)
				}
			}

			// The payload: the credential, and the base the receiver is
			// expected to build the link on.
			assertWebhookPayload(t, kind, delivery.request.Delivery)
		})
	}
}

// assertWebhookPayload decodes one delivery into the very type the core sent
// and checks that the credential and the link base survived the round trip. A
// receiver that gets no token has nothing to deliver.
func assertWebhookPayload(t *testing.T, kind string, raw json.RawMessage) {
	t.Helper()

	decode := func(into any) {
		t.Helper()
		if err := json.Unmarshal(raw, into); err != nil {
			t.Fatalf("decode %s delivery: %v", kind, err)
		}
	}
	switch kind {
	case auth.DeliveryKindMagicLink:
		var d auth.MagicLinkDelivery
		decode(&d)
		assertWebhookCredential(t, kind, d.Email, d.Token)
		assertWebhookLinkBase(t, kind, d.LinkBase, true)
	case auth.DeliveryKindPasswordReset:
		var d auth.PasswordResetDelivery
		decode(&d)
		assertWebhookCredential(t, kind, d.Email, d.Token)
		assertWebhookLinkBase(t, kind, d.LinkBase, true)
	case auth.DeliveryKindEmailVerification:
		var d auth.EmailVerificationDelivery
		decode(&d)
		assertWebhookCredential(t, kind, d.Email, d.Token)
		// Its own field, not the constant: this is the one kind a caller here
		// raises through the core rather than over HTTP, so there is no Origin
		// to resolve and the base is legitimately empty. Passing the constant
		// instead would compare the expectation with itself and check nothing.
		assertWebhookLinkBase(t, kind, d.LinkBase, false)
	case auth.DeliveryKindEmailChange:
		var d auth.EmailChangeDelivery
		decode(&d)
		assertWebhookCredential(t, kind, d.NewEmail, d.Token)
		assertWebhookLinkBase(t, kind, d.LinkBase, true)
	case auth.DeliveryKindSMSCode:
		var d auth.SMSCodeDelivery
		decode(&d)
		// A text message has no link at all — SMSCodeDelivery has no LinkBase
		// field — so there is nothing to check and nothing is asserted.
		assertWebhookCredential(t, kind, d.Phone, d.Code)
	default:
		t.Fatalf("unexpected kind %q", kind)
	}
}

func assertWebhookCredential(t *testing.T, kind, recipient, credential string) {
	t.Helper()
	if recipient == "" {
		t.Errorf("%s: the delivery names no recipient", kind)
	}
	if credential == "" {
		t.Errorf("%s: the delivery carries no token or code, so the receiver has nothing to deliver", kind)
	}
}

// assertWebhookLinkBase checks the base the receiver is told to build the link
// on, for the four kinds that carry one.
//
// The value must be the resolved site URL: a base a caller could steer would let
// it have a victim's link built against a host it controls. An empty base is a
// real case too — a delivery raised outside an HTTP request has no Origin to
// resolve, and the receiver falls back to its own — so `required` says whether
// this particular delivery came over HTTP, and every kind that did must actually
// carry one. Without that, the whole check would pass on an empty field and
// assert nothing at all.
func assertWebhookLinkBase(t *testing.T, kind, linkBase string, required bool) {
	t.Helper()
	if linkBase == "" {
		if required {
			t.Errorf("%s: the delivery carries no linkBase, and this one was raised by an HTTP request that resolved %q", kind, testLinkBase)
		}
		return
	}
	if linkBase != testLinkBase {
		t.Errorf("%s: linkBase = %q, want the resolved site URL %q", kind, linkBase, testLinkBase)
	}
}

// TestDeliveryWebhookHonoursItsTimeout: the route that minted the credential is
// waiting on this request inside a Lambda invocation, so a receiver that stops
// answering must cost timeoutMs and not the core's five second default, let
// alone the function's whole timeout.
func TestDeliveryWebhookHonoursItsTimeout(t *testing.T) {
	t.Parallel()

	rec := newWebhookReceiver(t)
	rec.setHang(10 * time.Second)

	const timeoutMs = 250
	cfg := loadTestConfig(t, webhookEnv(baseEnv(), rec.srv.URL,
		"AWESOME_AUTH_EMAIL_DELIVERY_WEBHOOK_TIMEOUT_MS", fmt.Sprint(timeoutMs)))
	d, err := newDelivery(cfg, nil, nil, rec.srv.Client(), discardLogger())
	if err != nil {
		t.Fatalf("newDelivery: %v", err)
	}
	if want := timeoutMs * time.Millisecond; d.webhook.Timeout != want {
		t.Fatalf("webhook timeout = %v, want %v from email.deliveryWebhook.timeoutMs", d.webhook.Timeout, want)
	}

	start := time.Now()
	err = d.webhook.SendMagicLink(context.Background(), auth.MagicLinkDelivery{
		Email: "slow@example.test", Token: "the-token-that-never-arrived",
	})
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a receiver that never answered reported success")
	}
	// Comfortably under the core's own 5s default, which is what proves the
	// configured value is the one in force.
	if elapsed > 2*time.Second {
		t.Errorf("the send took %v, want it bounded by the configured %dms", elapsed, timeoutMs)
	}
	if strings.Contains(err.Error(), "the-token-that-never-arrived") {
		t.Errorf("the error carries the credential, and an error is logged:\n%v", err)
	}
}

// TestEmailFlowDomainsStartTheApp is the P2 counterpart of the config package's
// TestEmailFlowDomainsAreWired, one layer up: a document that configures all
// three domains at once not only loads, it builds an App, and the cold-start
// log accounts for each of them.
func TestEmailFlowDomainsStartTheApp(t *testing.T) {
	t.Parallel()

	dir := writeTemplateFiles(t, map[string]string{
		auth.TemplateWelcome + ".json": seedFile("FROM THE DIRECTORY"),
	})
	env := with(mailerEnv(webhookEnv(baseEnv(), testWebhookURL)),
		ConfigJSONEnv, templatesDirDoc(dir),
		"AWESOME_AUTH_STORES_ENABLE_TEMPLATES", "true",
		"AWESOME_AUTH_EMAIL_SITE_URLS", testSiteURL+","+testAltSiteURL,
		"AWESOME_AUTH_CORS_ORIGINS", testCORSOrigin)

	d := newDeliveryApp(t, env)
	if d.app.Config.Email.TemplatesDir != dir {
		t.Errorf("templatesDir = %q, want %q", d.app.Config.Email.TemplatesDir, dir)
	}

	out := d.log.String()
	for _, want := range []string{
		// email.siteUrls: the canonical site every link is built on.
		testSiteURL,
		// email.templatesDir: what it seeded.
		"mailTemplatesSeeded",
		// email.deliveryWebhook: the receiver's origin, and never its path.
		"https://delivery.example.test",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the cold-start log does not mention %q:\n%s", want, out)
		}
	}
	// The receiver's path is where an operator puts a capability token when the
	// receiver cannot check a signature itself, so the log stops at the origin.
	if strings.Contains(out, "delivery.example.test/hook") {
		t.Errorf("the cold-start log carries the webhook's path:\n%s", out)
	}
	// And the signing secret is not in it either.
	if strings.Contains(out, testWebhookSecret) {
		t.Errorf("the delivery webhook's signing secret reached the log:\n%s", out)
	}
}

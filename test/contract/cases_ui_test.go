package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

// The hosted UI, black-box: the config document its pages boot from, and the
// server-rendered pages themselves.
//
// The reference mounts one router at <prefix>/ui (auth.router.ts:1640) whose
// four layers run in an order that is itself behaviour (src/router/ui.router.ts):
// /config answers first, the headless short-circuit returns before the uploaded
// assets are mounted, the SSR catch-all runs before the static serve — which is
// the only reason an extensionless /login is a page and /base.css is a file.
// This port mounts the same router as one handler, because a catch-all sibling
// of a fixed path is not something every Go router will register.
//
// Every case here fetches with no credential of any kind, and that is the
// assertion rather than the convenience: the login page is fetched before any
// session exists, so a deployment that had put the UI behind one would be
// serving a page nobody can reach, and a suite that arrived with a session would
// report it healthy.
//
// Two things are deliberately not asserted, both for the reason the docs cases
// leave out their Content-Security-Policy: the identical assertions run against
// the reference Express app, so anything this port adds belongs in the unit
// tests of the code that adds it.
//
//   - `Cache-Control: no-store` on GET <prefix>/ui/config. That header is the
//     port's own addition (adapter/nethttp/ui.go says so in as many words); the
//     reference sets none on that route. The SSR pages' no-store IS the
//     reference's (ui.router.ts:284) and is asserted below.
//   - The escaping of the injected __AUTH_CONFIG__ object. Go's encoder writes
//     `<` where JSON.stringify writes `<`, which is the registered upstream
//     deviation ui-ssr-config-json-is-html-escaped — the one place the port is
//     stricter than the reference. The bytes differ; the value JSON.parse yields
//     does not, so every case below parses the object rather than matching it.

// uiInjectedConfigMarker is what serveSsrHtml writes into every rendered page
// ahead of the config object (ui.router.ts:273). It is the anchor the pages'
// own scripts read, so a page that has lost it boots by fetching /ui/config
// instead — slower, and with a flash of unstyled content — while still
// answering 200.
const uiInjectedConfigMarker = "window.__AUTH_CONFIG__ = "

func init() {
	register(
		Case{
			Name: "ui/config-document-is-served-anonymously",
			Doc: "reference src/router/ui.router.ts:95-170 — GET <prefix>/ui/config is 200 application/json, fetched with no credential of any kind, " +
				"carrying apiPrefix (where the API is mounted, so the UI can be served from one path and call the API at another), a features object, " +
				"a ui branding object whose three mandatory members are never empty, a translations object that is never null, a lang, and headless",
			Needs: []Capability{CapUI},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/ui/config")
				r.mustStatus(t, 200)
				if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
					t.Fatalf("Content-Type = %q, want application/json\n  %s", ct, r.where())
				}

				doc := uiConfigOf(t, r.Body, r.where())

				// apiPrefix is the whole reason this document exists: it is what
				// lets the pages be served from one path and post to another. A
				// document naming a prefix this deployment does not answer is a
				// UI that renders and then fails on its first request.
				if doc.APIPrefix != e.Prefix {
					t.Errorf("apiPrefix = %q, want %q — the UI would call routes this deployment does not serve\n  %s",
						doc.APIPrefix, e.Prefix, r.where())
				}

				// The three branding members with defaults behind them. The
				// reference fills each from the settings store, then the static
				// config, then a literal (ui.router.ts:126-129), so there is no
				// configuration in which any of them is empty — and an empty one
				// renders a page with no heading and no colours.
				for _, row := range []struct{ name, got string }{
					{"ui.primaryColor", doc.UI.PrimaryColor},
					{"ui.secondaryColor", doc.UI.SecondaryColor},
					{"ui.siteName", doc.UI.SiteName},
				} {
					if strings.TrimSpace(row.got) == "" {
						t.Errorf("%s is empty; it has a default behind it on both sides and can never be\n  %s", row.name, r.where())
					}
				}

				// translations is an object and never null (:105-112): a
				// deployment with no template store, a store with no config
				// page, and a page holding neither the requested language nor
				// English all yield {}. A null here is a client crash on
				// Object.keys.
				if doc.Translations == nil {
					t.Errorf("translations is null; every documented path yields an object, even the empty one\n  %s", r.where())
				}
				if strings.TrimSpace(doc.Lang) == "" {
					t.Errorf("lang is empty; it falls back to the configured default and then to \"en\"\n  %s", r.where())
				}

				// features gates what the pages offer. register is true wherever
				// the route is mounted, which is every open realm of this port
				// (the core's register-route-is-always-mounted), and false on a
				// closed one (registration/closed-realm-hides-sign-up-from-the-ui
				// pins that half) — but the key has to be there whatever it
				// says, because the page reads it.
				if _, ok := doc.Features["register"]; !ok {
					t.Errorf("features carries no register flag, so the login page cannot decide whether to offer registration: %v\n  %s",
						keysOf(doc.Features), r.where())
				}

				// The route sits behind the CSRF auto-init and behind nothing
				// else, so that is the only cookie it may set. An access or
				// refresh cookie on a document fetched before login would be a
				// session handed to an anonymous caller.
				for _, name := range r.cookieBaseNames() {
					if name != cookieCSRF {
						t.Errorf("the config document sets a %q cookie; the only cookie this route may set is the csrf auto-init one\n  %s",
							name, r.where())
					}
				}
			},
		},

		Case{
			Name: "ui/login-page-is-server-rendered",
			Doc: "reference src/router/ui.router.ts:193-291 — GET <prefix>/ui/login is 200 text/html; charset=utf-8, uncacheable because it embeds a " +
				"per-request config object, and that object is injected into the document as window.__AUTH_CONFIG__ so the page boots without " +
				"waiting for GET <prefix>/ui/config; the readiness splash is injected with it",
			Needs: []Capability{CapUI},
			Run: func(t *testing.T, e *Env) {
				r := e.NewClient().GET(t, "/ui/login")
				r.mustStatus(t, 200)
				if ct := r.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
					t.Errorf("Content-Type = %q, want %q\n  %s", ct, "text/html; charset=utf-8", r.where())
				}

				// The page is not a shared resource: it carries a config object
				// built for this request. The reference says so all four ways
				// (:284) and the two that matter are asserted; matching the
				// whole string byte for byte would fail on a reordering that
				// changes nothing.
				cc := strings.ToLower(r.Header.Get("Cache-Control"))
				for _, want := range []string{"no-store", "max-age=0"} {
					if !strings.Contains(cc, want) {
						t.Errorf("Cache-Control = %q, want it to contain %q — this document embeds a per-request config object\n  %s",
							r.Header.Get("Cache-Control"), want, r.where())
					}
				}

				page := string(r.Body)
				doc := uiInjectedConfig(t, page, r.where())
				if doc.APIPrefix != e.Prefix {
					t.Errorf("the injected config names apiPrefix %q, want %q — the rendered page would call routes this deployment does not serve\n  %s",
						doc.APIPrefix, e.Prefix, r.where())
				}

				// The injected object and the fetched one are the same document
				// built by the same function, so a deployment where they
				// disagree renders a page that behaves one way before its first
				// fetch and another after it.
				fetched := uiConfigOf(t, e.NewClient().GET(t, "/ui/config").Body, r.where())
				if doc.APIPrefix != fetched.APIPrefix || doc.Lang != fetched.Lang || doc.UI.SiteName != fetched.UI.SiteName {
					t.Errorf("the injected config and GET %s/ui/config disagree: injected %+v, fetched %+v\n  %s",
						e.Prefix, doc, fetched, r.where())
				}

				// The readiness splash, injected into <body> with the config
				// (:231-270). Without it the page paints unstyled until its
				// stylesheet arrives, which is the flash the whole SSR injection
				// exists to prevent.
				if !strings.Contains(page, `id="global-splash"`) {
					t.Errorf("the rendered page carries no readiness splash, so it paints unstyled before its stylesheet arrives\n  %s", r.where())
				}
			},
		},

		Case{
			Name: "ui/mount-root-and-unknown-pages-render-the-login-page",
			Doc: "reference src/router/ui.router.ts:306-325 — the mount root renders the login page, with and without a trailing slash, and so does any " +
				"extensionless path with no page of its own: the page is req.path or \"login\" when empty, falling back to login.html. No redirect, " +
				"on any of the three",
			Needs: []Capability{CapUI},
			Run: func(t *testing.T, e *Env) {
				// Both spellings of the root, because they are one page in
				// Express and were two patterns here: a router mounted with
				// router.use('/ui', …) sees req.path "/" for both, while
				// net/http's subtree pattern does not cover its own root and
				// answers 301 to the trailing-slash form unless the adapter
				// registers it too. This client does not follow redirects, so a
				// 301 fails here rather than passing silently.
				//
				// And an unknown page, which is the catch-all's fallback: a path
				// with no file of its own renders login.html rather than 404ing,
				// which is what makes a client-side route like /ui/whatever
				// deep-linkable.
				for _, path := range []string{"/ui", "/ui/", "/ui/no-such-page-exists"} {
					r := e.NewClient().GET(t, path)
					if r.Status != 200 {
						t.Errorf("GET %s%s answered %d, want 200 — the mount root and every extensionless path render the login page\n  %s",
							e.Prefix, path, r.Status, r.where())
						continue
					}
					if ct := r.Header.Get("Content-Type"); ct != "text/html; charset=utf-8" {
						t.Errorf("GET %s%s: Content-Type = %q, want %q\n  %s", e.Prefix, path, ct, "text/html; charset=utf-8", r.where())
					}
					// Rendered, not merely served: the static layer sits under
					// the catch-all and would answer a raw file with no config
					// in it, which is a page that cannot talk to the API.
					if doc := uiInjectedConfig(t, string(r.Body), r.where()); doc.APIPrefix != e.Prefix {
						t.Errorf("GET %s%s: the injected config names apiPrefix %q, want %q\n  %s",
							e.Prefix, path, doc.APIPrefix, e.Prefix, r.where())
					}
				}
			},
		},
	)
}

// uiConfig is the body of GET <prefix>/ui/config, with the reference's keys
// (ui.router.ts:136-142 plus :168).
//
// features is a map rather than a struct on purpose: the reference's own error
// path serves a *shorter* object carrying three of the eight flags
// (:143-161), which a client cannot tell from success, so a struct would decode
// that as eight flags of which five are false and hide the difference.
type uiConfig struct {
	APIPrefix    string            `json:"apiPrefix"`
	Features     map[string]any    `json:"features"`
	UI           uiConfigBranding  `json:"ui"`
	Translations map[string]string `json:"translations"`
	Lang         string            `json:"lang"`
	Headless     bool              `json:"headless"`
}

type uiConfigBranding struct {
	PrimaryColor   string `json:"primaryColor"`
	SecondaryColor string `json:"secondaryColor"`
	LogoURL        string `json:"logoUrl"`
	SiteName       string `json:"siteName"`
}

func uiConfigOf(t *testing.T, raw []byte, where string) uiConfig {
	t.Helper()
	var doc uiConfig
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("the config document is not JSON (%v)\n  %s", err, where)
	}
	return doc
}

// uiInjectedConfig pulls the config object out of a rendered page.
//
// It decodes the first JSON value after the marker rather than matching up to a
// closing delimiter, which is what makes it indifferent to the one documented
// difference between the two implementations: this port's encoder escapes `<`,
// `>` and `&` as <, > and & where JSON.stringify leaves them
// (the upstream deviation ui-ssr-config-json-is-html-escaped), and it is also
// indifferent to whatever the page writes after the object.
func uiInjectedConfig(t *testing.T, page, where string) uiConfig {
	t.Helper()
	i := strings.Index(page, uiInjectedConfigMarker)
	if i < 0 {
		t.Fatalf(`the rendered page carries no %s block, so it boots by fetching the config instead of from the document.

That is the reference's own fallback for an injection that threw (ui.router.ts:286-290): the page still
works, and it flashes unstyled while it waits. A page that never had the block is a page the SSR layer
did not render.
  %s`, strings.TrimSuffix(uiInjectedConfigMarker, " = "), where)
	}
	var doc uiConfig
	dec := json.NewDecoder(strings.NewReader(page[i+len(uiInjectedConfigMarker):]))
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the injected config object is not JSON (%v)\n  %s", err, where)
	}
	return doc
}

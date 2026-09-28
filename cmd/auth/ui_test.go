package main

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	auth "github.com/nik2208/awesome-go-auth"

	"github.com/nik2208/awesome-lambda-auth/internal/config"
)

// uiEnv is a document that turns the hosted UI on, loaded through
// AllowUnimplemented so that these tests say the same thing on both sides of the
// phase gate: `ui` is removed from unwiredDomains() in a commit of its own, and
// nothing here should change on the day it is.
func uiEnv(t *testing.T, kv ...string) *config.Config {
	t.Helper()
	cfg, err := config.Load(context.Background(), config.Options{
		Getenv:             envFunc(with(baseEnv(), append([]string{"AWESOME_AUTH_UI_ENABLED", "true"}, kv...)...)),
		AllowUnimplemented: true,
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

// TestUIOptionsCarryTheWholeBlock pins the map from the product's `ui` block onto
// auth.UIOptions, knob by knob.
//
// It is a field-by-field assertion rather than a spot check because the failure
// this catches is a knob that loads, validates, and then reaches nothing — the
// exact thing internal/config/phases.go refuses a whole domain for. Once the
// domain is wired, this function is the only thing standing between a knob and
// that fate, and a missing line here is invisible everywhere else.
func TestUIOptionsCarryTheWholeBlock(t *testing.T) {
	t.Parallel()

	cfg := uiEnv(t,
		"AWESOME_AUTH_UI_HEADLESS", "true",
		"AWESOME_AUTH_UI_SITE_NAME", "Example Corp",
		"AWESOME_AUTH_UI_PRIMARY_COLOR", "#112233",
		"AWESOME_AUTH_UI_SECONDARY_COLOR", "#445566",
		"AWESOME_AUTH_UI_BG_COLOR", "#778899",
		"AWESOME_AUTH_UI_BG_IMAGE", "https://cdn.example.test/bg.png",
		"AWESOME_AUTH_UI_CARD_BG", "#aabbcc",
		"AWESOME_AUTH_UI_LOGO_URL", "https://cdn.example.test/logo.svg",
		"AWESOME_AUTH_MAILER_DEFAULT_LANG", "it",
	)
	got := uiOptions(cfg)

	if !got.Enabled || !got.Headless {
		t.Errorf("Enabled = %v, Headless = %v; want both true", got.Enabled, got.Headless)
	}
	for _, row := range []struct{ name, got, want string }{
		{"SiteName", got.Branding.SiteName, "Example Corp"},
		{"PrimaryColor", got.Branding.PrimaryColor, "#112233"},
		{"SecondaryColor", got.Branding.SecondaryColor, "#445566"},
		{"BgColor", got.Branding.BgColor, "#778899"},
		{"BgImage", got.Branding.BgImage, "https://cdn.example.test/bg.png"},
		{"CardBg", got.Branding.CardBg, "#aabbcc"},
	} {
		if row.got != row.want {
			t.Errorf("Branding.%s = %q, want %q", row.name, row.got, row.want)
		}
	}

	// The logo goes into the rung a stored setting still outranks, not into the
	// one above it. The reference's chain is settings.ui.logoUrl || customLogo ||
	// logoUrl (ui.router.ts:128); filling CustomLogo instead would place one
	// product knob above another product knob's own runtime override, which is
	// the thing §1.19 says must never happen.
	if got.Branding.LogoURL != "https://cdn.example.test/logo.svg" {
		t.Errorf("Branding.LogoURL = %q, want the configured logo", got.Branding.LogoURL)
	}
	if got.Branding.CustomLogo != "" {
		t.Errorf("Branding.CustomLogo = %q; the schema collapsed the pair into one knob and it belongs in LogoURL",
			got.Branding.CustomLogo)
	}

	// The reference reads the UI's fallback language from the mailer
	// (ui.router.ts:103). The core had no mailer block to read and exposed the
	// knob instead; this product has one, so the two are wired together and an
	// operator configures the language once.
	if got.DefaultLang != "it" {
		t.Errorf("DefaultLang = %q, want the mailer's %q", got.DefaultLang, "it")
	}

	// The uploads seam stays nil, and nil is now load-bearing the other way
	// round: the core serves the upload store admin.go configured through
	// auth.UploadFS whenever this field is nil (uiUploadsFollowTheUploadStore),
	// so a non-nil value here would *override* the store with a second
	// configuration of the same objects. TestUploadedAssetsAreServedFromTheUploadStore
	// in admin_test.go drives the read side end to end.
	if got.Uploads != nil {
		t.Error("UIOptions.Uploads is set; it must stay nil so the core serves the configured upload store rather than an override")
	}
}

// TestUICustomCSSIsStaticOnlyAndUnescaped states the one member of the served ui
// object that no runtime layer can reach, because getting it wrong is a
// same-origin script injection rather than a cosmetic bug.
//
// The reference injects customCss verbatim into a <style> of its own
// (ui.router.ts:130, :216) and reads it from the static config alone —
// auth.UISettings has no member for it, so a settings store cannot supply one.
// This test pins the product half of that: the value reaches the core from the
// document and from nowhere else.
func TestUICustomCSSIsStaticOnlyAndUnescaped(t *testing.T) {
	t.Parallel()

	doc := config.Document{
		"schemaVersion": 1,
		"ui":            map[string]any{"enabled": true, "customCss": ".card { border-radius: 0 }"},
	}
	cfg, err := config.Load(context.Background(), config.Options{
		Document:           doc,
		Getenv:             envFunc(baseEnv()),
		AllowUnimplemented: true,
	})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if got := uiOptions(cfg).CustomCSS; got != ".card { border-radius: 0 }" {
		t.Errorf("CustomCSS = %q, want the document's value unaltered", got)
	}
}

// TestUIAssetsDefaultToTheVendoredSet pins the meaning of a nil Assets, which is
// not "no assets" but "the reference's own fourteen, embedded".
func TestUIAssetsDefaultToTheVendoredSet(t *testing.T) {
	t.Parallel()

	if got := uiAssets(uiEnv(t)); got != nil {
		t.Error("uiAssets returned a filesystem for a document with no ui.assetsDir; " +
			"nil is what makes auth.UIHandler serve UpstreamUIAssetFS(), so an empty fs.FS here would serve nothing at all")
	}

	dir := t.TempDir()
	write(t, dir, "login.html", "<html><head><title>x</title></head><body></body></html>")
	cfg := uiEnv(t)
	cfg.UI.AssetsDir = dir
	fsys := uiAssets(cfg)
	if fsys == nil {
		t.Fatal("uiAssets returned nil for a configured ui.assetsDir")
	}
	if _, err := fs.Stat(fsys, "login.html"); err != nil {
		t.Errorf("the returned filesystem does not hold the directory's own files: %v", err)
	}
}

// TestUIAssetFallbacksMatchTheCore is the tripwire under uiFallbackPages.
//
// That list is a copy of the core's page resolution order (ui_pages.go
// uiResolvePage, reproducing ui.router.ts:306-325), kept here so checkUIAssets
// can ask in advance the question the handler will ask at request time. A copy
// drifts, and both directions of drift are silent: a fallback the core gained
// would make this build refuse a directory the handler would happily serve, and
// one the core dropped would let it accept a directory that answers 404 on every
// page.
//
// So the order is not asserted against another list, it is measured against the
// core's actual behaviour, through the same handler the adapter mounts.
func TestUIAssetFallbacksMatchTheCore(t *testing.T) {
	t.Parallel()

	// Each fallback alone must render for a page name that has no file of its
	// own, which is what makes it a fallback.
	for _, name := range uiFallbackPages {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			r := serveUI(t, fstest.MapFS{name: page(name)}, "/auth/ui/no-such-page")
			if r.Code != http.StatusOK {
				t.Fatalf("an asset set holding only %s answered %d for an unknown page; "+
					"the core no longer falls back to it and checkUIAssets would accept a directory that serves nothing", name, r.Code)
			}
			if !strings.Contains(r.Body.String(), "rendered:"+name) {
				t.Errorf("the page served was not %s:\n%s", name, r.Body.String())
			}
		})
	}

	// And the order between them, which decides what a directory holding
	// several of them actually serves.
	t.Run("the first match wins", func(t *testing.T) {
		t.Parallel()
		all := fstest.MapFS{}
		for _, name := range uiFallbackPages {
			all[name] = page(name)
		}
		r := serveUI(t, all, "/auth/ui/no-such-page")
		if want := "rendered:" + uiFallbackPages[0]; !strings.Contains(r.Body.String(), want) {
			t.Errorf("an asset set holding every fallback did not serve %s first; the core's preference order has changed:\n%s",
				uiFallbackPages[0], r.Body.String())
		}
	})

	// A set holding none of them renders nothing for any request, which is the
	// state checkUIAssets exists to refuse before a deployment discovers it.
	t.Run("none of them is a 404", func(t *testing.T) {
		t.Parallel()
		r := serveUI(t, fstest.MapFS{"base.css": &fstest.MapFile{Data: []byte("body{}")}}, "/auth/ui/no-such-page")
		if r.Code != http.StatusNotFound {
			t.Errorf("an asset set with no fallback page answered %d, want 404; "+
				"if the core grew a further fallback, uiFallbackPages has to grow with it", r.Code)
		}
	})
}

// TestCheckUISupportRefusesAnAssetDirectoryThatServesNothing covers the cold-start
// refusal, both of its branches, and the two ways it must stay quiet.
//
// The quiet halves matter as much as the loud ones: a refusal that also fired
// for the default configuration would make the vendored assets unusable, which
// is what almost every deployment runs.
func TestCheckUISupportRefusesAnAssetDirectoryThatServesNothing(t *testing.T) {
	t.Parallel()

	t.Run("the default configuration needs no filesystem", func(t *testing.T) {
		t.Parallel()
		if err := checkUISupport(uiEnv(t)); err != nil {
			t.Errorf("a UI serving the vendored assets was refused: %v", err)
		}
	})

	t.Run("the UI switched off is not checked at all", func(t *testing.T) {
		t.Parallel()
		cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(baseEnv())})
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		cfg.UI.AssetsDir = filepath.Join(t.TempDir(), "does-not-exist")
		if err := checkUISupport(cfg); err != nil {
			t.Errorf("a disabled UI was refused for an asset directory nothing would read: %v", err)
		}
	})

	t.Run("a directory that is not there", func(t *testing.T) {
		t.Parallel()
		cfg := uiEnv(t)
		cfg.UI.AssetsDir = filepath.Join(t.TempDir(), "does-not-exist")
		err := checkUISupport(cfg)
		if err == nil {
			t.Fatal("a ui.assetsDir that does not exist was accepted; every page would answer 404 on a stack reporting itself healthy")
		}
		for _, want := range []string{"ui.assetsDir", "does-not-exist"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %q:\n%v", want, err)
			}
		}
	})

	t.Run("a directory holding no page the handler falls back to", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, dir, "base.css", "body{}")
		cfg := uiEnv(t)
		cfg.UI.AssetsDir = dir
		err := checkUISupport(cfg)
		if err == nil {
			t.Fatal("an asset directory with no fallback page was accepted")
		}
		// The remedy is unusable without the names, because the operator has to
		// compare them against what their build actually copied.
		for _, name := range uiFallbackPages {
			if !strings.Contains(err.Error(), name) {
				t.Errorf("the refusal does not name the fallback page %q:\n%v", name, err)
			}
		}
	})

	t.Run("a directory holding one is enough", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		write(t, dir, "index.csr.html", "<html></html>")
		cfg := uiEnv(t)
		cfg.UI.AssetsDir = dir
		if err := checkUISupport(cfg); err != nil {
			t.Errorf("an asset directory holding a fallback page was refused: %v", err)
		}
	})
}

// TestHTTPConfigMountsTheUIHandler is the end of the wire this package can reach:
// the value httpConfig produces, handed to the adapter the binary actually
// mounts, really does register <prefix>/ui.
//
// It goes through nethttp.Mount rather than asserting a bool, because the bool
// is not the claim. Nothing in this binary may add a route under the api prefix,
// so the UI exists only if the imported adapter put it there — and the adapter
// reads UI.Enabled off the *resolved* config, which is a transformation this
// package never performs and could silently stop satisfying.
func TestHTTPConfigMountsTheUIHandler(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		cfg     *config.Config
		want    int
		explain string
	}{
		{"on", uiEnv(t), http.StatusOK, "the adapter did not mount the UI for a document that enables it"},
		{"off", mustLoad(t, baseEnv()), http.StatusNotFound, "the adapter mounted the UI for a document that does not enable it"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			core, err := auth.New(auth.WithSecret(testAccessSecret))
			if err != nil {
				t.Fatalf("auth.New: %v", err)
			}
			mux := http.NewServeMux()
			if err := mountAuthSurface(mux, core, tc.cfg, nil, nil); err != nil {
				t.Fatalf("mountAuthSurface: %v", err)
			}

			r := httptest.NewRecorder()
			mux.ServeHTTP(r, httptest.NewRequest(http.MethodGet, "/auth/ui/login", nil))
			if r.Code != tc.want {
				t.Errorf("%s: GET /auth/ui/login answered %d, want %d", tc.explain, r.Code, tc.want)
			}
		})
	}
}

// TestLogUISurfaceNamesWhatADeploymentCannotSee pins the cold-start report,
// because it is the only channel that tells an operator the UI is off, that
// headless serves no HTML, and that a settings-store failure degrades every page
// silently rather than failing it.
func TestLogUISurfaceNamesWhatADeploymentCannotSee(t *testing.T) {
	t.Parallel()

	t.Run("off", func(t *testing.T) {
		t.Parallel()
		out := captureUILog(t, mustLoad(t, baseEnv()))
		for _, want := range []string{"hosted UI not mounted", "/auth/ui", "404"} {
			if !strings.Contains(out, want) {
				t.Errorf("the cold-start log does not say %q:\n%s", want, out)
			}
		}
	})

	t.Run("on, with the settings store behind it", func(t *testing.T) {
		t.Parallel()
		cfg := uiEnv(t, "AWESOME_AUTH_UI_HEADLESS", "true")
		cfg.Stores.Enable.Settings = true
		out := captureUILog(t, cfg)
		for _, want := range []string{
			"hosted UI mounted",
			"hosted UI is headless",
			"the settings store is on the UI render path",
			"fallback document",
		} {
			if !strings.Contains(out, want) {
				t.Errorf("the cold-start log does not say %q:\n%s", want, out)
			}
		}
	})

	// The upload location, as the UI sees it: the two asset paths now serve
	// the upload store admin.go builds from an S3 location, one GetObject per
	// request, and the log says so where a visitor would meet it. A plain
	// path builds no store and is reported by unwiredKnobs instead
	// (TestAPlainUploadPathBuildsNoStoreAndIsReported, admin_test.go); this
	// used to be the retired ui-uploaded-assets-are-not-served warning.
	t.Run("an upload location the UI serves from", func(t *testing.T) {
		t.Parallel()
		out := captureUILog(t, uiEnv(t, "AWESOME_AUTH_UI_UPLOAD_DIR", "s3://logos/uploads"))
		for _, want := range []string{"ui.uploadDir", "uploaded assets on the hosted UI", "/auth/ui/assets/uploads/*", "GetObject", uploadAssetCSP} {
			if !strings.Contains(out, want) {
				t.Errorf("the cold-start log does not say %q:\n%s", want, out)
			}
		}
	})

	// The plain-path spelling builds no store, and the line says so instead
	// of claiming the two paths are served from one: the two cold-start lines
	// about ui.uploadDir — this one and the knob gap — used to contradict each
	// other, and this one was the wrong one on the wire.
	t.Run("an upload path the UI cannot serve from", func(t *testing.T) {
		t.Parallel()
		out := captureUILog(t, uiEnv(t, "AWESOME_AUTH_UI_UPLOAD_DIR", "/var/uploads"))
		for _, want := range []string{"uploaded assets on the hosted UI are not served", "/var/uploads", "/auth/ui/assets/uploads/* answer 404"} {
			if !strings.Contains(out, want) {
				t.Errorf("the cold-start log does not say %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "from the upload store") {
			t.Errorf("the cold-start log claims a filesystem path is served from the upload store:\n%s", out)
		}
	})
}

// ── helpers ──────────────────────────────────────────────────────────────────

func mustLoad(t *testing.T, env map[string]string) *config.Config {
	t.Helper()
	cfg, err := config.Load(context.Background(), config.Options{Getenv: envFunc(env)})
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// page is an HTML document carrying the anchors auth.UIHandler's SSR injection
// rewrites, plus a marker naming the file so a test can tell which one rendered.
func page(name string) *fstest.MapFile {
	return &fstest.MapFile{Data: []byte(
		"<html><head><title>t</title></head><body>rendered:" + name + "</body></html>")}
}

// serveUI drives the core's own UI handler over an asset set, which is the only
// way to measure what it resolves rather than what we believe it resolves.
func serveUI(t *testing.T, assets fs.FS, path string) *httptest.ResponseRecorder {
	t.Helper()
	core, err := auth.New(auth.WithSecret(testAccessSecret))
	if err != nil {
		t.Fatalf("auth.New: %v", err)
	}
	wire := auth.HTTPConfig{APIPrefix: "/auth", UI: auth.UIOptions{Enabled: true, Assets: assets}}
	r := httptest.NewRecorder()
	core.UIHandler(wire, nil).ServeHTTP(r, httptest.NewRequest(http.MethodGet, path, nil))
	return r
}

func captureUILog(t *testing.T, cfg *config.Config) string {
	t.Helper()
	var buf strings.Builder
	logUISurface(cfg, newLogger(&buf, slog.LevelInfo))
	return buf.String()
}

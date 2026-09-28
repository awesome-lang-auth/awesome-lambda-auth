package main

import (
	"net/http"
	"strings"
)

// The CORS response headers the reference hardcodes. docs/spec/config-schema.md
// §1.18 records them as "hardcoded, preserved without knobs", and
// docs/spec/wire-contract.md §84 pins the exact behaviour:
// src/router/auth.router.ts:513-527.
const (
	corsAllowMethods = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
	corsAllowHeaders = "Content-Type,Authorization,X-CSRF-Token,X-Api-Key"
)

// corsMiddleware reproduces the reference's dynamic CORS layer.
//
// Three details are the contract rather than taste, and a browser client
// notices all three:
//
//   - With no configured origins there is no middleware at all — not a
//     permissive one. The reference mounts cors() only when
//     options.cors.origins is non-empty (auth.router.ts:513), so a deployment
//     that declares none must not start answering preflights.
//   - Vary: Origin is set on every response, including the ones that get no
//     Access-Control-Allow-Origin, because the response body still varies by
//     origin and a shared cache must not serve one origin's response to
//     another.
//   - OPTIONS short-circuits to 204 whether or not the origin matched
//     (preflightContinue is false), which is also what keeps a preflight from
//     reaching the mux and collecting a 405.
//
// Access-Control-Allow-Origin echoes the request origin rather than emitting a
// list: the header takes exactly one origin, and Allow-Credentials is true, so
// the wildcard is not an option here even if the allowlist has one entry.
//
// exempt names mounts the layer leaves entirely alone — no Vary, no
// Allow-Origin, no OPTIONS short-circuit — because the reference mounts its CORS
// layer inside the auth router and its sibling routers carry none of it
// (corsExemptMounts, app.go). A path is exempt when it is the mount or below it.
func corsMiddleware(origins []string, exempt ...string) func(http.Handler) http.Handler {
	if len(origins) == 0 {
		return func(next http.Handler) http.Handler { return next }
	}

	allowed := make(map[string]struct{}, len(origins))
	for _, o := range origins {
		allowed[o] = struct{}{}
	}
	outside := func(path string) bool {
		for _, mount := range exempt {
			if path == mount || strings.HasPrefix(path, mount+"/") {
				return true
			}
		}
		return false
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if outside(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}
			w.Header().Add("Vary", "Origin")

			if origin := r.Header.Get("Origin"); origin != "" {
				if _, ok := allowed[origin]; ok {
					h := w.Header()
					h.Set("Access-Control-Allow-Origin", origin)
					h.Set("Access-Control-Allow-Credentials", "true")
					h.Set("Access-Control-Allow-Methods", corsAllowMethods)
					h.Set("Access-Control-Allow-Headers", corsAllowHeaders)
				}
			}

			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

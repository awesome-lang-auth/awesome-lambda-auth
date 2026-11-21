package contract

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"
)

// body is a JSON request body. Nil means "send no body at all", which is a
// distinct case on the wire: POST /refresh must work with no body in cookie mode
// (wire-contract.md hard point 3).
type body map[string]any

// Client is one client identity: its own cookie jar, so a case can hold several
// independent sessions at once (a cookie client and a bearer client, or a
// revoked session and a live one) without them contaminating each other.
type Client struct {
	env  *Env
	http *http.Client
	jar  *cookiejar.Jar
}

func (e *Env) NewClient() *Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		panic(err)
	}
	return &Client{
		env: e,
		jar: jar,
		http: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			// Redirects are part of the contract on the OAuth routes; following
			// them silently would hide the Location header from an assertion.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// ---------------------------------------------------------------------------
// Request options
// ---------------------------------------------------------------------------

type reqOpt func(*http.Request, *Client)

// Bearer presents an access token the way a native client does.
func Bearer(token string) reqOpt {
	return func(r *http.Request, _ *Client) { r.Header.Set("Authorization", "Bearer "+token) }
}

// Header sets a raw header. The literal is written out at every call site on
// purpose: the point of this suite is to catch a change in the literal, so
// importing a constant for it would defeat the test.
func Header(k, v string) reqOpt {
	return func(r *http.Request, _ *Client) { r.Header.Set(k, v) }
}

// BearerStrategy opts into bearer responses. Exact, case-sensitive value match
// (hard point 8).
func BearerStrategy() reqOpt { return Header("X-Auth-Strategy", "bearer") }

// CSRF copies the client's current csrf-token cookie into the X-CSRF-Token
// header — the double-submit a browser client performs. A client with no such
// cookie sends no header, which is exactly what a csrf-disabled deployment
// should see.
func CSRF() reqOpt {
	return func(r *http.Request, c *Client) {
		if v := c.CookieValue("csrf-token"); v != "" {
			r.Header.Set("X-CSRF-Token", v)
		}
	}
}

// RawCSRF sends a chosen value, for the mismatch case.
func RawCSRF(v string) reqOpt { return Header("X-CSRF-Token", v) }

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

func (c *Client) GET(t *testing.T, path string, opts ...reqOpt) *Resp {
	t.Helper()
	return c.do(t, http.MethodGet, path, nil, opts)
}

func (c *Client) POST(t *testing.T, path string, b body, opts ...reqOpt) *Resp {
	t.Helper()
	return c.do(t, http.MethodPost, path, b, opts)
}

func (c *Client) DELETE(t *testing.T, path string, opts ...reqOpt) *Resp {
	t.Helper()
	return c.do(t, http.MethodDelete, path, nil, opts)
}

// form posts an application/x-www-form-urlencoded body.
//
// It is the one request shape in this suite that is not JSON, and it exists for
// one surface: the OIDC token endpoint takes client_secret_post, which RFC 6749
// §4.1.3 defines as form parameters, and the authorization endpoint's login post
// is a form submission. Sending JSON there would be refused for the wrong
// reason and would prove nothing about the endpoint.
func (c *Client) form(t *testing.T, path string, values url.Values) *Resp {
	t.Helper()
	return c.send(t, http.MethodPost, path, []byte(values.Encode()), "application/x-www-form-urlencoded", nil)
}

func (c *Client) do(t *testing.T, method, path string, b body, opts []reqOpt) *Resp {
	t.Helper()
	var raw []byte
	contentType := ""
	if b != nil {
		var err error
		raw, err = json.Marshal(b)
		if err != nil {
			t.Fatalf("marshal request body for %s %s: %v", method, c.env.URL(path), err)
		}
		contentType = "application/json"
	}
	return c.send(t, method, path, raw, contentType, opts)
}

// send is the one place a request is built and issued. body is nil for "send no
// body at all", which is a distinct case on the wire.
func (c *Client) send(t *testing.T, method, path string, raw []byte, contentType string, opts []reqOpt) *Resp {
	t.Helper()
	target := c.env.URL(path)

	var reader io.Reader
	if raw != nil {
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, target, reader)
	if err != nil {
		t.Fatalf("build request %s %s: %v", method, target, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	for _, o := range opts {
		o(req, c)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("%s %s: read body: %v", method, target, err)
	}

	return &Resp{
		Method:    method,
		Target:    target,
		Status:    resp.StatusCode,
		Header:    resp.Header,
		Body:      payload,
		SetCookie: resp.Header.Values("Set-Cookie"),
		cookies:   resp.Cookies(),
	}
}

// CookieValue returns the jar's value for a cookie base name, resolving the
// documented read priority __Host- > __Secure- > bare (§0.3).
func (c *Client) CookieValue(base string) string {
	u, err := url.Parse(c.env.BaseURL + c.env.Prefix + "/")
	if err != nil {
		return ""
	}
	got := map[string]string{}
	for _, ck := range c.jar.Cookies(u) {
		got[ck.Name] = ck.Value
	}
	for _, n := range []string{"__Host-" + base, "__Secure-" + base, base} {
		if v, ok := got[n]; ok {
			return v
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Responses
// ---------------------------------------------------------------------------

type Resp struct {
	Method    string
	Target    string
	Status    int
	Header    http.Header
	Body      []byte
	SetCookie []string
	cookies   []*http.Cookie
}

func (r *Resp) snippet() string {
	s := strings.TrimSpace(string(r.Body))
	if len(s) > 400 {
		s = s[:400] + "…"
	}
	return s
}

// where identifies the exchange in every failure message, so a report can be
// read without re-running anything.
func (r *Resp) where() string {
	return fmt.Sprintf("%s %s -> %d %s", r.Method, r.Target, r.Status, r.snippet())
}

func (r *Resp) mustStatus(t *testing.T, want int) *Resp {
	t.Helper()
	if r.Status != want {
		t.Fatalf("want status %d, got %d\n  %s", want, r.Status, r.where())
	}
	return r
}

// mustStatusIn is for the paths where the reference itself allows more than one
// answer — never as a way to soften an assertion that has one right answer.
func (r *Resp) mustStatusIn(t *testing.T, want ...int) *Resp {
	t.Helper()
	for _, w := range want {
		if r.Status == w {
			return r
		}
	}
	t.Fatalf("want one of status %v, got %d\n  %s", want, r.Status, r.where())
	return r
}

func (r *Resp) obj(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("body is not a JSON object (%v)\n  %s", err, r.where())
	}
	return m
}

func (r *Resp) str(t *testing.T, key string) string {
	t.Helper()
	v, ok := r.obj(t)[key]
	if !ok {
		t.Fatalf("body has no %q field\n  %s", key, r.where())
	}
	s, ok := v.(string)
	if !ok {
		t.Fatalf("field %q is %T, want string\n  %s", key, v, r.where())
	}
	return s
}

func (r *Resp) hasKey(t *testing.T, key string) bool {
	t.Helper()
	_, ok := r.obj(t)[key]
	return ok
}

// mustError pins a coded error body: {"error":"<message>","code":"<CODE>"} and
// nothing else. handleError builds the body from exactly those two fields
// (§0.1, §4.1 — `res.status(err.statusCode).json({ error: err.message, code:
// err.code })`), so a third field is a divergence, and the field that turns up
// there will be the one a handler leaked: an internal message, a stack, a
// user id. Both literals are written out at the call site deliberately.
func (r *Resp) mustError(t *testing.T, status int, code, message string) {
	t.Helper()
	r.mustStatus(t, status)
	m := r.obj(t)
	if got := m["code"]; got != code {
		t.Errorf("want error code %q, got %v\n  %s", code, got, r.where())
	}
	if message != "" {
		if got := m["error"]; got != message {
			t.Errorf("want error message %q, got %v\n  %s", message, got, r.where())
		}
	}
	mustErrorKeys(t, r, m, "code", "error")
}

// mustCodelessError pins the bodies §4.4 says carry no `code` at all. Clients
// pattern-matching on `code` must not start seeing one, and must not stop
// seeing one where there is.
func (r *Resp) mustCodelessError(t *testing.T, status int, message string) {
	t.Helper()
	r.mustStatus(t, status)
	m := r.obj(t)
	if _, ok := m["code"]; ok {
		t.Errorf("body carries a `code` field, and this path is documented as code-less (wire-contract.md §4.4)\n  %s", r.where())
	}
	if message != "" {
		if got := m["error"]; got != message {
			t.Errorf("want error message %q, got %v\n  %s", message, got, r.where())
		}
	}
	mustErrorKeys(t, r, m, "error")
}

// mustErrorKeys pins the whole key set of an error body, not just the fields
// the caller happened to name. An assertion that only looks at the fields it
// expects cannot see the field it did not.
func mustErrorKeys(t *testing.T, r *Resp, m map[string]any, want ...string) {
	t.Helper()
	allowed := map[string]bool{}
	for _, k := range want {
		allowed[k] = true
	}
	var extra []string
	for k := range m {
		if !allowed[k] {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		t.Errorf("error body carries %v on top of %v; handleError emits those fields and no others (§0.1)\n  %s",
			extra, want, r.where())
	}
}

// mustSuccessOnly pins the cookie-mode success body: {"success":true} and
// nothing else — in particular no token ever reaches a cookie-mode body (§2).
func (r *Resp) mustSuccessOnly(t *testing.T) {
	t.Helper()
	r.mustStatus(t, 200)
	m := r.obj(t)
	if m["success"] != true {
		t.Errorf(`want "success":true, got %v\n  %s`, m["success"], r.where())
	}
	for _, forbidden := range []string{"accessToken", "refreshToken", "token", "tokens"} {
		if _, ok := m[forbidden]; ok {
			t.Errorf("cookie-mode body carries %q; tokens belong in cookies here and in the body only under X-Auth-Strategy: bearer\n  %s",
				forbidden, r.where())
		}
	}
	if len(m) != 1 {
		t.Errorf("want a body of exactly {\"success\":true}, got %d fields: %v\n  %s", len(m), keysOf(m), r.where())
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

// Account is a set of credentials the suite created for itself, or the realm
// account the operator declared (realm_test.go).
type Account struct {
	Email    string
	Password string
	UserID   string
	// TOTPSecret is the base32 secret the account is enrolled with, when it
	// is; Env.signIn completes a challenge with it.
	TOTPSecret string
}

func randomAccount() Account {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	// .invalid is reserved by RFC 2606 and resolves nowhere, so a deployment
	// with a live mailer cannot be made to send real mail by running this suite.
	return Account{
		Email:    fmt.Sprintf("contract-%d-%s@contract.invalid", time.Now().UnixNano(), hex.EncodeToString(b[:])),
		Password: "Contract-Suite-Passw0rd!",
	}
}

// NewAccount registers a fresh account through a throwaway client, so whatever
// credentials registration may hand back never leak into the caller's jar.
//
// On a realm declared closed or 2FA-required it skips the case instead: every
// caller registers through the route a closed realm refuses, or signs the
// account in with a password alone, which a 2FA-required realm refuses — so
// the case was written for an open realm and says so rather than failing. The
// runner lists the skip with its reason.
func (e *Env) NewAccount(t *testing.T) Account {
	t.Helper()
	if e.Realm.restricted() {
		e.realmSkip = fmt.Sprintf("provisions an account of its own and signs it in with a password, which a realm declared %s does not allow",
			e.Realm.describe())
		t.Skipf("this case %s; it runs against an open realm with an optional second factor", e.realmSkip)
	}
	acct := randomAccount()
	r := e.NewClient().POST(t, "/register", body{"email": acct.Email, "password": acct.Password})
	r.mustStatusIn(t, 200, 201)
	if id, ok := r.obj(t)["userId"].(string); ok {
		acct.UserID = id
	}
	return acct
}

// LoginCookie provisions an account and logs it in in cookie mode, returning a
// client holding the session.
func (e *Env) LoginCookie(t *testing.T) (*Client, Account) {
	t.Helper()
	acct := e.NewAccount(t)
	c := e.NewClient()
	c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}).mustStatus(t, 200)
	return c, acct
}

// LoginBearer provisions an account and logs it in in bearer mode, returning the
// access token. The client it used keeps no cookies, because a bearer login sets
// none.
func (e *Env) LoginBearer(t *testing.T) (*Client, Account, string) {
	t.Helper()
	acct := e.NewAccount(t)
	c := e.NewClient()
	r := c.POST(t, "/login", body{"email": acct.Email, "password": acct.Password}, BearerStrategy())
	r.mustStatus(t, 200)
	return c, acct, r.str(t, "accessToken")
}

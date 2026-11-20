package lambdahttp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
)

// proxyRequest is the transport-neutral shape every supported event is reduced
// to before an *http.Request is built. Keeping the per-shape knowledge in the
// four small constructors below means the fiddly parts — path escaping, body
// decoding, TLS detection, stage stripping — are written once.
type proxyRequest struct {
	kind Kind

	method string

	// path is the request path as the event delivered it. pathEncoded says
	// whether it is percent-encoded (v2, Function URL, and ALB by default) or
	// already decoded (API Gateway REST, which decodes before invoking).
	path        string
	pathEncoded bool

	// rawQuery is a ready-to-use, percent-encoded query string without the
	// leading '?'.
	rawQuery string

	// header already includes the Cookie header reconstructed from the
	// v2/Function URL "cookies" array, which never arrives as a Cookie header.
	header http.Header

	body     string
	isBase64 bool

	sourceIP     string
	proto        string
	hostFallback string
	stage        string

	// defaultTLS is the answer when no X-Forwarded-Proto header is present.
	// API Gateway and Function URLs are HTTPS-only; an ALB listener may be
	// plain HTTP.
	defaultTLS bool

	event any
}

func v2ProxyRequest(e events.APIGatewayV2HTTPRequest, opts Options) *proxyRequest {
	h := headerFromSingleValueMap(e.Headers, opts.splitSet())
	addCookieHeader(h, e.Cookies)
	path := e.RawPath
	if path == "" {
		path = e.RequestContext.HTTP.Path
	}
	return &proxyRequest{
		kind:         KindAPIGatewayV2,
		method:       e.RequestContext.HTTP.Method,
		path:         path,
		pathEncoded:  true,
		rawQuery:     strings.TrimPrefix(e.RawQueryString, "?"),
		header:       h,
		body:         e.Body,
		isBase64:     e.IsBase64Encoded,
		sourceIP:     e.RequestContext.HTTP.SourceIP,
		proto:        e.RequestContext.HTTP.Protocol,
		hostFallback: e.RequestContext.DomainName,
		stage:        e.RequestContext.Stage,
		defaultTLS:   true,
		event:        e,
	}
}

func functionURLProxyRequest(e events.LambdaFunctionURLRequest, opts Options) *proxyRequest {
	h := headerFromSingleValueMap(e.Headers, opts.splitSet())
	addCookieHeader(h, e.Cookies)
	path := e.RawPath
	if path == "" {
		path = e.RequestContext.HTTP.Path
	}
	return &proxyRequest{
		kind:         KindFunctionURL,
		method:       e.RequestContext.HTTP.Method,
		path:         path,
		pathEncoded:  true,
		rawQuery:     strings.TrimPrefix(e.RawQueryString, "?"),
		header:       h,
		body:         e.Body,
		isBase64:     e.IsBase64Encoded,
		sourceIP:     e.RequestContext.HTTP.SourceIP,
		proto:        e.RequestContext.HTTP.Protocol,
		hostFallback: e.RequestContext.DomainName,
		// Function URLs always serve at the root; there is no stage segment.
		defaultTLS: true,
		event:      e,
	}
}

func restProxyRequest(e events.APIGatewayProxyRequest, opts Options) *proxyRequest {
	h := headerFromEventMaps(e.MultiValueHeaders, e.Headers, opts.splitSet())
	return &proxyRequest{
		kind:   KindAPIGatewayREST,
		method: e.HTTPMethod,
		// REST APIs URL-decode the path before invoking, so it must not be
		// unescaped again.
		path:         e.Path,
		pathEncoded:  false,
		rawQuery:     buildQuery(e.MultiValueQueryStringParameters, e.QueryStringParameters, false),
		header:       h,
		body:         e.Body,
		isBase64:     e.IsBase64Encoded,
		sourceIP:     e.RequestContext.Identity.SourceIP,
		proto:        e.RequestContext.Protocol,
		hostFallback: e.RequestContext.DomainName,
		stage:        e.RequestContext.Stage,
		defaultTLS:   true,
		event:        e,
	}
}

func albProxyRequest(e events.ALBTargetGroupRequest, opts Options) *proxyRequest {
	h := headerFromEventMaps(e.MultiValueHeaders, e.Headers, opts.splitSet())
	return &proxyRequest{
		kind:        KindALB,
		method:      e.HTTPMethod,
		path:        e.Path,
		pathEncoded: !opts.ALBInputDecoded,
		rawQuery:    buildQuery(e.MultiValueQueryStringParameters, e.QueryStringParameters, !opts.ALBInputDecoded),
		header:      h,
		body:        e.Body,
		isBase64:    e.IsBase64Encoded,
		// ALB events carry no sourceIp; the client address is the first
		// X-Forwarded-For entry, resolved in newHTTPRequest.
		// An ALB listener may be plain HTTP, so do not assume TLS.
		defaultTLS: false,
		event:      e,
	}
}

// newHTTPRequest turns a normalised proxyRequest into an *http.Request shaped
// the way net/http's own server would shape it: Host lifted out of the header
// map, RemoteAddr as host:port, RequestURI matching URL, and a non-nil Body.
func newHTTPRequest(ctx context.Context, pr *proxyRequest, opts Options) (*http.Request, error) {
	body, err := decodeBody(pr.body, pr.isBase64)
	if err != nil {
		return nil, err
	}

	u, err := buildURL(pr.path, pr.rawQuery, pr.pathEncoded)
	if err != nil {
		return nil, err
	}
	stripStagePrefix(u, stagePrefixFor(pr, opts))

	if pr.header == nil {
		pr.header = make(http.Header)
	}

	host := pr.header.Get("Host")
	if host == "" {
		host = pr.hostFallback
	}
	// net/http's server keeps the Host outside the header map.
	pr.header.Del("Host")

	if len(body) > 0 {
		pr.header.Set("Content-Length", strconv.Itoa(len(body)))
	} else {
		pr.header.Del("Content-Length")
	}

	proto, major, minor := parseProto(pr.proto)

	method := pr.method
	if method == "" {
		method = http.MethodGet
	}

	req := &http.Request{
		Method:        method,
		URL:           u,
		Proto:         proto,
		ProtoMajor:    major,
		ProtoMinor:    minor,
		Header:        pr.header,
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
		Host:          host,
		RequestURI:    u.RequestURI(),
		RemoteAddr:    remoteAddr(pr),
	}

	if requestIsTLS(pr.header, pr.defaultTLS) {
		req.TLS = &tls.ConnectionState{
			HandshakeComplete: true,
			ServerName:        host,
		}
	}

	return req.WithContext(withEvent(ctx, pr.event)), nil
}

// eventKey is the context key under which the originating event is stored.
type eventKey struct{}

func withEvent(ctx context.Context, event any) context.Context {
	if event == nil {
		return ctx
	}
	return context.WithValue(ctx, eventKey{}, event)
}

// EventFrom returns the Lambda event a request was normalised from, or nil when
// the context did not come through this package. The concrete type is one of
// events.APIGatewayV2HTTPRequest, events.APIGatewayProxyRequest,
// events.LambdaFunctionURLRequest or events.ALBTargetGroupRequest, so handlers
// that need authorizer claims or the request context can type-switch on it.
func EventFrom(ctx context.Context) any {
	if ctx == nil {
		return nil
	}
	return ctx.Value(eventKey{})
}

// WithoutEventHeader returns ctx with the event EventFrom reports replaced by a
// copy that no longer carries the header name, compared case-insensitively, in
// Headers or in MultiValueHeaders. The original event is not modified; ctx is
// returned as it is when it carries no event, or one of a type this package
// does not produce.
//
// A middleware that strips a header from the request it hands on — a secret
// the front door sends, for example — calls it too, so that a handler reading
// the raw event cannot find there what the request no longer carries.
func WithoutEventHeader(ctx context.Context, name string) context.Context {
	event := EventFrom(ctx)
	if event == nil {
		return ctx
	}
	var scrubbed any
	switch e := event.(type) {
	case events.APIGatewayV2HTTPRequest:
		e.Headers = withoutHeader(e.Headers, name)
		scrubbed = e
	case *events.APIGatewayV2HTTPRequest:
		c := *e
		c.Headers = withoutHeader(c.Headers, name)
		scrubbed = &c
	case events.APIGatewayProxyRequest:
		e.Headers = withoutHeader(e.Headers, name)
		e.MultiValueHeaders = withoutMultiHeader(e.MultiValueHeaders, name)
		scrubbed = e
	case *events.APIGatewayProxyRequest:
		c := *e
		c.Headers = withoutHeader(c.Headers, name)
		c.MultiValueHeaders = withoutMultiHeader(c.MultiValueHeaders, name)
		scrubbed = &c
	case events.LambdaFunctionURLRequest:
		e.Headers = withoutHeader(e.Headers, name)
		scrubbed = e
	case *events.LambdaFunctionURLRequest:
		c := *e
		c.Headers = withoutHeader(c.Headers, name)
		scrubbed = &c
	case events.ALBTargetGroupRequest:
		e.Headers = withoutHeader(e.Headers, name)
		e.MultiValueHeaders = withoutMultiHeader(e.MultiValueHeaders, name)
		scrubbed = e
	case *events.ALBTargetGroupRequest:
		c := *e
		c.Headers = withoutHeader(c.Headers, name)
		c.MultiValueHeaders = withoutMultiHeader(c.MultiValueHeaders, name)
		scrubbed = &c
	default:
		return ctx
	}
	return context.WithValue(ctx, eventKey{}, scrubbed)
}

// withoutHeader returns a copy of headers without name, compared
// case-insensitively; headers itself is left alone, since the event that owns
// it may still be read elsewhere. A map without the header is returned as it
// is.
func withoutHeader(headers map[string]string, name string) map[string]string {
	found := false
	for k := range headers {
		if strings.EqualFold(k, name) {
			found = true
			break
		}
	}
	if !found {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		if !strings.EqualFold(k, name) {
			out[k] = v
		}
	}
	return out
}

// withoutMultiHeader is withoutHeader for a multi-value header map.
func withoutMultiHeader(headers map[string][]string, name string) map[string][]string {
	found := false
	for k := range headers {
		if strings.EqualFold(k, name) {
			found = true
			break
		}
	}
	if !found {
		return headers
	}
	out := make(map[string][]string, len(headers))
	for k, v := range headers {
		if !strings.EqualFold(k, name) {
			out[k] = v
		}
	}
	return out
}

// decodeBody returns the raw request body bytes, base64-decoding when the event
// says the body is encoded.
func decodeBody(body string, isBase64Encoded bool) ([]byte, error) {
	if body == "" {
		return nil, nil
	}
	if !isBase64Encoded {
		return []byte(body), nil
	}
	raw, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("%w: decode base64 body: %w", ErrBadRequestEvent, err)
	}
	return raw, nil
}

// buildURL assembles the request URL. When the path is percent-encoded it is
// unescaped into URL.Path with the original kept in URL.RawPath, so
// URL.EscapedPath — and therefore RequestURI — round-trips byte for byte. When
// the path is already decoded it is used verbatim and Go re-escapes it on
// output.
func buildURL(path, rawQuery string, encoded bool) (*url.URL, error) {
	if path == "" {
		path = "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	u := &url.URL{RawQuery: rawQuery}
	if !encoded {
		u.Path = path
		return u, nil
	}

	unescaped, err := url.PathUnescape(path)
	if err != nil {
		// A malformed escape is not worth failing the request over: fall back
		// to treating the path as a literal, which is what a decoded-path
		// integration would have sent anyway.
		u.Path = path
		return u, nil
	}
	u.Path = unescaped
	// URL.EscapedPath keeps RawPath only when it is a valid encoding of Path,
	// so this cannot smuggle a '?' or '#' into the path.
	u.RawPath = path
	return u, nil
}

// stagePrefixFor resolves the path prefix to strip. Nothing is ever guessed:
// either the operator named a prefix, or they opted into using the event's own
// stage. "$default" is never a real path segment.
func stagePrefixFor(pr *proxyRequest, opts Options) string {
	prefix := opts.StagePrefix
	if prefix == "" && opts.StripStageFromEvent {
		prefix = pr.stage
	}
	prefix = strings.Trim(prefix, "/")
	if prefix == "" || prefix == "$default" {
		return ""
	}
	return "/" + prefix
}

// stripStagePrefix removes prefix from the front of the URL path, keeping Path
// and RawPath consistent. A path equal to the prefix becomes "/".
func stripStagePrefix(u *url.URL, prefix string) {
	if prefix == "" {
		return
	}
	trimmed, ok := trimPathPrefix(u.Path, prefix)
	if !ok {
		return
	}
	u.Path = trimmed
	if u.RawPath != "" {
		if rawTrimmed, rawOK := trimPathPrefix(u.RawPath, prefix); rawOK {
			u.RawPath = rawTrimmed
		} else {
			// Escaped and unescaped forms disagree; let Go re-derive the
			// escaped path from Path rather than emit a mismatched pair.
			u.RawPath = ""
		}
	}
}

func trimPathPrefix(path, prefix string) (string, bool) {
	switch {
	case path == prefix:
		return "/", true
	case strings.HasPrefix(path, prefix+"/"):
		return path[len(prefix):], true
	default:
		return path, false
	}
}

// headerFromEventMaps prefers the multi-value map, which AWS only populates
// when the integration has multi-value headers enabled and which already keeps
// repeated headers apart. The two maps are never merged: they carry the same
// headers and merging would duplicate every one of them.
func headerFromEventMaps(multi map[string][]string, single map[string]string, split map[string]struct{}) http.Header {
	if len(multi) > 0 {
		h := make(http.Header, len(multi))
		for _, k := range slices.Sorted(maps.Keys(multi)) {
			key := textproto.CanonicalMIMEHeaderKey(k)
			for _, v := range multi[k] {
				appendHeaderValue(h, key, v, split)
			}
		}
		return h
	}
	return headerFromSingleValueMap(single, split)
}

// headerFromSingleValueMap canonicalises AWS's lowercased single-value header
// map into an http.Header, splitting the configured headers back apart where
// AWS comma-joined repeated values.
func headerFromSingleValueMap(m map[string]string, split map[string]struct{}) http.Header {
	h := make(http.Header, len(m))
	// Sorted so that two source keys differing only in case land in a
	// deterministic order after canonicalisation.
	for _, k := range slices.Sorted(maps.Keys(m)) {
		appendHeaderValue(h, textproto.CanonicalMIMEHeaderKey(k), m[k], split)
	}
	return h
}

// appendHeaderValue appends one event value under an already-canonical key,
// splitting it on commas when the header is in the configured split set.
//
// The split is needed in the multi-value map as well as the single-value one: a
// multiValueHeaders entry is one array element per header LINE, so a client (or
// an upstream proxy such as CloudFront) that sends one line holding a
// comma-separated list still delivers a single element. AWS's own proxy
// integration example spells this out — `-H 'header3: value1,value2'` arrives
// as "multiValueHeaders": {"header3": ["value1,value2"]} — and the motivating
// case, x-forwarded-proto: https,https behind CloudFront, reaches an ALB target
// group whose multi-value attribute is on precisely because that is the only
// mode that can return more than one Set-Cookie.
func appendHeaderValue(h http.Header, key, value string, split map[string]struct{}) {
	if _, ok := split[key]; ok && strings.Contains(value, ",") {
		for _, part := range strings.Split(value, ",") {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			h[key] = append(h[key], part)
		}
		return
	}
	h[key] = append(h[key], value)
}

// addCookieHeader rebuilds the Cookie request header from the v2/Function URL
// "cookies" array. Without it http.Request.Cookie() finds nothing, because
// those payloads never send a Cookie header.
func addCookieHeader(h http.Header, cookies []string) {
	parts := make([]string, 0, len(cookies)+1)
	if existing := strings.TrimSpace(h.Get("Cookie")); existing != "" {
		parts = append(parts, existing)
	}
	for _, c := range cookies {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		parts = append(parts, c)
	}
	if len(parts) == 0 {
		return
	}
	// RFC 6265 §5.4: one Cookie header, pairs separated by "; ".
	h.Set("Cookie", strings.Join(parts, "; "))
}

// buildQuery renders the v1/ALB query-string maps into an encoded query string.
// The multi-value map wins when present. preEncoded passes values through
// untouched (ALB delivers them percent-encoded); otherwise they are escaped,
// because API Gateway hands them over decoded.
func buildQuery(multi map[string][]string, single map[string]string, preEncoded bool) string {
	var keys []string
	var valuesOf func(string) []string

	switch {
	case len(multi) > 0:
		keys = slices.Sorted(maps.Keys(multi))
		valuesOf = func(k string) []string { return multi[k] }
	case len(single) > 0:
		keys = slices.Sorted(maps.Keys(single))
		valuesOf = func(k string) []string { return []string{single[k]} }
	default:
		return ""
	}

	var b strings.Builder
	for _, k := range keys {
		for _, v := range valuesOf(k) {
			if b.Len() > 0 {
				b.WriteByte('&')
			}
			if preEncoded {
				b.WriteString(k)
				b.WriteByte('=')
				b.WriteString(v)
				continue
			}
			b.WriteString(url.QueryEscape(k))
			b.WriteByte('=')
			b.WriteString(url.QueryEscape(v))
		}
	}
	return b.String()
}

// requestIsTLS reports whether the original client connection was HTTPS.
// X-Forwarded-Proto wins when present; behind CloudFront it may itself be a
// comma-joined list whose first entry is the client-facing scheme.
func requestIsTLS(h http.Header, fallback bool) bool {
	proto := h.Get("X-Forwarded-Proto")
	if proto == "" {
		return fallback
	}
	first, _, _ := strings.Cut(proto, ",")
	return strings.EqualFold(strings.TrimSpace(first), "https")
}

// remoteAddr renders the client address as host:port, the form net/http uses
// and net.SplitHostPort expects. ALB events carry no source IP of their own, so
// the first X-Forwarded-For entry is used.
func remoteAddr(pr *proxyRequest) string {
	ip := strings.TrimSpace(pr.sourceIP)
	if ip == "" {
		if xff := pr.header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			ip = strings.TrimSpace(first)
		}
	}
	if ip == "" {
		return ""
	}
	// No event shape reports the client's ephemeral port, and X-Forwarded-Port
	// is the load balancer's listener port, not the client's. Report 0 rather
	// than something plausible but wrong; the host half is what callers read.
	return net.JoinHostPort(ip, "0")
}

func parseProto(proto string) (string, int, int) {
	if proto != "" {
		if major, minor, ok := http.ParseHTTPVersion(proto); ok {
			return proto, major, minor
		}
	}
	return "HTTP/1.1", 1, 1
}

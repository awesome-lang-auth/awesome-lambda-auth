package aws

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// The upload store: auth.UploadStore over one S3 prefix.
//
// It is the serverless answer to the reference's `uploadDir`
// (admin.router.ts:991-1085, ui.router.ts:185-191), which is a directory on a
// local disk that the admin router writes into with multer and the UI router
// serves back with express.static. A Lambda has no such directory — /var/task
// is read-only and /tmp is per execution environment and emptied without
// warning — so the core made the seam an interface (upload_store.go) and left
// the durable implementation to the host. This is it, and config-schema.md
// §1.12 already said where it would point: "serverless target is an S3
// location".
//
// One store serves both halves of the reference's arrangement, because the core
// composes them: the four admin upload routes write through Put, List and
// Delete, and (*Auth).UIHandler serves <prefix>/ui/assets/logo/ and
// <prefix>/ui/assets/uploads/ from Open through auth.UploadFS when
// UIOptions.Uploads is nil. So cmd/auth wires exactly one thing — this store,
// through auth.WithUploadStore — and the UI's read side follows without a
// second configuration (cmd/auth/admin.go, ui.go).
//
// # The rules the seam states, and how each is met here
//
//   - Every key satisfies auth.ValidUploadKey. The core checks before every
//     call it makes, and this store checks again on every method, because it
//     is also reachable by a host calling it directly and the grammar is the
//     only thing standing between a key and the bucket's namespace: no key
//     contains '/', so prefix + key is one object below the prefix by
//     construction, never a second "directory" and never a sibling of it.
//   - Put reads content to EOF and leaves nothing behind on failure. S3 makes
//     the second half free: a PutObject either creates the whole object or
//     nothing — there is no partial object to clean up and no temporary key to
//     rename — so a reader that fails halfway yields a failed PutObject and an
//     unchanged bucket.
//   - Content-Type is recorded at write time with auth.UploadContentType. An
//     S3 object stored without one is served as binary/octet-stream forever
//     after, and no browser paints a logo it is handed under that type; the
//     core exports the table for exactly this reason.
//   - List is newest first, ties broken by key ascending, applied with the
//     core's own auth.SortUploadedFiles over what ListObjectsV2 returned in
//     key order. Objects under the prefix whose name is not a valid key — put
//     there by something other than this store — are left out, the way the
//     reference's readdirSync filter leaves out a stray .DS_Store.
//   - Open and Delete answer auth.ErrUploadNotFound for an absent key, and
//     nothing else for it: the 404s of GET <prefix>/ui/assets/uploads/x and
//     DELETE <admin>/api/upload/x depend on that sentinel, and auth.UploadFS
//     maps it to fs.ErrNotExist so that a real store failure stays a 500
//     rather than a miss.
//
// # Delete is two calls, and the reason is the reference's own race
//
// S3's DeleteObject is idempotent: deleting a key that is not there answers
// 204 exactly as deleting one that is. The seam wants a 404 for an absent key,
// so this store asks first — HeadObject, then DeleteObject. The reference does
// the same two steps (existsSync, then unlinkSync, admin.router.ts:1074-1080)
// and the core's comment on ErrUploadNotFound names the race that pair has:
// two administrators deleting the same file, where the second's unlink throws
// and the route answers 500. What the seam asks for in that race is the
// sentinel — "Delete removes one object and returns ErrUploadNotFound if there
// was none", because a 404 for the loser is better than a 500 — and this store
// gives it in the common ordering: the loser's HeadObject runs after the
// winner's DeleteObject landed, finds nothing, and answers ErrUploadNotFound.
// In the narrow interleaving where both HeadObjects run before either delete,
// the loser's DeleteObject succeeds too — the delete is idempotent — and both
// callers are answered "deleted". That is not what the seam asks for, and it
// is said here rather than claimed otherwise; it is still not the reference's
// 500, the object is gone either way, and closing it would take a conditional
// delete S3 only offers on versioned or ETag-matched requests, for a window
// two people have to hit within one round trip of each other.
//
// # What Open does not do
//
// It does not return a seeker. GetObject's body is a stream, and turning it
// into an io.ReadSeeker would mean buffering the object here to save the UI
// buffering it there; the UI reads a non-seekable body into memory before
// serving it, bounded by auth.UploadMaxBytes for anything the routes wrote, and
// answers Range requests from that copy. For a five-megabyte ceiling that is
// the right trade. It does carry a deadline of its own, because auth.UploadFS
// calls Open with context.Background() — fs.FS.Open takes no context — and a
// GetObject with no deadline on the request path of every page that shows a
// logo is a hung page rather than a slow one. See Options.ReadTimeout.
//
// # Cost, so the cold-start log and docs/cost-model.md can say it
//
// Put is one PutObject; List is one ListObjectsV2 per thousand objects; Open is
// one GetObject, and it is Open that is on the request path — once per page
// view that shows the logo, misses included, because every miss is a GetObject
// that answers 404. Delete is a HeadObject and a DeleteObject. The bucket's
// standing cost is its storage, cents for a few logos.

// S3API is the five calls this store makes, and nothing else. Declared here so
// a test injects a fake, as SESAPI and SNSAPI are, and so the IAM statement in
// infra/sam/template.yaml can be read off the interface: GetObject, PutObject,
// DeleteObject and ListBucket, on one bucket's objects and on the bucket itself
// for the listing.
type S3API interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	HeadObject(ctx context.Context, in *s3.HeadObjectInput, optFns ...func(*s3.Options)) (*s3.HeadObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, optFns ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
	ListObjectsV2(ctx context.Context, in *s3.ListObjectsV2Input, optFns ...func(*s3.Options)) (*s3.ListObjectsV2Output, error)
}

// S3UploadOptions configures NewS3UploadStore.
type S3UploadOptions struct {
	// Bucket is the bucket the objects live in. Required.
	Bucket string

	// Prefix is the key prefix every object is written under, with or without
	// a trailing slash; empty writes at the bucket root. It is what lets one
	// bucket hold more than this store's objects without the listing seeing
	// them, and what the S3 location's path segment becomes.
	Prefix string

	// Region overrides the region the default chain resolves. Empty uses
	// AWS_REGION. An S3 bucket is regional and a client addressing it from the
	// wrong region is redirected, which the SDK follows at the cost of a round
	// trip; the stack passes the function's own region.
	Region string

	// ReadTimeout bounds Open when its context carries no deadline, which is
	// the case for every call auth.UploadFS makes. Zero means
	// DefaultS3ReadTimeout.
	ReadTimeout time.Duration

	// Client injects an S3API. Non-nil skips the lazy build.
	Client S3API

	// Now is the clock the Put answer is stamped with; nil is time.Now.
	Now func() time.Time
}

// DefaultS3ReadTimeout is the deadline Open applies when it is handed a context
// without one. Ten seconds is far longer than a GetObject of a five-megabyte
// object takes from inside the region, and far shorter than the function's own
// timeout, so a stalled read fails the one page rather than the invocation.
const DefaultS3ReadTimeout = 10 * time.Second

// ParseS3Location reads the `s3://<bucket>[/<prefix>]` form ui.uploadDir takes
// on this product, and reports whether the value was that form at all.
//
// The scheme is the whole test. A value without it is a filesystem path — the
// reference's meaning of the knob, and one this runtime cannot honour — and is
// reported as such by cmd/auth rather than refused, so a document written for
// another port in the family still loads here. A value with the scheme and no
// bucket is an error, because "s3://" is neither a path nor a location.
func ParseS3Location(value string) (bucket, prefix string, isS3 bool, err error) {
	v := strings.TrimSpace(value)
	if !strings.HasPrefix(strings.ToLower(v), "s3://") {
		return "", "", false, nil
	}
	u, err := url.Parse(v)
	if err != nil {
		return "", "", true, fmt.Errorf("aws: %q is not an S3 location: %w", value, err)
	}
	bucket = u.Host
	if bucket == "" {
		return "", "", true, fmt.Errorf("aws: %q names no bucket; the form is s3://<bucket>[/<prefix>]", value)
	}
	if u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", true, fmt.Errorf("aws: %q carries a query, fragment or credentials; the form is s3://<bucket>[/<prefix>]", value)
	}
	return bucket, strings.Trim(u.Path, "/"), true, nil
}

// S3UploadStore is auth.UploadStore over one bucket and prefix.
type S3UploadStore struct {
	bucket      string
	prefix      string
	readTimeout time.Duration
	now         func() time.Time
	client      *lazyClient[S3API]
}

var _ auth.UploadStore = (*S3UploadStore)(nil)

// NewS3UploadStore builds the store. It performs no I/O: the client is built on
// the first call that needs one, for the reason lazyClient gives — a
// deployment that configures uploads must not pay for an S3 client during a
// cold start that will serve a login.
func NewS3UploadStore(opts S3UploadOptions) (*S3UploadStore, error) {
	if strings.TrimSpace(opts.Bucket) == "" {
		return nil, errors.New("aws: s3 upload store: bucket is required")
	}
	s := &S3UploadStore{
		bucket:      strings.TrimSpace(opts.Bucket),
		prefix:      strings.Trim(strings.TrimSpace(opts.Prefix), "/"),
		readTimeout: opts.ReadTimeout,
		now:         opts.Now,
	}
	if s.prefix != "" {
		s.prefix += "/"
	}
	if s.readTimeout <= 0 {
		s.readTimeout = DefaultS3ReadTimeout
	}
	if s.now == nil {
		s.now = time.Now
	}
	if opts.Client != nil {
		s.client = &lazyClient[S3API]{build: func(context.Context) (S3API, error) { return opts.Client, nil }}
		return s, nil
	}
	shared := &lazyConfig{region: opts.Region}
	s.client = &lazyClient[S3API]{build: func(ctx context.Context) (S3API, error) {
		cfg, err := shared.get(ctx)
		if err != nil {
			return nil, err
		}
		return s3.NewFromConfig(cfg), nil
	}}
	return s, nil
}

// Location is the `s3://bucket/prefix` the store was built from, for the
// cold-start log.
func (s *S3UploadStore) Location() string {
	return "s3://" + s.bucket + "/" + s.prefix
}

func (s *S3UploadStore) objectKey(key string) string { return s.prefix + key }

// errInvalidUploadKey is what every method answers for a key outside
// auth.ValidUploadKey. It is not ErrUploadNotFound on purpose: a caller that
// hands this store a name the grammar refuses has a bug, and a 404 would hide
// it.
var errInvalidUploadKey = errors.New("aws: s3 upload store: invalid upload key")

// Put implements auth.UploadStore.
func (s *S3UploadStore) Put(ctx context.Context, key string, content io.Reader) (auth.UploadedFile, error) {
	if !auth.ValidUploadKey(key) {
		return auth.UploadedFile{}, errInvalidUploadKey
	}
	api, err := s.client.get(ctx)
	if err != nil {
		return auth.UploadedFile{}, fmt.Errorf("aws: s3 upload store: cannot build a client: %w", err)
	}

	// The SDK signs the body and may retry the request, both of which need to
	// read it more than once, so it wants a seekable body. The route hands over
	// a *bytes.Reader — the seam says so — and a host that passes a plain
	// stream gets it read whole here; that host owns the bound, as the seam
	// also says, because the routes hold theirs at auth.UploadMaxBytes before
	// this is called.
	var body io.ReadSeeker
	if rs, ok := content.(io.ReadSeeker); ok {
		body = rs
	} else {
		data, err := io.ReadAll(content)
		if err != nil {
			return auth.UploadedFile{}, fmt.Errorf("aws: s3 upload store: read upload: %w", err)
		}
		body = bytes.NewReader(data)
	}
	size, err := body.Seek(0, io.SeekEnd)
	if err != nil {
		return auth.UploadedFile{}, fmt.Errorf("aws: s3 upload store: size upload: %w", err)
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return auth.UploadedFile{}, fmt.Errorf("aws: s3 upload store: rewind upload: %w", err)
	}

	contentType := auth.UploadContentType(key)
	if contentType == "" {
		// A key outside the seven image extensions is one a host put here
		// directly; the routes never produce one. Stored as the generic type
		// rather than guessed, so a browser is at least not lied to.
		contentType = "application/octet-stream"
	}

	if _, err := api.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        awssdk.String(s.bucket),
		Key:           awssdk.String(s.objectKey(key)),
		Body:          body,
		ContentLength: awssdk.Int64(size),
		ContentType:   awssdk.String(contentType),
		// No CacheControl is recorded, on purpose. The only reader of these
		// objects is the core's UI handler, through auth.UploadFS, and it
		// answers every static file with the reference's own
		// `public, max-age=0` (express.static's default maxAge of 0,
		// ui.router.ts:187-189) whatever the object's metadata says: an
		// fs.File carries no headers,
		// so a value stored here would reach no browser and would only
		// disagree with the one that does. The bucket is private and has no
		// other origin in front of it. docs/cost-model.md §2.6 counts what
		// that revalidation costs: one GetObject per fetch.
	}); err != nil {
		return auth.UploadedFile{}, fmt.Errorf("aws: s3 upload store: put %s: %w", key, err)
	}

	// Stamped from the local clock rather than read back with a HeadObject:
	// the listing reports S3's own LastModified, which is second-granular, so
	// the Put answer is truncated to match and a caller that lists straight
	// after a Put sees the same instant.
	return auth.UploadedFile{Name: key, Size: size, ModTime: s.now().UTC().Truncate(time.Second)}, nil
}

// List implements auth.UploadStore.
func (s *S3UploadStore) List(ctx context.Context) ([]auth.UploadedFile, error) {
	api, err := s.client.get(ctx)
	if err != nil {
		return nil, fmt.Errorf("aws: s3 upload store: cannot build a client: %w", err)
	}

	out := []auth.UploadedFile{}
	var token *string
	for {
		page, err := api.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket:            awssdk.String(s.bucket),
			Prefix:            awssdk.String(s.prefix),
			ContinuationToken: token,
		})
		if err != nil {
			return nil, fmt.Errorf("aws: s3 upload store: list: %w", err)
		}
		for _, obj := range page.Contents {
			name := strings.TrimPrefix(awssdk.ToString(obj.Key), s.prefix)
			if !auth.ValidUploadKey(name) {
				// Something else's object, or a "subdirectory" under the
				// prefix: not a key this store could have written and not one
				// Open could resolve, so it is not listed.
				continue
			}
			var mod time.Time
			if obj.LastModified != nil {
				mod = obj.LastModified.UTC()
			}
			out = append(out, auth.UploadedFile{Name: name, Size: awssdk.ToInt64(obj.Size), ModTime: mod})
		}
		if !awssdk.ToBool(page.IsTruncated) || page.NextContinuationToken == nil {
			break
		}
		token = page.NextContinuationToken
	}
	auth.SortUploadedFiles(out)
	return out, nil
}

// Open implements auth.UploadStore.
func (s *S3UploadStore) Open(ctx context.Context, key string) (io.ReadCloser, auth.UploadedFile, error) {
	if !auth.ValidUploadKey(key) {
		return nil, auth.UploadedFile{}, errInvalidUploadKey
	}
	api, err := s.client.get(ctx)
	if err != nil {
		return nil, auth.UploadedFile{}, fmt.Errorf("aws: s3 upload store: cannot build a client: %w", err)
	}

	// The deadline auth.UploadFS cannot pass. It bounds the request and the
	// first byte; the body is read by the caller after this returns, so the
	// cancel is tied to the body's Close rather than to this function's exit,
	// or the stream would be cancelled before the UI had read it.
	cancel := func() {}
	if _, has := ctx.Deadline(); !has {
		ctx, cancel = context.WithTimeout(ctx, s.readTimeout)
	}

	got, err := api.GetObject(ctx, &s3.GetObjectInput{
		Bucket: awssdk.String(s.bucket),
		Key:    awssdk.String(s.objectKey(key)),
	})
	if err != nil {
		cancel()
		if isS3NotFound(err) {
			return nil, auth.UploadedFile{}, auth.ErrUploadNotFound
		}
		return nil, auth.UploadedFile{}, fmt.Errorf("aws: s3 upload store: get %s: %w", key, err)
	}
	info := auth.UploadedFile{Name: key, Size: awssdk.ToInt64(got.ContentLength)}
	if got.LastModified != nil {
		info.ModTime = got.LastModified.UTC()
	}
	return cancelOnClose{ReadCloser: got.Body, cancel: cancel}, info, nil
}

// cancelOnClose releases Open's deadline when the caller is done with the body.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	defer c.cancel()
	return c.ReadCloser.Close()
}

// Delete implements auth.UploadStore. See the file header for why it is two
// calls.
func (s *S3UploadStore) Delete(ctx context.Context, key string) error {
	if !auth.ValidUploadKey(key) {
		return errInvalidUploadKey
	}
	api, err := s.client.get(ctx)
	if err != nil {
		return fmt.Errorf("aws: s3 upload store: cannot build a client: %w", err)
	}
	if _, err := api.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: awssdk.String(s.bucket),
		Key:    awssdk.String(s.objectKey(key)),
	}); err != nil {
		if isS3NotFound(err) {
			return auth.ErrUploadNotFound
		}
		return fmt.Errorf("aws: s3 upload store: head %s: %w", key, err)
	}
	if _, err := api.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: awssdk.String(s.bucket),
		Key:    awssdk.String(s.objectKey(key)),
	}); err != nil {
		return fmt.Errorf("aws: s3 upload store: delete %s: %w", key, err)
	}
	return nil
}

// isS3NotFound recognises the two spellings S3 has for an absent object —
// NoSuchKey from GetObject, and the bare 404 NotFound from HeadObject, which
// carries no body and therefore no error code — plus the HTTP status itself,
// for an SDK version that models neither.
//
// **A 403 is deliberately not a miss.** S3 answers a request for an absent key
// with 404 only to a caller that holds s3:ListBucket on the bucket; to one that
// does not it answers 403 AccessDenied, so that the absence of a key is not
// disclosed to somebody who may not enumerate them. Reading AccessDenied as
// "not found" would make this store work under a role that lacks the listing
// grant, and it would also turn every genuine permission fault — a bucket
// policy edited by hand, a role narrowed, the wrong bucket named — into a
// console that reports an empty, healthy upload tab. So the grant is the fix
// and not the mapping: infra/sam/template.yaml gives the role s3:ListBucket on
// the bucket with no s3:prefix condition (a condition GetObject and HeadObject
// requests do not carry, so a conditioned grant does not apply to them), and a
// 403 stays the store failure it is. TestS3AccessDeniedIsAFailureNotAMiss pins
// the decision.
func isS3NotFound(err error) bool {
	var noSuchKey *s3types.NoSuchKey
	if errors.As(err, &noSuchKey) {
		return true
	}
	var notFound *s3types.NotFound
	if errors.As(err, &notFound) {
		return true
	}
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NoSuchKey", "NotFound":
			return true
		}
	}
	// The status itself, last: a 404 whose code this SDK version models under
	// neither name is still an absent object. Only 404 — see above for 403.
	var response *smithyhttp.ResponseError
	if errors.As(err, &response) && response.HTTPStatusCode() == http.StatusNotFound {
		return true
	}
	return false
}

package aws

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	auth "github.com/nik2208/awesome-go-auth"
)

// fakeS3 is one bucket in memory, keyed by the full object key, recording what
// each call was handed. It answers the two "not found" shapes the real service
// answers — NoSuchKey from GetObject, a bare NotFound from HeadObject — so the
// store's mapping of both onto ErrUploadNotFound is tested against the shapes
// it will really see.
type fakeS3 struct {
	objects map[string]fakeObject
	puts    []*s3.PutObjectInput
	gets    []*s3.GetObjectInput
	heads   []*s3.HeadObjectInput
	deletes []*s3.DeleteObjectInput
	lists   []*s3.ListObjectsV2Input

	// pageSize makes ListObjectsV2 paginate, so the continuation loop is
	// exercised. Zero is one page.
	pageSize int

	// sawDeadline records whether GetObject was handed a context with one.
	sawDeadline bool

	// miss, when set, is what GetObject and HeadObject answer for an absent
	// key in place of the two modelled shapes: the way to hand the store the
	// AccessDenied a mis-granted role sees, or a 404 whose code the SDK does
	// not model.
	miss error
}

type fakeObject struct {
	body        []byte
	contentType string
	modified    time.Time
}

func newFakeS3() *fakeS3 { return &fakeS3{objects: map[string]fakeObject{}} }

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	f.puts = append(f.puts, in)
	data, err := io.ReadAll(in.Body)
	if err != nil {
		return nil, err
	}
	f.objects[awssdk.ToString(in.Key)] = fakeObject{
		body:        data,
		contentType: awssdk.ToString(in.ContentType),
		modified:    time.Now().UTC().Truncate(time.Second),
	}
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) GetObject(ctx context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.gets = append(f.gets, in)
	_, f.sawDeadline = ctx.Deadline()
	obj, ok := f.objects[awssdk.ToString(in.Key)]
	if !ok {
		if f.miss != nil {
			return nil, f.miss
		}
		return nil, &s3types.NoSuchKey{Message: awssdk.String("The specified key does not exist.")}
	}
	return &s3.GetObjectOutput{
		Body:          io.NopCloser(bytes.NewReader(obj.body)),
		ContentLength: awssdk.Int64(int64(len(obj.body))),
		ContentType:   awssdk.String(obj.contentType),
		LastModified:  awssdk.Time(obj.modified),
	}, nil
}

func (f *fakeS3) HeadObject(_ context.Context, in *s3.HeadObjectInput, _ ...func(*s3.Options)) (*s3.HeadObjectOutput, error) {
	f.heads = append(f.heads, in)
	obj, ok := f.objects[awssdk.ToString(in.Key)]
	if !ok {
		if f.miss != nil {
			return nil, f.miss
		}
		return nil, &s3types.NotFound{}
	}
	return &s3.HeadObjectOutput{ContentLength: awssdk.Int64(int64(len(obj.body)))}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	f.deletes = append(f.deletes, in)
	// Idempotent, as the real one is: a missing key is not an error.
	delete(f.objects, awssdk.ToString(in.Key))
	return &s3.DeleteObjectOutput{}, nil
}

func (f *fakeS3) ListObjectsV2(_ context.Context, in *s3.ListObjectsV2Input, _ ...func(*s3.Options)) (*s3.ListObjectsV2Output, error) {
	f.lists = append(f.lists, in)
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		if strings.HasPrefix(k, awssdk.ToString(in.Prefix)) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys) // S3 lists in UTF-8 binary key order
	start := 0
	if in.ContinuationToken != nil {
		start = sort.SearchStrings(keys, awssdk.ToString(in.ContinuationToken))
	}
	end := len(keys)
	if f.pageSize > 0 && start+f.pageSize < end {
		end = start + f.pageSize
	}
	out := &s3.ListObjectsV2Output{IsTruncated: awssdk.Bool(end < len(keys))}
	for _, k := range keys[start:end] {
		obj := f.objects[k]
		out.Contents = append(out.Contents, s3types.Object{
			Key:          awssdk.String(k),
			Size:         awssdk.Int64(int64(len(obj.body))),
			LastModified: awssdk.Time(obj.modified),
		})
	}
	if end < len(keys) {
		out.NextContinuationToken = awssdk.String(keys[end])
	}
	return out, nil
}

func newTestUploadStore(t *testing.T, fake *fakeS3, prefix string) *S3UploadStore {
	t.Helper()
	store, err := NewS3UploadStore(S3UploadOptions{Bucket: "uploads-bucket", Prefix: prefix, Client: fake})
	if err != nil {
		t.Fatalf("NewS3UploadStore: %v", err)
	}
	return store
}

func TestS3PutRecordsTheContentTypeAndWritesUnderThePrefix(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store := newTestUploadStore(t, fake, "uploads/")

	info, err := store.Put(t.Context(), "logo_1700000000000.png", bytes.NewReader([]byte("png-bytes")))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if len(fake.puts) != 1 {
		t.Fatalf("PutObject called %d times, want 1", len(fake.puts))
	}
	in := fake.puts[0]
	if got := awssdk.ToString(in.Key); got != "uploads/logo_1700000000000.png" {
		t.Errorf("Key = %q, want the key one segment below the prefix", got)
	}
	if got := awssdk.ToString(in.Bucket); got != "uploads-bucket" {
		t.Errorf("Bucket = %q", got)
	}
	// The one property the file header calls out: an object stored without a
	// type serves as binary/octet-stream forever, and no browser paints that.
	if got := awssdk.ToString(in.ContentType); got != "image/png" {
		t.Errorf("ContentType = %q, want image/png from the key's extension", got)
	}
	if got := awssdk.ToInt64(in.ContentLength); got != int64(len("png-bytes")) {
		t.Errorf("ContentLength = %d, want %d — read off the seeker, not guessed", got, len("png-bytes"))
	}
	if info.Name != "logo_1700000000000.png" || info.Size != int64(len("png-bytes")) {
		t.Errorf("Put answered %+v", info)
	}
	if info.ModTime.IsZero() || info.ModTime.Nanosecond() != 0 {
		t.Errorf("ModTime = %v, want a second-granular instant matching what the listing reports", info.ModTime)
	}
}

// TestS3PutReadsAStreamWholeAndLeavesNothingOnFailure: a non-seekable reader
// is buffered so the SDK has a body it can sign and retry, and a reader that
// fails halfway reaches no PutObject at all.
func TestS3PutReadsAStreamWholeAndLeavesNothingOnFailure(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store := newTestUploadStore(t, fake, "")

	if _, err := store.Put(t.Context(), "bg.jpg", strings.NewReader("stream")); err != nil {
		t.Fatalf("Put(stream): %v", err)
	}
	if got := string(fake.objects["bg.jpg"].body); got != "stream" {
		t.Errorf("stored %q, want the whole stream", got)
	}

	failing := io.MultiReader(strings.NewReader("half"), errReader{errors.New("disk on fire")})
	if _, err := store.Put(t.Context(), "broken.png", failing); err == nil {
		t.Fatal("Put over a failing reader succeeded")
	}
	if _, stored := fake.objects["broken.png"]; stored || len(fake.puts) != 1 {
		t.Errorf("a failed upload left an object behind (puts=%d)", len(fake.puts))
	}
}

type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// TestS3ListIsNewestFirstAndSkipsForeignObjects pins the order the seam
// promises, over more than one page, and that an object under the prefix
// whose name the grammar refuses — a "subdirectory", a stray file — is not
// reported as an upload.
func TestS3ListIsNewestFirstAndSkipsForeignObjects(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	fake.pageSize = 2
	store := newTestUploadStore(t, fake, "uploads")

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	fake.objects["uploads/b.png"] = fakeObject{body: []byte("b"), modified: now}
	fake.objects["uploads/a.png"] = fakeObject{body: []byte("aa"), modified: now}
	fake.objects["uploads/old.png"] = fakeObject{body: []byte("o"), modified: now.Add(-time.Hour)}
	fake.objects["uploads/new.png"] = fakeObject{body: []byte("n"), modified: now.Add(time.Hour)}
	fake.objects["uploads/nested/x.png"] = fakeObject{body: []byte("x"), modified: now}
	fake.objects["uploads/.hidden"] = fakeObject{body: []byte("h"), modified: now}
	fake.objects["elsewhere/z.png"] = fakeObject{body: []byte("z"), modified: now}

	got, err := store.List(t.Context())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	names := make([]string, 0, len(got))
	for _, f := range got {
		names = append(names, f.Name)
	}
	want := "new.png,a.png,b.png,old.png"
	if strings.Join(names, ",") != want {
		t.Errorf("List = %v, want %s (newest first, key ascending on a tie, foreign objects left out)", names, want)
	}
	if len(fake.lists) < 2 {
		t.Errorf("ListObjectsV2 called %d time(s) with a page size of 2 over 6 keys; the continuation loop never ran", len(fake.lists))
	}
	if got[1].Size != 2 {
		t.Errorf("a.png Size = %d, want 2 — the size comes from the listing, not a second call", got[1].Size)
	}
}

func TestS3OpenReturnsTheObjectAndMapsAMissToTheSentinel(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store := newTestUploadStore(t, fake, "uploads")
	fake.objects["uploads/logo.svg"] = fakeObject{body: []byte("<svg/>"), modified: time.Now().UTC()}

	rc, info, err := store.Open(context.Background(), "logo.svg")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	data, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(data) != "<svg/>" || info.Size != 6 || info.Name != "logo.svg" {
		t.Errorf("Open answered %q %+v", data, info)
	}
	// context.Background() is what auth.UploadFS passes, because fs.FS.Open
	// takes no context; the store must bound the read itself.
	if !fake.sawDeadline {
		t.Error("GetObject ran with no deadline; a hung read on the page path would hang the page")
	}

	if _, _, err := store.Open(t.Context(), "absent.png"); !errors.Is(err, auth.ErrUploadNotFound) {
		t.Errorf("Open(absent) = %v, want ErrUploadNotFound — the UI's 404 depends on it", err)
	}
}

// TestS3OpenThroughUploadFSIsWhatTheUIServes drives the store through the
// core's own adapter, because that is the composition cmd/auth relies on: a
// nil UIOptions.Uploads plus this store is the UI's read side.
func TestS3OpenThroughUploadFSIsWhatTheUIServes(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store := newTestUploadStore(t, fake, "")
	fake.objects["logo.png"] = fakeObject{body: []byte("png"), modified: time.Now().UTC()}

	fsys := auth.UploadFS(store)
	f, err := fsys.Open("logo.png")
	if err != nil {
		t.Fatalf("UploadFS.Open: %v", err)
	}
	st, _ := f.Stat()
	_ = f.Close()
	if st.Size() != 3 || st.IsDir() {
		t.Errorf("Stat = size %d dir %v", st.Size(), st.IsDir())
	}
	if _, err := fsys.Open("missing.png"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("UploadFS.Open(missing) = %v, want fs.ErrNotExist — the store's sentinel must survive the adapter", err)
	}
}

func TestS3DeleteAnswersNotFoundForAnAbsentKeyAndDeletesAPresentOne(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store := newTestUploadStore(t, fake, "uploads")
	fake.objects["uploads/logo.png"] = fakeObject{body: []byte("png")}

	if err := store.Delete(t.Context(), "absent.png"); !errors.Is(err, auth.ErrUploadNotFound) {
		t.Errorf("Delete(absent) = %v, want ErrUploadNotFound", err)
	}
	if len(fake.deletes) != 0 {
		t.Errorf("an absent key reached DeleteObject; S3's delete is idempotent and would have answered success")
	}

	if err := store.Delete(t.Context(), "logo.png"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, still := fake.objects["uploads/logo.png"]; still {
		t.Error("the object is still there")
	}
	if len(fake.heads) != 2 || len(fake.deletes) != 1 {
		t.Errorf("heads=%d deletes=%d, want a HeadObject per call and one DeleteObject", len(fake.heads), len(fake.deletes))
	}
}

// TestS3StoreRefusesAKeyOutsideTheGrammarBeforeAnyCall: the grammar is the
// only thing between a key and the bucket's namespace, so every method checks
// it — and answers a distinct error rather than a 404 that would hide a bug.
func TestS3StoreRefusesAKeyOutsideTheGrammarBeforeAnyCall(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	store := newTestUploadStore(t, fake, "uploads")

	for _, bad := range []string{"", "../etc/passwd", "a/b.png", ".env", "logo.png?x=1", strings.Repeat("a", 129) + ".png"} {
		if _, err := store.Put(t.Context(), bad, strings.NewReader("x")); !errors.Is(err, errInvalidUploadKey) {
			t.Errorf("Put(%q) = %v, want errInvalidUploadKey", bad, err)
		}
		if _, _, err := store.Open(t.Context(), bad); !errors.Is(err, errInvalidUploadKey) {
			t.Errorf("Open(%q) = %v, want errInvalidUploadKey", bad, err)
		}
		if err := store.Delete(t.Context(), bad); !errors.Is(err, errInvalidUploadKey) {
			t.Errorf("Delete(%q) = %v, want errInvalidUploadKey", bad, err)
		}
	}
	if n := len(fake.puts) + len(fake.gets) + len(fake.heads) + len(fake.deletes); n != 0 {
		t.Errorf("%d call(s) reached S3 for keys the grammar refuses", n)
	}
}

func TestParseS3Location(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in             string
		bucket, prefix string
		isS3, wantErr  bool
	}{
		{"s3://my-bucket", "my-bucket", "", true, false},
		{"s3://my-bucket/", "my-bucket", "", true, false},
		{"s3://my-bucket/uploads", "my-bucket", "uploads", true, false},
		{"s3://my-bucket/a/b/", "my-bucket", "a/b", true, false},
		{"S3://My-Bucket/x", "My-Bucket", "x", true, false},
		{"/var/uploads", "", "", false, false},
		{"", "", "", false, false},
		{"s3://", "", "", true, true},
		{"s3://bucket/x?versionId=1", "", "", true, true},
	} {
		bucket, prefix, isS3, err := ParseS3Location(tc.in)
		if isS3 != tc.isS3 || (err != nil) != tc.wantErr || bucket != tc.bucket || prefix != tc.prefix {
			t.Errorf("ParseS3Location(%q) = (%q, %q, %v, %v), want (%q, %q, %v, err=%v)",
				tc.in, bucket, prefix, isS3, err, tc.bucket, tc.prefix, tc.isS3, tc.wantErr)
		}
	}
	if _, err := NewS3UploadStore(S3UploadOptions{}); err == nil {
		t.Error("NewS3UploadStore accepted an empty bucket")
	}
	store := newTestUploadStore(t, newFakeS3(), "/uploads/")
	if got := store.Location(); got != "s3://uploads-bucket/uploads/" {
		t.Errorf("Location = %q", got)
	}
}

// s3Response builds the error the SDK hands a caller for an HTTP status and
// an error code: the aws transport's ResponseError around smithy's, around the
// generic API error — which is the chain the real client produces, and the one
// isS3NotFound has to see through.
func s3Response(status int, code string) error {
	return &awshttp.ResponseError{
		ResponseError: &smithyhttp.ResponseError{
			Response: &smithyhttp.Response{Response: &http.Response{StatusCode: status}},
			Err:      &smithy.GenericAPIError{Code: code, Message: code},
		},
		RequestID: "req-1",
	}
}

// TestS3AccessDeniedIsAFailureNotAMiss pins the decision isS3NotFound argues:
// S3 answers 403 for an absent key to a caller that may not list the bucket,
// and the store reports that as the failure it is rather than as an empty
// upload tab. The grant is the fix — infra/sam/template.yaml gives the role
// s3:ListBucket on the bucket with no s3:prefix condition, which is what turns
// the 403 back into the 404 the two mappings below recognise — and this test
// is what keeps the mapping from quietly widening to cover a broken grant.
func TestS3AccessDeniedIsAFailureNotAMiss(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	fake.miss = s3Response(http.StatusForbidden, "AccessDenied")
	store := newTestUploadStore(t, fake, "uploads")

	_, _, err := store.Open(t.Context(), "absent.png")
	if err == nil || errors.Is(err, auth.ErrUploadNotFound) {
		t.Errorf("Open under AccessDenied = %v, want a store failure, never ErrUploadNotFound: a 403 is a grant to fix, not a miss", err)
	}
	if !strings.Contains(err.Error(), "AccessDenied") {
		t.Errorf("the failure does not carry the service's code, which is what the operator needs to read: %v", err)
	}
	if err := store.Delete(t.Context(), "absent.png"); err == nil || errors.Is(err, auth.ErrUploadNotFound) {
		t.Errorf("Delete under AccessDenied = %v, want a store failure, never ErrUploadNotFound", err)
	}
	if len(fake.deletes) != 0 {
		t.Error("a HeadObject refused with 403 still reached DeleteObject")
	}
	// Through the core's adapter, the same failure is not fs.ErrNotExist: the
	// UI answers 500 on it, which is the honest answer for a bucket the role
	// cannot read.
	if _, err := auth.UploadFS(store).Open("absent.png"); err == nil || errors.Is(err, fs.ErrNotExist) {
		t.Errorf("UploadFS.Open under AccessDenied = %v, want a failure the adapter does not read as a miss", err)
	}
}

// TestS3ABare404IsAMissWhateverItsCode is the third clause of isS3NotFound:
// a 404 whose error code this SDK version models under neither NoSuchKey nor
// NotFound is still an absent object, and the status decides.
func TestS3ABare404IsAMissWhateverItsCode(t *testing.T) {
	t.Parallel()
	fake := newFakeS3()
	fake.miss = s3Response(http.StatusNotFound, "SomeFutureCode")
	store := newTestUploadStore(t, fake, "uploads")

	if _, _, err := store.Open(t.Context(), "absent.png"); !errors.Is(err, auth.ErrUploadNotFound) {
		t.Errorf("Open on a 404 with an unmodelled code = %v, want ErrUploadNotFound", err)
	}
	if err := store.Delete(t.Context(), "absent.png"); !errors.Is(err, auth.ErrUploadNotFound) {
		t.Errorf("Delete on a 404 with an unmodelled code = %v, want ErrUploadNotFound", err)
	}
	// And the two shapes the fake answers by default stay misses, so the
	// status clause widened nothing it should not have.
	plain := newTestUploadStore(t, newFakeS3(), "uploads")
	if _, _, err := plain.Open(t.Context(), "absent.png"); !errors.Is(err, auth.ErrUploadNotFound) {
		t.Errorf("Open on NoSuchKey = %v, want ErrUploadNotFound", err)
	}
}

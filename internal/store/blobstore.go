package store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"cloud.google.com/go/storage"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

// Object-store backends only ever see ciphertext.
//
//   - Local: filesystem, for development.
//   - GCS:   Google Cloud Storage (bucket with CMEK, uniform access, public access prevention).
//   - S3:    any S3-compatible endpoint (AWS GovCloud, MinIO, self-hosted Supabase Storage).
//
// GCS sits behind a small objectAPI interface (faked in tests); S3 is faked at the client interface.

// Storage keys are one to six segments, each starting with an alphanumeric, so "." and ".." can
// never appear as a segment. App-scoped objects live under apps/<app_id>/<env>/.
var keyRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,120}(/[A-Za-z0-9][A-Za-z0-9._-]{0,120}){0,5}$`)

// ValidStorageKey reports whether a key has the canonical object-store syntax.
func ValidStorageKey(key string) bool { return keyRe.MatchString(key) }

func checkKey(key string) error {
	if !keyRe.MatchString(key) {
		return fmt.Errorf("invalid storage key %q", key)
	}
	return nil
}

// Writer receives ciphertext. Exactly one of Commit or Abort must be called.
type Writer interface {
	io.Writer
	Commit() error
	Abort() error
}

type Backend interface {
	OpenWriter(ctx context.Context, key string) (Writer, error)
	Read(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
	Describe() map[string]any
}

// ---------------------------------------------------------------------------------------------
// Local filesystem
// ---------------------------------------------------------------------------------------------

type Local struct{ root string }

func NewLocal(root string) (*Local, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Local{root: root}, nil
}

func (l *Local) path(key string) (string, error) {
	if err := checkKey(key); err != nil {
		return "", err
	}
	if strings.Contains(key, "/") {
		return filepath.Join(l.root, filepath.FromSlash(key)), nil
	}
	if len(key) < 2 {
		return "", errors.New("legacy local keys must have at least two characters")
	}
	return filepath.Join(l.root, key[len(key)-2:], key), nil // pre-app-scoping layout
}

type localWriter struct {
	f     *os.File
	final string
	ctx   context.Context
}

func (l *Local) OpenWriter(ctx context.Context, key string) (Writer, error) {
	final, err := l.path(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(final); err == nil {
		return nil, errs.Conflict("object already exists")
	}
	f, err := os.CreateTemp(filepath.Dir(final), ".upload-*")
	if err != nil {
		return nil, err
	}
	return &localWriter{f: f, final: final, ctx: ctx}, nil
}

func (w *localWriter) Write(p []byte) (int, error) { return w.f.Write(p) }

func (w *localWriter) Commit() error {
	if err := w.f.Sync(); err != nil {
		return err
	}
	if err := w.f.Close(); err != nil {
		return err
	}
	err := localLock(w.ctx, w.final, func() error {
		if err := os.Link(w.f.Name(), w.final); err != nil {
			return err
		}
		return os.Remove(w.f.Name())
	})
	if err != nil {
		_ = os.Remove(w.f.Name())
	}
	return err
}

func (w *localWriter) Abort() error {
	_ = w.f.Close()
	return os.Remove(w.f.Name())
}

func (l *Local) Read(_ context.Context, key string) (io.ReadCloser, error) {
	p, err := l.path(key)
	if err != nil {
		return nil, err
	}
	f, err := os.Open(p) //nolint:gosec // key validated by checkKey
	if errors.Is(err, os.ErrNotExist) {
		return nil, errs.NotFound("object missing from blob store")
	}
	return f, err
}

func (l *Local) Delete(ctx context.Context, key string) error {
	path, err := l.path(key)
	if err != nil {
		return err
	}
	err = localLock(ctx, path, func() error { return os.Remove(path) })
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

func (l *Local) Describe() map[string]any {
	return map[string]any{"backend": "local", "root": l.root, "production_safe": false}
}

// ---------------------------------------------------------------------------------------------
// Remote backends share one shape: a small API interface (faked in tests) behind the Backend.
// ---------------------------------------------------------------------------------------------

type objectAPI interface {
	put(ctx context.Context, key string, r io.Reader) error
	get(ctx context.Context, key string) (io.ReadCloser, error)
	remove(ctx context.Context, key string) error
}

// Remote streams a writer into objectAPI.put through a pipe, so uploads use O(part) memory.
type Remote struct {
	api    objectAPI
	prefix string
	info   map[string]any
}

type pipeWriter struct {
	pw     *io.PipeWriter
	done   chan error
	cancel context.CancelFunc
}

func (r *Remote) OpenWriter(ctx context.Context, key string) (Writer, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	ctx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	done := make(chan error, 1)
	go func() {
		err := r.api.put(ctx, r.prefix+key, pr)
		_ = pr.CloseWithError(err)
		done <- err
	}()
	return &pipeWriter{pw: pw, done: done, cancel: cancel}, nil
}

func (w *pipeWriter) Write(p []byte) (int, error) { return w.pw.Write(p) }

func (w *pipeWriter) Commit() error {
	defer w.cancel()
	if err := w.pw.Close(); err != nil {
		return err
	}
	return <-w.done
}

func (w *pipeWriter) Abort() error {
	w.cancel()
	_ = w.pw.CloseWithError(errors.New("upload aborted"))
	<-w.done
	return nil
}

func (r *Remote) Read(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	return r.api.get(ctx, r.prefix+key)
}

func (r *Remote) Delete(ctx context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	return r.api.remove(ctx, r.prefix+key)
}

func (r *Remote) Describe() map[string]any { return r.info }

// GCS --------------------------------------------------------------------------------------------

type gcsAPI struct{ bucket *storage.BucketHandle }

func (g gcsAPI) put(ctx context.Context, key string, r io.Reader) error {
	// DoesNotExist: never overwrite an existing object.
	w := g.bucket.Object(key).If(storage.Conditions{DoesNotExist: true}).NewWriter(ctx)
	w.ChunkSize = 8 << 20
	if _, err := io.Copy(w, r); err != nil {
		_ = w.Close()
		return err
	}
	return w.Close()
}

func (g gcsAPI) get(ctx context.Context, key string) (io.ReadCloser, error) {
	rc, err := g.bucket.Object(key).NewReader(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil, errs.NotFound("object missing from blob store")
	}
	return rc, err
}

func (g gcsAPI) remove(ctx context.Context, key string) error {
	err := g.bucket.Object(key).Delete(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil
	}
	return err
}

func NewGCS(ctx context.Context, bucket, prefix string) (*Remote, error) {
	client, err := storage.NewClient(ctx)
	if err != nil {
		return nil, err
	}
	return &Remote{
		api:    gcsAPI{bucket: client.Bucket(bucket)},
		prefix: prefix,
		info:   map[string]any{"backend": "gcs", "bucket": bucket, "prefix": prefix, "production_safe": true},
	}, nil
}

// S3-compatible -----------------------------------------------------------------------------------

// S3Client is the subset of *s3.Client used here.
type S3Client interface {
	PutObject(ctx context.Context, in *s3.PutObjectInput, opts ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	CreateMultipartUpload(ctx context.Context, in *s3.CreateMultipartUploadInput, opts ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error)
	UploadPart(ctx context.Context, in *s3.UploadPartInput, opts ...func(*s3.Options)) (*s3.UploadPartOutput, error)
	CompleteMultipartUpload(ctx context.Context, in *s3.CompleteMultipartUploadInput, opts ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error)
	AbortMultipartUpload(ctx context.Context, in *s3.AbortMultipartUploadInput, opts ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error)
	GetObject(ctx context.Context, in *s3.GetObjectInput, opts ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	DeleteObject(ctx context.Context, in *s3.DeleteObjectInput, opts ...func(*s3.Options)) (*s3.DeleteObjectOutput, error)
}

const s3PartSize = 16 << 20 // S3 requires >= 5 MiB for every part but the last

type S3 struct {
	c      S3Client
	bucket string
	prefix string
	info   map[string]any
}

// NewS3 connects to S3 or an S3-compatible endpoint. Credentials come from the standard AWS chain.
// For self-hosted Supabase Storage use endpoint https://<host>/storage/v1/s3 (path-style is forced).
func NewS3(ctx context.Context, bucket, prefix, endpointURL, region string) (*S3, error) {
	cfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(region))
	if err != nil {
		return nil, err
	}
	client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		if endpointURL != "" {
			o.BaseEndpoint = aws.String(endpointURL)
			o.UsePathStyle = true
		}
	})
	return NewS3WithClient(client, bucket, prefix, endpointURL), nil
}

func NewS3WithClient(c S3Client, bucket, prefix, endpoint string) *S3 {
	if endpoint == "" {
		endpoint = "aws"
	}
	return &S3{c: c, bucket: bucket, prefix: prefix,
		info: map[string]any{"backend": "s3", "bucket": bucket, "endpoint": endpoint, "prefix": prefix, "production_safe": true}}
}

type s3Writer struct {
	s        *S3
	ctx      context.Context
	key      string
	buf      []byte
	uploadID *string
	parts    []s3types.CompletedPart
}

func (s *S3) OpenWriter(ctx context.Context, key string) (Writer, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	return &s3Writer{s: s, ctx: ctx, key: s.prefix + key}, nil
}

func (w *s3Writer) flushPart() error {
	if w.uploadID == nil {
		out, err := w.s.c.CreateMultipartUpload(w.ctx, &s3.CreateMultipartUploadInput{Bucket: &w.s.bucket, Key: &w.key})
		if err != nil {
			return err
		}
		w.uploadID = out.UploadId
	}
	n := min(len(w.buf), s3PartSize)
	num := int32(len(w.parts) + 1) //nolint:gosec // bounded by object size / part size
	out, err := w.s.c.UploadPart(w.ctx, &s3.UploadPartInput{
		Bucket: &w.s.bucket, Key: &w.key, UploadId: w.uploadID, PartNumber: &num, Body: bytes.NewReader(w.buf[:n]),
	})
	if err != nil {
		return err
	}
	w.parts = append(w.parts, s3types.CompletedPart{ETag: out.ETag, PartNumber: &num})
	w.buf = append([]byte(nil), w.buf[n:]...)
	return nil
}

func (w *s3Writer) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for len(w.buf) > s3PartSize {
		if err := w.flushPart(); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (w *s3Writer) Commit() error {
	if w.uploadID == nil {
		_, err := w.s.c.PutObject(w.ctx, &s3.PutObjectInput{Bucket: &w.s.bucket, Key: &w.key, Body: bytes.NewReader(w.buf)})
		return err
	}
	if len(w.buf) > 0 {
		if err := w.flushPart(); err != nil {
			return err
		}
	}
	_, err := w.s.c.CompleteMultipartUpload(w.ctx, &s3.CompleteMultipartUploadInput{
		Bucket: &w.s.bucket, Key: &w.key, UploadId: w.uploadID,
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: w.parts},
	})
	return err
}

func (w *s3Writer) Abort() error {
	if w.uploadID == nil {
		return nil
	}
	_, err := w.s.c.AbortMultipartUpload(context.WithoutCancel(w.ctx), &s3.AbortMultipartUploadInput{
		Bucket: &w.s.bucket, Key: &w.key, UploadId: w.uploadID,
	})
	return err
}

func (s *S3) Read(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := checkKey(key); err != nil {
		return nil, err
	}
	k := s.prefix + key
	out, err := s.c.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.bucket, Key: &k})
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return nil, errs.NotFound("object missing from blob store")
	}
	if err != nil {
		return nil, err
	}
	return out.Body, nil
}

func (s *S3) Delete(ctx context.Context, key string) error {
	if err := checkKey(key); err != nil {
		return err
	}
	k := s.prefix + key
	_, err := s.c.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.bucket, Key: &k})
	return err
}

func (s *S3) Describe() map[string]any { return s.info }

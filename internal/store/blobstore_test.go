package store

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"

	"github.com/paulmalmquist/storage_relspace/internal/errs"
)

func exercise(t *testing.T, b Backend, size int) {
	t.Helper()
	ctx := context.Background()
	data := make([]byte, size)
	_, _ = rand.Read(data)
	w, err := b.OpenWriter(ctx, "obj_1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < len(data); i += 1_000_000 {
		if _, err := w.Write(data[i:min(i+1_000_000, len(data))]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Commit(); err != nil {
		t.Fatal(err)
	}
	rc, err := b.Read(ctx, "obj_1")
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if !bytes.Equal(got, data) {
		t.Fatal("round trip mismatch")
	}
	if err := b.Delete(ctx, "obj_1"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Read(ctx, "obj_1"); !errs.Is(err, "not_found") {
		t.Fatalf("read after delete: %v", err)
	}
}

func TestLocal(t *testing.T) {
	b, err := NewLocal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	exercise(t, b, 1234)
	if _, err := b.OpenWriter(context.Background(), "../escape"); err == nil {
		t.Fatal("path traversal accepted")
	}
}

// fakeObjects stands in for GCS behind objectAPI.
type fakeObjects struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func (f *fakeObjects) put(_ context.Context, key string, r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objs[key] = b
	return nil
}

func (f *fakeObjects) get(_ context.Context, key string) (io.ReadCloser, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objs[key]
	if !ok {
		return nil, errs.NotFound("missing")
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (f *fakeObjects) remove(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.objs, key)
	return nil
}

func TestRemotePipe(t *testing.T) {
	f := &fakeObjects{objs: map[string][]byte{}}
	exercise(t, &Remote{api: f, prefix: "objects/"}, 3_000_000)

	w, _ := (&Remote{api: f, prefix: "objects/"}).OpenWriter(context.Background(), "obj_2")
	_, _ = w.Write([]byte("partial"))
	if err := w.Abort(); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.objs["objects/obj_2"]; ok {
		t.Fatal("aborted upload was stored")
	}
}

// fakeS3 implements S3Client in memory, including multipart uploads.
type fakeS3 struct {
	objs    map[string][]byte
	uploads map[string]map[int32][]byte
}

func (f *fakeS3) PutObject(_ context.Context, in *s3.PutObjectInput, _ ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	b, _ := io.ReadAll(in.Body)
	f.objs[*in.Key] = b
	return &s3.PutObjectOutput{}, nil
}

func (f *fakeS3) CreateMultipartUpload(_ context.Context, _ *s3.CreateMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CreateMultipartUploadOutput, error) {
	f.uploads["u1"] = map[int32][]byte{}
	return &s3.CreateMultipartUploadOutput{UploadId: aws.String("u1")}, nil
}

func (f *fakeS3) UploadPart(_ context.Context, in *s3.UploadPartInput, _ ...func(*s3.Options)) (*s3.UploadPartOutput, error) {
	b, _ := io.ReadAll(in.Body)
	f.uploads[*in.UploadId][*in.PartNumber] = b
	return &s3.UploadPartOutput{ETag: aws.String("e")}, nil
}

func (f *fakeS3) CompleteMultipartUpload(_ context.Context, in *s3.CompleteMultipartUploadInput, _ ...func(*s3.Options)) (*s3.CompleteMultipartUploadOutput, error) {
	var buf bytes.Buffer
	for _, p := range in.MultipartUpload.Parts {
		buf.Write(f.uploads[*in.UploadId][*p.PartNumber])
	}
	delete(f.uploads, *in.UploadId)
	f.objs[*in.Key] = buf.Bytes()
	return &s3.CompleteMultipartUploadOutput{}, nil
}

func (f *fakeS3) AbortMultipartUpload(_ context.Context, in *s3.AbortMultipartUploadInput, _ ...func(*s3.Options)) (*s3.AbortMultipartUploadOutput, error) {
	delete(f.uploads, *in.UploadId)
	return &s3.AbortMultipartUploadOutput{}, nil
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	b, ok := f.objs[*in.Key]
	if !ok {
		return nil, &s3types.NoSuchKey{}
	}
	return &s3.GetObjectOutput{Body: io.NopCloser(bytes.NewReader(b))}, nil
}

func (f *fakeS3) DeleteObject(_ context.Context, in *s3.DeleteObjectInput, _ ...func(*s3.Options)) (*s3.DeleteObjectOutput, error) {
	delete(f.objs, *in.Key)
	return &s3.DeleteObjectOutput{}, nil
}

func TestS3(t *testing.T) {
	for _, size := range []int{10, 2*s3PartSize + 5} {
		f := &fakeS3{objs: map[string][]byte{}, uploads: map[string]map[int32][]byte{}}
		exercise(t, NewS3WithClient(f, "bucket", "objects/", ""), size)
		if len(f.uploads) != 0 {
			t.Fatal("multipart upload left open")
		}
	}
	f := &fakeS3{objs: map[string][]byte{}, uploads: map[string]map[int32][]byte{}}
	w, _ := NewS3WithClient(f, "bucket", "objects/", "").OpenWriter(context.Background(), "obj_2")
	_, _ = w.Write(make([]byte, s3PartSize+1))
	if len(f.uploads) != 1 {
		t.Fatal("expected an open multipart upload")
	}
	if err := w.Abort(); err != nil || len(f.uploads) != 0 {
		t.Fatalf("abort: %v", errors.Join(err))
	}
}

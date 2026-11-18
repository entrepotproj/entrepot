package storage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	smithy "github.com/aws/smithy-go"
)

// S3Config configures an S3 blob store. When AccessKeyID is empty the default
// AWS credential chain is used (env, IRSA web identity, instance profile).
type S3Config struct {
	Bucket          string `json:"bucket"`
	Region          string `json:"region,omitempty"`
	Prefix          string `json:"prefix,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	ForcePathStyle  bool   `json:"forcePathStyle,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
	// RedirectDownloads makes the server answer downloads with a 307 to a
	// presigned URL instead of streaming through the pod.
	RedirectDownloads bool `json:"redirectDownloads,omitempty"`
}

type S3Store struct {
	cfg      S3Config
	client   *s3.Client
	presign  *s3.PresignClient
	uploader *manager.Uploader
	tempDir  string
}

func NewS3Store(ctx context.Context, cfg S3Config, tempDir string) (*S3Store, error) {
	if cfg.Bucket == "" {
		return nil, errors.New("s3 store: bucket is required")
	}
	opts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		opts = append(opts, awsconfig.WithRegion(cfg.Region))
	} else {
		opts = append(opts, awsconfig.WithRegion("us-east-1"))
	}
	if cfg.AccessKeyID != "" {
		opts = append(opts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")))
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("s3 store: %w", err)
	}
	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		if cfg.Endpoint != "" {
			o.BaseEndpoint = aws.String(cfg.Endpoint)
		}
		o.UsePathStyle = cfg.ForcePathStyle
	})
	if tempDir == "" {
		tempDir = os.TempDir()
	}
	return &S3Store{
		cfg:     cfg,
		client:  client,
		presign: s3.NewPresignClient(client),
		uploader: manager.NewUploader(client, func(u *manager.Uploader) {
			u.PartSize = 16 << 20
		}),
		tempDir: tempDir,
	}, nil
}

func (s *S3Store) Type() string { return "s3" }

func (s *S3Store) key(parts ...string) string {
	return path.Join(append([]string{strings.Trim(s.cfg.Prefix, "/")}, parts...)...)
}

func (s *S3Store) blobKey(d Digest) string {
	h := d.Hex()
	return s.key("blobs", "sha256", h[:2], h)
}

// Ingest spools to a local temp file while hashing, so the final object key
// (the digest) is known before uploading.
func (s *S3Store) Ingest(ctx context.Context, r io.Reader, expected Digest) (Digest, int64, error) {
	tmp, err := os.CreateTemp(s.tempDir, "entrepot-s3-*")
	if err != nil {
		return "", 0, err
	}
	defer func() {
		tmp.Close()
		os.Remove(tmp.Name())
	}()
	hr := newHashingReader(ctxReader{ctx, r})
	if _, err := io.Copy(tmp, hr); err != nil {
		return "", 0, err
	}
	d := hr.Digest()
	if expected != "" && d != expected {
		return "", 0, fmt.Errorf("%w: expected %s, got %s", ErrDigestMismatch, expected, d)
	}
	if _, err := s.Stat(ctx, d); err == nil {
		return d, hr.size, nil
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return "", 0, err
	}
	_, err = s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(s.cfg.Bucket),
		Key:           aws.String(s.blobKey(d)),
		Body:          tmp,
		ContentLength: aws.Int64(hr.size),
	})
	if err != nil {
		return "", 0, fmt.Errorf("s3 upload: %w", err)
	}
	return d, hr.size, nil
}

func (s *S3Store) Open(ctx context.Context, d Digest) (ReadSeekCloser, Info, error) {
	info, err := s.Stat(ctx, d)
	if err != nil {
		return nil, Info{}, err
	}
	return &s3Reader{ctx: ctx, s: s, key: s.blobKey(d), size: info.Size}, info, nil
}

func (s *S3Store) Stat(ctx context.Context, d Digest) (Info, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(s.blobKey(d)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return Info{}, ErrNotFound
		}
		return Info{}, err
	}
	info := Info{Digest: d, Size: aws.ToInt64(out.ContentLength)}
	if out.LastModified != nil {
		info.ModTime = *out.LastModified
	}
	return info, nil
}

func (s *S3Store) Delete(ctx context.Context, d Digest) error {
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(s.blobKey(d)),
	})
	return err
}

func (s *S3Store) Walk(ctx context.Context, fn func(Info) error) error {
	prefix := s.key("blobs", "sha256") + "/"
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.Bucket),
		Prefix: aws.String(prefix),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, obj := range page.Contents {
			d, err := ParseDigest("sha256:" + path.Base(aws.ToString(obj.Key)))
			if err != nil {
				continue
			}
			info := Info{Digest: d, Size: aws.ToInt64(obj.Size)}
			if obj.LastModified != nil {
				info.ModTime = *obj.LastModified
			}
			if err := fn(info); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *S3Store) PutTemp(ctx context.Context, key string, r io.Reader) (int64, error) {
	if err := validTempKey(key); err != nil {
		return 0, err
	}
	cr := &countingReader{r: ctxReader{ctx, r}}
	_, err := s.uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(s.key("temp", key)),
		Body:   cr,
	})
	return cr.n, err
}

func (s *S3Store) OpenTemp(ctx context.Context, key string) (io.ReadCloser, error) {
	if err := validTempKey(key); err != nil {
		return nil, err
	}
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(s.key("temp", key)),
	})
	if err != nil {
		if isS3NotFound(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return out.Body, nil
}

func (s *S3Store) DeleteTempPrefix(ctx context.Context, prefix string) error {
	if err := validTempKey(strings.TrimSuffix(prefix, "/")); err != nil {
		return err
	}
	p := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.Bucket),
		Prefix: aws.String(s.key("temp", prefix)),
	})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		if len(page.Contents) == 0 {
			continue
		}
		ids := make([]types.ObjectIdentifier, 0, len(page.Contents))
		for _, o := range page.Contents {
			ids = append(ids, types.ObjectIdentifier{Key: o.Key})
		}
		if _, err := s.client.DeleteObjects(ctx, &s3.DeleteObjectsInput{
			Bucket: aws.String(s.cfg.Bucket),
			Delete: &types.Delete{Objects: ids, Quiet: aws.Bool(true)},
		}); err != nil {
			return err
		}
	}
	return nil
}

func (s *S3Store) Check(ctx context.Context) error {
	_, err := s.client.HeadBucket(ctx, &s3.HeadBucketInput{Bucket: aws.String(s.cfg.Bucket)})
	if err != nil {
		return fmt.Errorf("s3 bucket %s: %w", s.cfg.Bucket, err)
	}
	return nil
}

func (s *S3Store) PresignGet(ctx context.Context, d Digest, ttl time.Duration) (string, error) {
	if !s.cfg.RedirectDownloads {
		return "", errors.ErrUnsupported
	}
	req, err := s.presign.PresignGetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.Bucket),
		Key:    aws.String(s.blobKey(d)),
	}, s3.WithPresignExpires(ttl))
	if err != nil {
		return "", err
	}
	return req.URL, nil
}

func isS3NotFound(err error) bool {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		switch apiErr.ErrorCode() {
		case "NotFound", "NoSuchKey", "404":
			return true
		}
	}
	var nsk *types.NoSuchKey
	var nf *types.NotFound
	return errors.As(err, &nsk) || errors.As(err, &nf)
}

// s3Reader implements ReadSeeker with lazily-issued ranged GETs so that
// http.ServeContent can answer Range requests without downloading the object.
type s3Reader struct {
	ctx  context.Context
	s    *S3Store
	key  string
	size int64
	pos  int64
	body io.ReadCloser
}

func (r *s3Reader) Read(p []byte) (int, error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}
	if r.body == nil {
		out, err := r.s.client.GetObject(r.ctx, &s3.GetObjectInput{
			Bucket: aws.String(r.s.cfg.Bucket),
			Key:    aws.String(r.key),
			Range:  aws.String(fmt.Sprintf("bytes=%d-", r.pos)),
		})
		if err != nil {
			return 0, err
		}
		r.body = out.Body
	}
	n, err := r.body.Read(p)
	r.pos += int64(n)
	return n, err
}

func (r *s3Reader) Seek(offset int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = offset
	case io.SeekCurrent:
		abs = r.pos + offset
	case io.SeekEnd:
		abs = r.size + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if abs < 0 {
		return 0, errors.New("negative position")
	}
	if abs != r.pos && r.body != nil {
		r.body.Close()
		r.body = nil
	}
	r.pos = abs
	return abs, nil
}

func (r *s3Reader) Close() error {
	if r.body != nil {
		return r.body.Close()
	}
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

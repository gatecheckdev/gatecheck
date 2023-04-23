package utilities

import (
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type mockPutObject func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)

func (m mockPutObject) PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
	return m(ctx, params, optFns...)
}

func TestPutObject(t *testing.T) {
	cases := []struct {
		client        func(t *testing.T) S3PutObjectAPI
		name          string
		bucket        string
		key           string
		body          *os.File
		contentLength int64
		secretString  string
		expect        []byte
	}{
		{
			client: func(t *testing.T) S3PutObjectAPI {
				return mockPutObject(func(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error) {
					t.Helper()
					if params.Bucket == nil {
						t.Errorf("expected name to be set")
					}
					if e, a := "bucketName", *params.Bucket; e != a {
						t.Errorf("expected %v, got %v", e, a)
					}
					return &s3.PutObjectOutput{
						ETag: aws.String("etag"),
					}, nil
				})
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.TODO()
			_, err := PutObject(ctx, c.client(t), "bucketName", "key", nil)
			if err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

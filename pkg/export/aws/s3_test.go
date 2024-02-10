package aws

import (
	"bytes"
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
)

func TestExport_timeout(t *testing.T) {
	cfg, _ := config.LoadDefaultConfig(context.Background())

	service := NewService("some-bucket", cfg)

	ctx := context.Background()
	ctx.Done()

	err := service.Export(ctx, bytes.NewBufferString("Content"), "some/object/key")
	if err == nil {
		t.Fatal("Expected timeout error")
	}

	t.Log(err)
}

func TestExport_success(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	mockServer := httptest.NewServer(faker.Server())
	defer mockServer.Close()

	client := mockServer.Client()
	client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}

	endpointResolver := aws.EndpointResolverWithOptionsFunc(func(service string, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{URL: mockServer.URL}, nil
	})

	cfg, _ := config.LoadDefaultConfig(context.Background(),
		config.WithEndpointResolverWithOptions(endpointResolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("KEY", "SECRET", "SESSION")),
		config.WithHTTPClient(client))

	service := NewService("some-bucket", cfg)

	s3Client := s3.NewFromConfig(cfg, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	_, err := s3Client.CreateBucket(context.Background(), &s3.CreateBucketInput{Bucket: aws.String("some-bucket")})
	if err != nil {
		t.Fatal(err)
	}

	testFilename := path.Join(t.TempDir(), "somefile.txt")

	_ = os.WriteFile(testFilename, []byte("Some content"), 0o664)

	f, err := os.Open(testFilename)
	if err != nil {
		t.Fatal(err)
	}

	err = service.Export(context.Background(), f, "some/object/key")
	if err != nil {
		t.Fatal(err)
	}
}

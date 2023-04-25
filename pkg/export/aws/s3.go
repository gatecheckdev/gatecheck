// Package aws integrates aws-sdk-go-v2 into gatecheck
package aws

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Service struct {
	client    *http.Client
	Profile   string
	Bucket    string
	AWSConfig aws.Config
}

func NewService(bucket string, config aws.Config) Service {
	return Service{
		AWSConfig: config,
		Bucket:    bucket,
	}
}

func (s Service) Export(ctx context.Context, r io.Reader, key string) error {

	s3Client := s3.NewFromConfig(s.AWSConfig, func(o *s3.Options) {
		o.UsePathStyle = true
	})

	_, err := s3Client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(s.Bucket),
		Key:    aws.String(key),
		Body:   r,
	})

	if err != nil {
		return fmt.Errorf("failed to put object to AWS S3: %v", err)
	}

	return nil
}

// Package aws integrates aws-sdk-go-v2 into gatecheck
package aws

import (
	"context"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	util "github.com/gatecheckdev/gatecheck/pkg/export/aws/utilities"
)

type UploadQuery struct {
	Filepath      string
	DDEngagement  string
	DDProduct     string
	DDProductType string
}

type AWS interface {
	Export(context.Context, io.Reader, UploadQuery) error
}

type Service struct {
	Retry           int           // How many times to retry on a failed export
	BackoffDuration time.Duration // The interval for the exponential back off retry
	client          *http.Client
	Profile         string
	Bucket          string
}

func NewService(client *http.Client, profile, bucket string) Service {
	return Service{
		client:          client,
		Retry:           3,
		BackoffDuration: time.Second,
		Profile:         profile,
		Bucket:          bucket,
	}
}

func (s Service) Export(ctx context.Context, r io.Reader, upload UploadQuery) error {
	c := make(chan error)

	go func() {
		var err error
		for i := 0; i < s.Retry; i++ {
			err = s.export(r, upload)
			if err == nil {
				close(c)
				return
			}
			// Sleep for 2 ^ backoff, seconds
			sleepFor := time.Duration(int64(math.Pow(2, float64(i)))) * s.BackoffDuration
			log.Printf("Export Attempt %d / %d, will Retrying after %s. Error: %v\n", i+1, s.Retry,
				sleepFor.String(), err)
			time.Sleep(sleepFor)
		}
		c <- err
	}()

	for {
		select {
		case err, ok := <-c:
			if !ok {
				return nil
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (s Service) export(r io.Reader, q UploadQuery) error {
	cfg, err := config.LoadDefaultConfig(context.TODO(), config.WithSharedConfigProfile(s.Profile))
	if err != nil {
		return errors.New("failed to load AWS configuration")
	}

	s3Client := s3.NewFromConfig(cfg)
	ctx := context.TODO()

	key, err := uploadKey(q)
	if err != nil {
		return err
	}

	_, err = util.PutObject(ctx, s3Client, s.Bucket, key, r)
	if err != nil {
		return errors.New("failed to put object to AWS S3")
	}

	return nil
}

func uploadKey(q UploadQuery) (string, error) {
	if q.DDProductType == "" {
		return "", errors.New("product type is required")
	}

	if q.DDProduct == "" {
		return "", errors.New("product is required")
	}

	if q.DDEngagement == "" {
		return "", errors.New("engagement is required")
	}

	if q.Filepath == "" {
		return "", errors.New("filepath is required")
	}

	filepath := strings.Split(q.Filepath, "/")
	file := filepath[len(filepath)-1] // set file as last item in filepath slice

	key := q.DDProductType + "/" + q.DDProduct + "/" + q.DDEngagement + "/" + file

	return key, nil
}

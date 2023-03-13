// package s3 contains the implementation code for `gatecheck export s3`
package s3

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ...

//go:generate mockery --name S3NewUploaderAPI
type S3NewUploaderAPI interface {
	// func manager.NewUploader(client manager.UploadAPIClient, options ...func(*manager.Uploader)) *manager.Uploader
	NewUploader(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*manager.UploadOutput, error)
}

//go:generate mockery --name S3UploadObjectAPI
type S3UploadObjectAPI interface {
	Upload(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*manager.UploadOutput, error)
}

// func UploadObjectToS3(ctx context.Context, api S3UploadObjectAPI, bucket, key string, fileBytes []byte) {
func UploadObjectToS3() {
	// bad-upload
	uploadFile := bytes.NewReader([]byte(""))
	// good-upload
	// uploadFile := bytes.NewReader([]byte("Hello, Test uploadFile"))

	cfg, _ := config.LoadDefaultConfig(context.TODO())
	// if err != nil {
	// 	log.Printf("error: %v", err)
	// 	// panic(err)
	// 	log.Fatal(err)
	// 	return err
	// }

	client := s3.NewFromConfig(cfg)

	uploader := manager.NewUploader(client)
	result, _ := uploader.Upload(context.TODO(), &s3.PutObjectInput{
		Bucket: aws.String(os.Getenv("AWS_BUCKET")),
		Key:    aws.String("my-test-object-key"),
		Body:   uploadFile,
	})
	// if err != nil {
	// 	logFatalf("err: %v", err)
	// 	panic(err)
	// 	// return err
	// }

	fmt.Printf("File uploaded!\n\nResult: %v", result)

	fmt.Fprintf(os.Stderr, "DEBUGPRINT[1]: upload.go:43: result=%+v\n", result)

	return
}

// Custom logger for unit-tests
//
// Usage:
//
//	if err != nil {
//	    logFatalf("error during some operation, error: %v", err)
//	}
var logFatalf = log.Fatalf

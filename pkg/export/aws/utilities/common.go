package utilities

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type S3PutObjectAPI interface {
	PutObject(ctx context.Context,
		params *s3.PutObjectInput,
		optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
}

func PutObject(ctx context.Context, client S3PutObjectAPI, bucket, key string, body io.Reader) (*s3.PutObjectOutput, error) {
	res, err := client.PutObject(ctx, &s3.PutObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
		Body:   body,
	})
	if err != nil {
		return res, err
	}
	return res, err
}

func BucketOps(ctx context.Context, client s3.Client, name string) error {
	// snippet-start:[s3.go-v2.PutObject]
	// Place an object in a bucket.
	fmt.Println("Upload an object to the bucket")
	// Get the object body to upload.
	// Image credit: https://unsplash.com/photos/iz58d89q3ss
	stat, err := os.Stat("image.jpg")
	if err != nil {
		panic("Couldn't stat image: " + err.Error())
	}
	file, err := os.Open("image.jpg")
	if err != nil {
		panic("Couldn't open local file")
	}

	_, err = client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:        aws.String(name),
		Key:           aws.String("path/myfile.jpg"),
		Body:          file,
		ContentLength: stat.Size(),
	})

	file.Close()

	if err != nil {
		return err
	}

	// snippet-end:[s3.go-v2.PutObject]

	return nil
}

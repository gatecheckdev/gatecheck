// package aws unit-tests for `gatecheck export aws` module
package aws

import (
	"bytes"
	"context"
	"log"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/smithy-go/middleware"

	"github.com/gatecheckdev/gatecheck/pkg/export/aws/mock"
	util "github.com/gatecheckdev/gatecheck/pkg/export/aws/utilities"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

var (
	client     *s3.Client
	bucketName string
)

var runLiveTests = false

func init() {
	log.Println("Setting up suite")

	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		panic("Failed to load configuration")
	}

	client = s3.NewFromConfig(cfg)
}

func TestOps(t *testing.T) {
	if !runLiveTests {
		t.Skip("Skipping live test. Change variable runLiveTests to true to run.")
	}
	ctx := context.TODO()
	t.Log("Doing things to the bucket...")
	util.BucketOps(ctx, *client, bucketName)
}

func TestMock_PutObject(t *testing.T) {
	m := mock.NewMockPutObjectClient()
	dataToWrite := []byte("Hi!")

	m.ObjectOutput(&s3.PutObjectOutput{
		BucketKeyEnabled:     false,
		ETag:                 aws.String("etag"),
		RequestCharged:       "",
		ServerSideEncryption: "",
		ResultMetadata:       middleware.Metadata{},
	})

	result, err := util.PutObject(context.TODO(),
		m.ClientS3PutObject(),
		"bucketName", "key",
		bytes.NewReader(dataToWrite))
	if err != nil {
		t.Error(err)
	}
	if result == nil {
		t.Error("Expected a result")
	}

	data, err := m.GetData(make([]byte, 20))
	if string(data) != "Hi!" {
		t.Error("Expected data to be Hi!")
	}
}

package mock

import (
	"bytes"
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go/middleware"

	util "github.com/gatecheckdev/gatecheck/pkg/export/aws/utilities"
)

func TestMockClient_ClientS3PutObject(t *testing.T) {
	m := NewMockPutObjectClient()
	m.ObjectOutput(&s3.PutObjectOutput{
		BucketKeyEnabled:        false,
		ETag:                    aws.String("etag"),
		Expiration:              nil,
		RequestCharged:          "",
		SSECustomerAlgorithm:    nil,
		SSECustomerKeyMD5:       nil,
		SSEKMSEncryptionContext: nil,
		SSEKMSKeyId:             nil,
		ServerSideEncryption:    "",
		VersionId:               nil,
		ResultMetadata:          middleware.Metadata{},
	})

	output, err := util.PutObject(context.TODO(), m.ClientS3PutObject(), "bucketName", "key",
		bytes.NewReader([]byte("Hi!")))
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if e, a := "etag", *output.ETag; e != a {
		t.Errorf("expected %v, got %v", e, a)
	}
	b := make([]byte, 20)
	data, err := m.GetData(b)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if e, a := "Hi!", string(data); e != a {
		t.Errorf("expected %v, got %v", e, a)
	}
}

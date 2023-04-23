package mock

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/s3"

	util "github.com/gatecheckdev/gatecheck/pkg/export/aws/utilities"
)

type MockPutObject func(ctx context.Context, params *s3.PutObjectInput,
	optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)

func (m MockPutObject) PutObject(ctx context.Context, params *s3.PutObjectInput,
	optFns ...func(*s3.Options),
) (*s3.PutObjectOutput, error) {
	return m(ctx, params, optFns...)
}

type MockClientPutObject struct {
	bucket          *string
	putObjectOutput *s3.PutObjectOutput
	putObjectInput  *s3.PutObjectInput
	err             error
}

func NewMockPutObjectClient() *MockClientPutObject {
	return &MockClientPutObject{}
}

func (m *MockClientPutObject) GetBucket() *string {
	return m.bucket
}

func (m *MockClientPutObject) ObjectOutput(output *s3.PutObjectOutput) {
	m.putObjectOutput = output
}

func (m *MockClientPutObject) GetPutObjectOutput() *s3.PutObjectOutput {
	return m.putObjectOutput
}

func (m *MockClientPutObject) GetPutObjectInput() *s3.PutObjectInput {
	return m.putObjectInput
}

func (m *MockClientPutObject) GetData(b []byte) ([]byte, error) {
	n, err := m.putObjectInput.Body.Read(b)
	return b[:n], err
}

func (m *MockClientPutObject) ClientS3PutObject() util.S3PutObjectAPI {
	return MockPutObject(func(ctx context.Context, params *s3.PutObjectInput,
		optFns ...func(*s3.Options),
	) (*s3.PutObjectOutput, error) {
		m.bucket = params.Bucket
		m.putObjectInput = params
		return m.putObjectOutput, m.err
	})
}

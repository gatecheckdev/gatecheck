// package s3 unit-test code for `gatecheck export s3`
package s3

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

func TestToS3(t *testing.T) {
	type args struct {
		ctx context.Context
		i   s3.PutObjectInput
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "failed-upload",
			args: args{
				ctx: context.TODO(),
				i: s3.PutObjectInput{
					Bucket: aws.String("nonexistent-bucket"),
					Key:    aws.String("some-key"),
					Body:   bytes.NewReader([]byte("some-file-contents")),
				},
			},
			wantErr: true,
		},
		{
			name: "successful-upload",
			args: args{
				ctx: context.TODO(),
				i: s3.PutObjectInput{
					Bucket: aws.String(os.Getenv("AWS_BUCKET")),
					Key:    aws.String("some-key"),
					Body:   bytes.NewReader([]byte("some-file-contents")),
				},
			},
			wantErr: false,
		},
		{
			name: "failed-without-error-upload",
			args: args{
				ctx: context.TODO(),
				i: s3.PutObjectInput{
					Bucket: aws.String("nonexistent-bucket"),
					Key:    aws.String("some-key"),
					Body:   bytes.NewReader([]byte("")),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ToS3(tt.args.ctx, tt.args.i); (err != nil) != tt.wantErr {
				t.Errorf("ToS3() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

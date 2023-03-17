// package s3 code for `gatecheck export s3`
package s3

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

//  ────────────────────────────────────────────────────────────────────────────────

// Stage is the name of a CI Pipeline Stage and creates part of the AWS S3 upload key.
// The value is the name of the stage that triggers the scan that creates the artifact.
//
// E.g. During the 'scan-image' stage a Grype scan is triggered creating a Grype Scan Report Artifact.
//
// NOTE: The value of `Stage` should match the value of `CI_BUILD_STAGE` in a GitLab CI Pipeline.
//
// Values:
//
//	const (
//	    GrypeStageName    Stage = "scan-image" // Grype scan stage
//	    SemgrepStageName        = "sast"       // Semgrep scan stage
//	    GitleaksStageName       = "sast"       // Gitleaks scan stage
//	)
type Stage string

const (
	GrypeStageName    Stage = "scan-image" // Grype scan stage
	SemgrepStageName        = "sast"       // Semgrep scan stage
	GitleaksStageName       = "sast"       // Gitleaks scan stage
)

// `Filename` is the name of the file uploaded to AWS S3.
//
// Values:
//
//	const (
//	    GrypeFilename    Filename = "grype-report.json"        // Grype filename
//	    SemgrepFilename           = "semgrep-sast-report.json" // Semgrep filename
//	    GitleaksFilename          = "gitleaks-report.json"     // Gitleaks filename
//	)
type Filename string

const (
	GrypeFilename    Filename = "grype-report.json"        // Grype filename
	SemgrepFilename           = "semgrep-sast-report.json" // Semgrep filename
	GitleaksFilename          = "gitleaks-report.json"     // Gitleaks filename
)

//  ────────────────────────────────────────────────────────────────────────────────

// ToS3 is the entrypoint function that loads the AWS Config, constructs the Client Service,
// invokes the API Operation, and builds a new *s3.Client.
// builds a new *s3.Client.
func ToS3(ctx context.Context, i s3.PutObjectInput) error {
	fmt.Println("──────────── ClientFor(ctx context.Context) *s3.Client ──────────────")
	fmt.Println("")

	// Loads the AWS Config
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return err
	}

	// Constructs the Client Service
	client := s3.NewFromConfig(cfg)

	uploader := manager.NewUploader(client)

	// Invokes the API Operation
	output, err := uploader.Upload(ctx, &s3.PutObjectInput{
		Bucket: i.Bucket,
		Key:    i.Key,
		Body:   i.Body,
	})
	if err != nil {
		return err
	}

	fmt.Printf("File upload type: %T\n\nvalue: %v\n\n", output, output)
	return nil
}

//  ────────────────────────────────────────────────────────────────────────────────

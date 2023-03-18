package cmd

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/spf13/cobra"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	upload "github.com/gatecheckdev/gatecheck/pkg/export/s3"
)

func NewExportCmd(service DDExportService, timeout time.Duration, engagement defectdojo.EngagementQuery) *cobra.Command {
	// gatecheck export command
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export a report to a target location",
	}

	// gatecheck export defect-dojo command
	defectDojoCmd := &cobra.Command{
		Use:     "defect-dojo [FILE]",
		Short:   "Export raw scan report to DefectDojo",
		Aliases: []string{"dd"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Open the file
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rType, fileBytes, err := artifact.ReadWithContext(ctx, f)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			var ddScanType defectdojo.ScanType
			switch rType {
			case artifact.Grype:
				ddScanType = defectdojo.Grype
			case artifact.Semgrep:
				ddScanType = defectdojo.Semgrep
			case artifact.Gitleaks:
				ddScanType = defectdojo.Gitleaks
			default:
				return fmt.Errorf("%w: Unsupported file type", ErrorEncoding)
			}

			return service.Export(ctx, bytes.NewBuffer(fileBytes), engagement, ddScanType)
		},
	}

	// gatecheck export s3 command
	s3Cmd := &cobra.Command{
		Use:     "s3 [FILE]",
		Short:   "Export raw scan report to AWS S3",
		Aliases: []string{"aws"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Open the file
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()

			rType, fileBytes, err := artifact.ReadWithContext(ctx, f)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			// Get the filepath from the CLI args then
			// split the filepath and set the filename
			fp := strings.Split(args[0], "/")
			filename := fp[len(fp)-1]

			key := engagement.ProductTypeName + "/" + engagement.ProductName + "/" + engagement.Name + "/" + string(filename)

			input := s3.PutObjectInput{
				Bucket: aws.String(os.Getenv("AWS_BUCKET")),
				Key:    aws.String(key),
				Body:   bytes.NewReader(fileBytes),
			}

			fmt.Println("")
			fmt.Println("───────────────────── Gatecheck Upload to S3 ────────────────────")
			fmt.Println("")

			return upload.ToS3(ctx, input)
		},
	}
	exportCmd.AddCommand(defectDojoCmd)
	exportCmd.AddCommand(s3Cmd)
	return exportCmd
}

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	gcS3 "github.com/gatecheckdev/gatecheck/pkg/export/s3"
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
		Args:    cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Open the file
			// f, err := os.Open(args[0])
			// if err != nil {
			// 	return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			// }

			// ctx, cancel := context.WithTimeout(context.Background(), timeout)
			// defer cancel()

			// rType, fileBytes, err := artifact.ReadWithContext(ctx, f)
			// if err != nil {
			// 	return fmt.Errorf("%w: %v", ErrorEncoding, err)
			// }

			// Set filename to "stage/filenamne"
			// var stage gcS3.Stage
			// var filename gcS3.Filename
			// switch rType {
			// case artifact.Grype:
			// 	stage = gcS3.GrypeStageName
			// 	filename = gcS3.GrypeFilename
			// case artifact.Semgrep:
			// 	stage = gcS3.SemgrepStageName
			// 	filename = gcS3.SemgrepFilename
			// case artifact.Gitleaks:
			// 	stage = gcS3.GitleaksStageName
			// 	filename = gcS3.GitleaksFilename
			// default:
			// 	logFatalf("unsupported file type, err:%v", err)
			// 	return fmt.Errorf("%w: Unsupported file type", ErrorEncoding)
			// }
			//
			// // Get AWS_BUCKET environment variable
			// bucket := os.Getenv("AWS_BUCKET")
			//
			// // Create the AWS S3 upload key
			// key := engagement.ProductTypeName + "/" + engagement.ProductName + "/" + engagement.Name + "/" + string(stage) + "/" + string(filename)
			//
			// // Executes the logic of uploading a scan to AWS S3
			// uploadOutput, err := gcS3.UploadScan(bucket, key, fileBytes)
			// if err != nil {
			// 	logFatalf("%w: %v", ErrorEncoding, err)
			// 	return fmt.Errorf("%w: %v", ErrorEncoding, err)
			// }
			//
			// // Print message on successful upload
			// fmt.Printf("File successfully uploaded to S3!\n\nUploadOutput=%v", uploadOutput)
			//
			// // Return nil to satisfy want(error)
			// return nil

			// WIP: Testing
			// err := gcS3.UploadObjectToS3()
			// if err != nil {
			// 	return err
			// }
			gcS3.UploadObjectToS3()
			return nil
		},
	}
	exportCmd.AddCommand(defectDojoCmd)
	exportCmd.AddCommand(s3Cmd)
	return exportCmd
}

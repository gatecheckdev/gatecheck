package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/export/aws"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/spf13/cobra"
)

func NewExportCmd(
	service DDExportService,
	ddTimeout time.Duration,
	engagement defectdojo.EngagementQuery,
	awsService AWSExportService,
	upload aws.UploadQuery,
	awsTimeout time.Duration,
) *cobra.Command {
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
		RunE: func(_ *cobra.Command, args []string) error {
			// Open the file
			log.Infof("Opening file: %s", args[0])
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), ddTimeout)
			defer cancel()

			rType, fileBytes, err := artifact.ReadWithContext(ctx, f)
			log.Infof("file size: %d", len(fileBytes))
			log.Infof("Detected File Type: %s", rType)
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

	// gatecheck export aws command
	awsCmd := &cobra.Command{
		Use:     "aws [FILE]",
		Short:   "Export raw scan report to AWS S3",
		Aliases: []string{"s3"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Open the file
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), awsTimeout)
			defer cancel()

			_, fileBytes, err := artifact.ReadWithContext(ctx, f)
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorEncoding, err)
			}

			return awsService.Export(ctx, bytes.NewReader(fileBytes), upload)
		},
	}
	exportCmd.AddCommand(defectDojoCmd)
	exportCmd.AddCommand(awsCmd)
	return exportCmd
}

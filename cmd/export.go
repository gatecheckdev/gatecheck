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

			rType, err := artifact.InspectWithContext(ctx, f)
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

			return service.Export(ctx, f, engagement, ddScanType)
		},
	}
	exportCmd.AddCommand(defectDojoCmd)
	exportCmd.AddCommand(s3Cmd)
	return exportCmd
}

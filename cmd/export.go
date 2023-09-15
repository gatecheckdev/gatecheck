package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
	"github.com/spf13/cobra"
)

func newExportCmd(
	ddService ddExportService,
	ddTimeout time.Duration,
	newAsyncDecoder func() AsyncDecoder,
	ddEngagement defectdojo.EngagementQuery,
	awsService awsExportService,
	awsTimeout time.Duration,
) *cobra.Command {
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "Export a report to a target location",
	}

	defectDojoCmd := &cobra.Command{
		Use:     "defect-dojo [FILE]",
		Short:   "Export raw scan report to DefectDojo",
		Aliases: []string{"dd"},
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fullBom, _ := cmd.Flags().GetBool("full-bom")

			slog.Debug("Open", "filename", args[0])
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			slog.Debug("Decode", "filename", args[0])

			decoder := newAsyncDecoder()
			exportBuf := new(bytes.Buffer)
			multiWriter := io.MultiWriter(decoder, exportBuf)

			_, _ = io.Copy(multiWriter, f)
			obj, _ := decoder.Decode()

			var ddScanType defectdojo.ScanType
			switch obj.(type) {
			case *grype.ScanReport:
				ddScanType = defectdojo.Grype
			case *semgrep.ScanReport:
				ddScanType = defectdojo.Semgrep
			case *gitleaks.ScanReport:
				ddScanType = defectdojo.Gitleaks
			case *cyclonedx.ScanReport:
				ddScanType = defectdojo.CycloneDX
			default:
				return fmt.Errorf("%w: Unsupported file type", ErrorEncoding)
			}

			if ddScanType != defectdojo.CycloneDX && fullBom {
				return fmt.Errorf("%w: --full-bom is only permitted with a CycloneDx file", ErrorUserInput)
			}

			if fullBom {
				slog.Debug("Shimming components as vulnerabilities with 'none' severity")
				report := obj.(*cyclonedx.ScanReport)
				report = report.ShimComponentsAsVulnerabilities()
				exportBuf = new(bytes.Buffer)
				_ = json.NewEncoder(exportBuf).Encode(report)
			}

			ctx, cancel := context.WithTimeout(context.Background(), ddTimeout)
			defer cancel()

			return ddService.Export(ctx, exportBuf, ddEngagement, ddScanType)
		},
	}

	// gatecheck export aws command
	awsCmd := &cobra.Command{
		Use:   "s3 [FILE]",
		Short: "Export raw scan report to AWS S3",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Open the file
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			objectKey, _ := cmd.Flags().GetString("key")

			ctx, cancel := context.WithTimeout(context.Background(), awsTimeout)
			defer cancel()

			return awsService.Export(ctx, f, objectKey)
		},
	}
	awsCmd.Flags().String("key", "", "The AWS S3 object key for the location in the bucket")
	_ = awsCmd.MarkFlagRequired("key")

	exportCmd.PersistentFlags().BoolP("full-bom", "m", false, "CycloneDx: Adds all the components with no vulnerabilities as SeverityNone")
	exportCmd.AddCommand(defectDojoCmd)
	exportCmd.AddCommand(awsCmd)
	return exportCmd
}

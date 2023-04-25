package cmd

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/spf13/cobra"
)

// NewPrintCommand will pretty print a report file table, r can be piped input from standard out
func NewPrintCommand(decodeTimeout time.Duration, pipedFile *os.File) *cobra.Command {
	var command = &cobra.Command{
		Use:     "print [FILE ...]",
		Short:   "Pretty print a gatecheck report or security scan report",
		Example: "gatecheck print grype-report.json semgrep-report.json",
		RunE: func(cmd *cobra.Command, args []string) error {

			if pipedFile != nil {
				log.Infof("Piped File Received: %s", pipedFile.Name())
				err := ParseAndFPrint(pipedFile, cmd.OutOrStdout(), decodeTimeout)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorEncoding, err)
				}
			}

			for _, v := range args {
				log.Infof("Opening file: %s", v)
				f, err := os.Open(v)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				err = ParseAndFPrint(f, cmd.OutOrStdout(), decodeTimeout)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorEncoding, err)
				}
			}

			return nil
		},
	}

	return command
}

func ParseAndFPrint(r io.Reader, w io.Writer, timeout time.Duration) error {
	var err error

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	rType, b, err := artifact.ReadWithContext(ctx, r)

	if err != nil {
		return err
	}

	buf := bytes.NewBuffer(b)
	log.Infof("Bytes received: %d", len(b))
	log.Infof("Detected Type: %s", rType)

	// No need to check decode errors since it's decoded in the DetectReportType Function
	switch rType {
	case artifact.Cyclonedx:
		_, err = fmt.Fprintln(w, artifact.DecodeJSON[artifact.CyclonedxSbomReport](buf))
	case artifact.Semgrep:
		_, err = fmt.Fprintln(w, artifact.DecodeJSON[artifact.SemgrepScanReport](buf))
	case artifact.Grype:
		_, err = fmt.Fprintln(w, artifact.DecodeJSON[artifact.GrypeScanReport](buf))
	case artifact.Gitleaks:
		_, err = fmt.Fprintln(w, artifact.DecodeJSON[artifact.GitleaksScanReport](buf))
	case artifact.GatecheckBundle:
		bundle := artifact.DecodeBundle(buf)
		_, err = fmt.Fprintln(w, bundle.String())
	default:
		_, err = fmt.Fprintln(w, "Unsupported file type")
	}

	return err
}

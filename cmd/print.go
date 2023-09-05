package cmd

import (
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/dustin/go-humanize"
	gio "github.com/gatecheckdev/gatecheck/internal/io"
	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/spf13/cobra"
)

func newPrintCommand(pipedFile *os.File, newAsyncDecoder func() AsyncDecoder) *cobra.Command {
	var command = &cobra.Command{
		Use:     "print [FILE ...]",
		Short:   "Pretty print a gatecheck report or security scan report",
		Example: "gatecheck print grype-report.json semgrep-report.json",
		RunE: func(cmd *cobra.Command, args []string) error {

			if pipedFile != nil {
				slog.Debug("piped file detected", "filename", pipedFile.Name())
				v, _ := newAsyncDecoder().DecodeFrom(pipedFile)
				printArtifact(cmd.OutOrStdout(), v, newAsyncDecoder)
			}

			for _, filename := range args {
				v, _ := newAsyncDecoder().DecodeFrom(gio.NewLazyReader(filename))
				printArtifact(cmd.OutOrStdout(), v, newAsyncDecoder)
			}

			return nil
		},
	}

	return command
}

func printArtifact(w io.Writer, v any, newDecoder func() AsyncDecoder) {
	outputString := ""
	if v == nil {
		_, _ = strings.NewReader("fail").WriteTo(w)
		return
	}
	switch obj := v.(type) {
	case *grype.ScanReport:
		outputString = obj.String()
	case *semgrep.ScanReport:
		outputString = obj.String()
	case *gitleaks.ScanReport:
		outputString = obj.String()
	case *cyclonedx.ScanReport:
		outputString = obj.String()
	case *archive.Bundle:
		printBundleContentTable(w, obj, newDecoder)
		return
	}

	_, _ = strings.NewReader(outputString).WriteTo(w)

}

func printBundleContentTable(w io.Writer, bundle *archive.Bundle, newDecoder func() AsyncDecoder) {

	table := format.NewTable()
	table.AppendRow("Type", "Label", "Digest", "Size")

	for label, descriptor := range bundle.Manifest().Files {
		decoder := newDecoder()
		_, _ = bundle.WriteFileTo(decoder, label)
		obj, _ := decoder.Decode()
		typeStr := "Generic"
		fileSize := bundle.FileSize(label)
		switch obj.(type) {
		case *grype.ScanReport:
			typeStr = grype.ReportType
		case *semgrep.ScanReport:
			typeStr = semgrep.ReportType
		case *gitleaks.ScanReport:
			typeStr = gitleaks.ReportType
		case *cyclonedx.ScanReport:
			typeStr = cyclonedx.ReportType
		}
		table.AppendRow(typeStr, label, descriptor.Digest, humanize.Bytes(uint64(fileSize)))
	}
	_, _ = format.NewTableWriter(table).WriteTo(w)
}

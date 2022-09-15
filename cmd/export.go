package cmd

import (
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/exporter"
	"github.com/spf13/cobra"
	"os"
)

func NewExportCmd(e exporter.Exporter) *cobra.Command {
	var exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Export a report to a target location",
	}

	var defectDojoCmd = &cobra.Command{
		Use:   "defect-dojo",
		Short: "export raw scan report to Defect Dojo",
	}

	var grypeToDojoCmd = &cobra.Command{
		Use:   "grype <FILE>",
		Short: "export a grype file to Defect Dojo",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			// Open the file
			f, err := os.Open(args[0])
			if err != nil {
				return fmt.Errorf("Could not open grype report '%s': %w\n", args[0], err)
			}

			return e.ExportGrype(f)
		},
	}

	defectDojoCmd.AddCommand(grypeToDojoCmd)
	exportCmd.AddCommand(defectDojoCmd)
	return exportCmd
}

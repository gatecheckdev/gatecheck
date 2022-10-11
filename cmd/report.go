package cmd

import (
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"path"
)

func NewReportCmd(configFile *string, reportFile *string) *cobra.Command {
	// Flags
	var flagPipelineURL string
	var flagPipelineID string
	var flagProjectName string

	var reportCmd = &cobra.Command{
		Use:   "report",
		Short: "Manage the Gate Check report",
	}

	var reportUpdateCmd = &cobra.Command{
		Use:   "update",
		Short: "the configuration thresholds and other values on the report.",
		Long:  "Use any combination of flags --config, --url, --id, --name to edit the report",
		RunE: func(cmd *cobra.Command, args []string) error {

			// Open the config file, expecting an error if the file doesn't exist
			gatecheckConfig, err := OpenAndDecode[gatecheck.Config](*configFile, YAML)
			if err != nil {
				return err
			}

			gatecheckReport, err := OpenAndDecodeOrCreate[gatecheck.Report](*reportFile, JSON)
			if err != nil {
				return err
			}

			gatecheckReport = gatecheckReport.WithConfig(gatecheckConfig)

			gatecheckReport = gatecheckReport.WithSettings(gatecheck.Settings{
				ProjectName: flagProjectName,
				PipelineId:  flagPipelineID,
				PipelineUrl: flagPipelineURL,
			})

			cmd.Println(gatecheckReport)

			return OpenAndEncode(*reportFile, JSON, gatecheckReport)
		},
	}

	var reportPrintCmd = &cobra.Command{
		Use:   "print",
		Short: "Print the Gate Check Report",
		RunE: func(cmd *cobra.Command, args []string) error {

			gatecheckReport, err := OpenAndDecodeOrCreate[gatecheck.Report](*reportFile, JSON)
			if err != nil {
				return err
			}

			cmd.Println(gatecheckReport)
			return nil
		},
	}

	var reportAddCmd = &cobra.Command{
		Use:   "add",
		Short: "add an output file to the report",
	}

	var reportAddSemgrepCmd = &cobra.Command{
		Use:   "semgrep <FILE>",
		Short: "add a Semgrep scan file to the report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			// Decode the files into objects
			gatecheckConfig, err := OpenAndDecode[gatecheck.Config](*configFile, YAML)
			if err != nil {
				return err
			}

			gatecheckReport, err := OpenAndDecodeOrCreate[gatecheck.Report](*reportFile, JSON)
			if err != nil {
				return err
			}

			scanFile, err := Open(args[0])
			if err != nil {
				return err
			}

			// Create a semgrep artifact with the scan report
			artifact, err := semgrep.NewArtifact().WithScanReport(scanFile, path.Base(args[0]))
			if err != nil {
				return fmt.Errorf("%w : %v", ErrorDecode, err)
			}
			artifact = artifact.WithConfig(&gatecheckConfig.Semgrep)

			// Create an Asset from the Grype Scan and add it to the report
			gatecheckReport.Artifacts.Semgrep = *artifact

			// Write report to file
			return OpenAndEncode(*reportFile, JSON, gatecheckReport)
		},
	}

	var reportAddGrypeCmd = &cobra.Command{
		Use:   "grype <FILE>",
		Short: "add a grype scan file to the report",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {

			// Decode the files into objects
			gatecheckConfig, err := OpenAndDecode[gatecheck.Config](*configFile, YAML)
			if err != nil {
				return err
			}

			gatecheckReport, err := OpenAndDecodeOrCreate[gatecheck.Report](*reportFile, JSON)
			if err != nil {
				return err
			}

			grypeScanFile, err := Open(args[0])
			if err != nil {
				return err
			}

			// Create a grype artifact with the scan report
			grypeArtifact, err := grype.NewArtifact().WithScanReport(grypeScanFile, path.Base(args[0]))
			if err != nil {
				return fmt.Errorf("%w : %v", ErrorDecode, err)
			}
			grypeArtifact = grypeArtifact.WithConfig(&gatecheckConfig.Grype)

			// Create an Asset from the Grype Scan and add it to the report
			gatecheckReport.Artifacts.Grype = *grypeArtifact

			// Write report to file
			return OpenAndEncode(*reportFile, JSON, gatecheckReport)
		},
	}

	reportCmd.PersistentFlags().StringVar(&flagPipelineURL, "url", "",
		"The Pipeline URL for the report")
	reportCmd.PersistentFlags().StringVar(&flagPipelineID, "id", "",
		"The Pipeline ID for the report")
	reportCmd.PersistentFlags().StringVar(&flagProjectName, "name", "",
		"The Project name for the report")

	reportAddCmd.AddCommand(reportAddGrypeCmd, reportAddSemgrepCmd)
	reportCmd.AddCommand(reportAddCmd, reportPrintCmd, reportUpdateCmd)

	return reportCmd
}

package cmd

import (
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/report"
	"github.com/spf13/cobra"
)

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
		GateCheckConfig, GateCheckReport, err := internal.ConfigAndReportFrom(FlagConfigFile, FlagReportFile)

		if err != nil {
			return err
		}

		GateCheckReport = GateCheckReport.WithConfig(GateCheckConfig)
		GateCheckReport = GateCheckReport.WithSettings(report.Settings{
			ProjectName: flagProjectName,
			PipelineId:  flagPipelineID,
			PipelineUrl: flagPipelineURL,
		})

		cmd.Printf("Flag value: '%s'\n", flagPipelineURL)

		cmd.Println(GateCheckReport)

		return internal.ReportToFile(FlagReportFile, GateCheckReport)
	},
}

var reportPrintCmd = &cobra.Command{
	Use:   "print",
	Short: "Print the Gate Check Report",
	RunE: func(cmd *cobra.Command, args []string) error {

		_, GateCheckReport, err := internal.ConfigAndReportFrom(FlagConfigFile, FlagReportFile)
		if err != nil {
			return err
		}
		cmd.Println(GateCheckReport.String())
		return nil
	},
}

var reportAddCmd = &cobra.Command{
	Use:   "add",
	Short: "add an output file to the report",
}

var reportAddGrypeCmd = &cobra.Command{
	Use:   "grype <FILE>",
	Short: "add a grype scan file to the report",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {

		_, GateCheckReport, err := internal.ConfigAndReportFrom(FlagConfigFile, FlagReportFile)
		if err != nil {
			return err
		}
		scan, err := internal.GrypeScanFromFile(args[0])
		if err != nil {
			return err
		}

		// Create an Asset from the Grype Scan and add it to the report
		asset := grype.NewAsset(args[0]).WithScan(scan)
		GateCheckReport.Artifacts.Grype = *GateCheckReport.Artifacts.Grype.WithAsset(asset)

		// Write report to file
		return internal.ReportToFile(FlagReportFile, GateCheckReport)
	},
}

func init() {

	reportCmd.PersistentFlags().StringVar(&flagPipelineURL, "url", "",
		"The Pipeline URL for the report")
	reportCmd.PersistentFlags().StringVar(&flagPipelineID, "id", "",
		"The Pipeline ID for the report")
	reportCmd.PersistentFlags().StringVar(&flagProjectName, "name", "",
		"The Project name for the report")

	reportAddCmd.AddCommand(reportAddGrypeCmd)
	reportCmd.AddCommand(reportAddCmd, reportPrintCmd, reportUpdateCmd)
}

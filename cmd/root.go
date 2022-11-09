package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/exporter"
	"github.com/spf13/cobra"
)

// Defaults

const VersionNumber = "0.0.7"
const DefaultReportFile = "gatecheck-report.json"
const DefaultConfigFile = "gatecheck.yaml"

func NewRootCmd(e exporter.Exporter) *cobra.Command {
	// Flags

	var FlagConfigFile string
	var FlagReportFile string

	var RootCmd = &cobra.Command{
		Use:   "gatecheck",
		Short: "Gate Check is a 'go' 'no-go' status reporter",
		Long: `A tool used to collect job reports from various scans and
                   compare the findings to an expected threshold provided
                   gatecheck.yaml file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Printf(GatecheckLogo)
			return nil
		},
	}

	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Show the version and other defaults",
		RunE: func(cmd *cobra.Command, args []string) error {
			cmd.Printf("Gate Check Version %s\n", VersionNumber)
			cmd.Printf("Config File: %s\n", FlagConfigFile)
			cmd.Printf("Report File: %s\n", FlagReportFile)
			return nil
		},
	}

	RootCmd.PersistentFlags().StringVarP(&FlagConfigFile, "config", "c", DefaultConfigFile,
		"Gate Check configuration file")
	RootCmd.PersistentFlags().StringVarP(&FlagReportFile, "report", "r", DefaultReportFile,
		"Gate Check report file")

	RootCmd.AddCommand(versionCmd)

	RootCmd.AddCommand(NewConfigCmd(), NewReportCmd(&FlagConfigFile, &FlagReportFile),
		NewValidateCmd(&FlagConfigFile, &FlagReportFile), NewExportCmd(e))
	return RootCmd
}

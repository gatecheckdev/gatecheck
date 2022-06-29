package cmd

import (
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/validator"
	"github.com/spf13/cobra"
)

// Flags
var flagAudit bool
var flagIgnoreConfig bool

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "compare thresholds in config to findings in report",
	RunE: func(cmd *cobra.Command, args []string) error {
		var GateCheckConfig *config.Config
		var err error

		if flagIgnoreConfig == false {
			GateCheckConfig, err = internal.ConfigFromFile(FlagConfigFile)
			if err != nil {
				return err
			}
		}

		GateCheckReport, err := internal.ReportFromFile(FlagReportFile)
		if err != nil {
			return err
		}

		GateCheckReport = GateCheckReport.WithConfig(GateCheckConfig)

		err = validator.NewStdValidator(*GateCheckReport).Validate()

		if err != nil {
			cmd.PrintErrln(err.Error())
			if flagAudit == true {
				return nil
			}
			return internal.ErrorValidation
		}

		return nil
	},
}

func init() {
	validateCmd.PersistentFlags().BoolVarP(&flagIgnoreConfig, "ignore-config", "x", false,
		"Validate the report without using the thresholds from the gatecheck.yaml config")
	validateCmd.PersistentFlags().BoolVarP(&flagAudit, "audit", "a", false,
		"Print validation status without a non-zero exit code")
	RootCmd.AddCommand(validateCmd)
}

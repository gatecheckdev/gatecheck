package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func NewValidateCmd(configFile *string, reportFile *string) *cobra.Command {
	// Flags
	var flagAudit bool
	var flagIgnoreConfig bool

	var validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "compare thresholds in config to findings in report",
		RunE: func(cmd *cobra.Command, args []string) error {
			var config *gatecheck.Config
			var err error

			if flagIgnoreConfig == false {
				config, err = OpenAndDecode[gatecheck.Config](*configFile, YAML)
				if err != nil {
					return err
				}
			}

			report, err := OpenAndDecode[gatecheck.Report](*reportFile, JSON)
			if err != nil {
				return err
			}

			report = report.WithConfig(config)

			if err := report.Validate(); err != nil {
				cmd.PrintErrln(err.Error())
				if flagAudit == true {
					return nil
				}
				return ErrorValidation
			}

			return nil
		},
	}

	validateCmd.PersistentFlags().BoolVarP(&flagIgnoreConfig, "ignore-config", "x", false,
		"Validate the report without using the thresholds from the gatecheck.yaml config")
	validateCmd.PersistentFlags().BoolVarP(&flagAudit, "audit", "a", false,
		"Print validation status without a non-zero exit code")

	return validateCmd
}

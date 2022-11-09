package cmd

import (
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/blacklist"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
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

	var blacklistCmd = &cobra.Command{
		Use:   "blacklist <Grype Report FILE> <KEV Blacklist FILE>",
		Short: "Validate a Grype report with a CISA Known Exploited Vulnerabilities Blacklist",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			grypeReport, err := OpenAndDecode[entity.GrypeScanReport](args[0], JSON)
			if err != nil {
				return fmt.Errorf("%w : %v", ErrorDecode, err)
			}
			kevBlacklist, err := OpenAndDecode[entity.KEVCatalog](args[1], JSON)
			if err != nil {
				return fmt.Errorf("%w : %v", ErrorDecode, err)
			}

			blacklistedVulnerabilities := blacklist.BlacklistedVulnerabilities(*grypeReport, *kevBlacklist)

			cmd.Println(blacklist.StringBlacklistedVulnerabilities(kevBlacklist.CatalogVersion, blacklistedVulnerabilities))

			if flagAudit != true && len(blacklistedVulnerabilities) != 0 {
				return fmt.Errorf("%w : %d Vulnerabilities listed on CISA Known Exploited Vulnerabilities Blacklist",
					ErrorValidation, len(blacklistedVulnerabilities))
			}

			return nil
		},
	}

	validateCmd.AddCommand(blacklistCmd)

	validateCmd.PersistentFlags().BoolVarP(&flagIgnoreConfig, "ignore-config", "x", false,
		"Validate the report without using the thresholds from the gatecheck.yaml config")
	validateCmd.PersistentFlags().BoolVarP(&flagAudit, "audit", "a", false,
		"Print validation status without a non-zero exit code")

	return validateCmd
}

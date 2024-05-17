// Package cmd contains the CLI code for Gatecheck
//
// # Organization Methodology
//
// The goal for this package is readability, ease of maintainence, and
// seperation of concerns for easier testing and debugging.
//
// new<cmd name>Command functions should only build the command structure
// to include flag, cli options, and viper bindings.
// sub commands can also be included here as determined by the complexity
// of the command.
//
// run<Cmd/sub cmd name> functions are specific to cobra's runE functions
// it handles parsing arguments, opening files, and early returning errors.
// These commands eventually result in calls to functions in the package
// github.com/gatecheckdev/gatecheck/pkg/gatecheck

// The root file contains common helper functions used by other commands.
// Major commands can be in seperate files for ease of readability.
package cmd

import (
	"log/slog"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	ApplicationMetadata gatecheck.ApplicationMetadata
	LogLeveler          *slog.LevelVar = &slog.LevelVar{}
)

var gatecheckCmd = &cobra.Command{
	Use:   "gatecheck",
	Short: "Report validation tool",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		verbose := RuntimeConfig.Verbose.Value().(bool)
		silent := RuntimeConfig.Silent.Value().(bool)

		switch {
		case verbose:
			LogLeveler.Set(slog.LevelDebug)
			slog.Debug("debug logging enabled")
		case silent:
			LogLeveler.Set(slog.LevelError)
			slog.Debug("silent logging enabled")
		}
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		versionFlag, _ := cmd.Flags().GetBool("version")
		if versionFlag {
			return versionCmd.RunE(cmd, args)
		}
		return nil
	},
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "print version and build information",
	RunE: func(cmd *cobra.Command, args []string) error {
		_, err := ApplicationMetadata.WriteTo(cmd.OutOrStdout())
		return err
	},
}

// NewGatecheckCommand the root for all CLI commands
func NewGatecheckCommand() *cobra.Command {
	RuntimeConfig.Verbose.SetupCobra(gatecheckCmd)
	RuntimeConfig.Silent.SetupCobra(gatecheckCmd)

	gatecheckCmd.MarkFlagsMutuallyExclusive("verbose", "silent")
	gatecheckCmd.Flags().Bool("version", false, "print version and build information")

	_ = viper.BindEnv("cli.audit", "GATECHECK_CLI_AUDIT")

	_ = viper.BindEnv("cli.list.epss-file", "GATECHECK_EPSS_FILE")
	_ = viper.BindEnv("cli.validate.epss-file", "GATECHECK_EPSS_FILE")

	_ = viper.BindEnv("cli.validate.kev-file", "GATECHECK_KEV_FILE")

	_ = viper.BindEnv("api.epss-url", "GATECHECK_EPSS_URL")
	_ = viper.BindEnv("api.kev-url", "GATECHECK_KEV_URL")

	gatecheckCmd.SilenceUsage = true

	gatecheckCmd.AddCommand(
		versionCmd,
		newConfigCommand(),
		newListCommand(),
		newListAllCommand(),
		newBundleCommand(),
		newValidateCommand(),
		newDownloadCommand(),
	)
	return gatecheckCmd
}

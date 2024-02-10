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
// github.com/gatecheckdev/gatecheck/lib
//
// The root file contains common helper functions used by other commands.
// Major commands can be in seperate files for ease of readability.
package cmd

import (
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var ApplicationMetadata gatecheck.ApplicationMetadata

// NewGatecheckCommand the root for all CLI commands
func NewGatecheckCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "gatecheck",
		Short: "Report validation tool",
	}

	versionCmd := newBasicCommand("version", "print version information", runVersion)
	cmd.Flags().Bool("version", false, "print only the version of the CLI without additional information")

	cmd.AddCommand(versionCmd)
	return cmd
}

// runVersion prints the version and/or additional information about Gatecheck
//
// gatecheck version
// gatecheck --version
func runVersion(cmd *cobra.Command, args []string) error {
	versionFlag, _ := cmd.Flags().GetBool("version")
	switch {
	case versionFlag:
		cmd.Println(ApplicationMetadata.CLIVersion)
	default:
		ApplicationMetadata.WriteTo(cmd.OutOrStdout())
	}
	return nil
}

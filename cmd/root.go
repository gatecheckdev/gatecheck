// Package cmd contains the CLI code for Gatecheck.
//
// NewGatecheckCommand builds a fresh command tree on every call, so commands
// hold no state between runs. Each new<Name>Command function wires flags and
// reads settings in the order flag, then environment variable, then default.
// Command behavior that is not flag parsing lives in
// github.com/gatecheckdev/gatecheck/pkg/gatecheck.
package cmd

import (
	"errors"
	"fmt"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

// ApplicationMetadata is the build information printed by version. main sets it.
var ApplicationMetadata gatecheck.ApplicationMetadata

// Exit codes.
const (
	ExitOK = 0
	// ExitValidation means a report failed a configured threshold.
	ExitValidation = 1
	// ExitUsage means a bad command line, a file that could not be read or
	// written, or a report or config that could not be decoded.
	ExitUsage = 2
	// ExitFetch means EPSS or KEV data could not be downloaded or read.
	ExitFetch = 3
)

// ExitCode maps an error returned by the command tree to a process status.
// Scanner passthrough commands return the scanner's own status.
func ExitCode(err error) int {
	if err == nil {
		return ExitOK
	}
	var coder interface{ ExitCode() int }
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}
	switch {
	case errors.Is(err, gatecheck.ErrValidationFailure):
		return ExitValidation
	case errors.Is(err, gatecheck.ErrExternalData):
		return ExitFetch
	default:
		return ExitUsage
	}
}

// NewGatecheckCommand returns a new root command and its subcommands.
func NewGatecheckCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "gatecheck",
		Short:         "Report validation tool",
		SilenceUsage:  true,
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return setupLogging(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			if show, _ := cmd.Flags().GetBool("version"); show {
				_, err := ApplicationMetadata.WriteTo(cmd.OutOrStdout())
				return err
			}
			return nil
		},
	}
	addLoggingFlags(root)
	root.Flags().Bool("version", false, "print version and build information")
	root.SetFlagErrorFunc(func(cmd *cobra.Command, err error) error {
		return fmt.Errorf("%w\nRun '%s --help' for usage", err, cmd.CommandPath())
	})

	root.AddCommand(
		newVersionCommand(),
		newConfigCommand(),
		newListCommand(),
		newListAllCommand(),
		newBundleCommand(),
		newValidateCommand(),
		newDownloadCommand(),
		newAgentGuideCommand(),
		newBootstrapCommand(),
		newUpdateCommand(),
	)
	for _, tool := range []struct{ name, short string }{
		{"grype", "Run the managed grype scanner"},
		{"syft", "Run the managed syft scanner"},
		{"gitleaks", "Run the managed gitleaks scanner"},
		{"semgrep", "Run osemgrep from the managed semgrep wheel"},
		{"osemgrep", "Run osemgrep from the managed semgrep wheel"},
		{"trivy", "Run the managed trivy scanner"},
		{"osv-scanner", "Run the managed osv-scanner"},
		{"gosec", "Run the managed gosec scanner"},
		{"hadolint", "Run the managed hadolint linter"},
		{"zizmor", "Run the managed zizmor scanner"},
	} {
		root.AddCommand(newPassthroughCommand(tool.name, tool.short))
	}
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "print version and build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := ApplicationMetadata.WriteTo(cmd.OutOrStdout())
			return err
		},
	}
}

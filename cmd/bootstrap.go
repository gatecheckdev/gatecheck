package cmd

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/gatecheckdev/gatecheck/internal/bootstrap"
	"github.com/spf13/cobra"
)

func newBootstrapCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bootstrap",
		Short: "Install the scanners gatecheck reads reports from",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tools, err := cmd.Flags().GetString("tools")
			if err != nil {
				return err
			}
			force, err := cmd.Flags().GetBool("force")
			if err != nil {
				return err
			}
			list, err := cmd.Flags().GetBool("list")
			if err != nil {
				return err
			}
			return bootstrap.Bootstrap(cmd.Context(), bootstrap.Options{
				Home:      os.Getenv("GATECHECK_HOME"),
				ToolsCSV:  tools,
				Force:     force,
				List:      list,
				Stdout:    cmd.OutOrStdout(),
				Stderr:    cmd.ErrOrStderr(),
				UserAgent: gatecheckUserAgent(),
			})
		},
	}
	cmd.Flags().String("tools", "", "comma-separated scanners to install (default grype,syft,gitleaks,semgrep,trivy,osv-scanner)")
	cmd.Flags().Bool("force", false, "reinstall even when the pinned version is already present")
	cmd.Flags().Bool("list", false, "print pinned versions, installed versions, and paths")
	return cmd
}

func newPassthroughCommand(name, short string) *cobra.Command {
	return &cobra.Command{
		Use:                name,
		Short:              short,
		DisableFlagParsing: true,
		SilenceErrors:      true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := bootstrap.Run(cmd.Context(), name, args, os.Getenv("GATECHECK_HOME"), cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
			var exitErr *bootstrap.ExitError
			if errors.As(err, &exitErr) || errors.Is(err, bootstrap.ErrNotInstalled) {
				return err
			}
			if err != nil {
				_, _ = fmt.Fprintln(cmd.ErrOrStderr(), "gatecheck:", err)
			}
			return err
		},
	}
}

func gatecheckUserAgent() string {
	version := strings.TrimSpace(ApplicationMetadata.CLIVersion)
	if version == "" || version == "[Not Provided]" || strings.EqualFold(version, "unknown") {
		version = "unknown"
	}
	return fmt.Sprintf("gatecheck/%s (+https://github.com/gatecheckdev/gatecheck)", version)
}

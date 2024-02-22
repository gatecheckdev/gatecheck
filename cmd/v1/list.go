package cmd

import (
	"log/slog"
	"slices"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var supportedTypes = []string{"grype", "semgrep", "gitleaks", "syft", "cyclonedx", "bundle"}

func newListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list",
		Short: "print a summarized view of a security report artifact",
		RunE:  runList,
		Args:  cobra.MaximumNArgs(1),
	}

	cmd.Aliases = []string{"ls", "print"}

	cmd.Flags().StringP("input-type", "i", "", "the input filetype if using STDIN [grype|semgrep|gitleaks|syft]")

	return cmd
}

func runList(cmd *cobra.Command, args []string) error {
	slog.Debug("list artifact summary")
	filename := ""

	if len(args) > 0 {
		filename = args[0]
	}

	inputType, _ := cmd.Flags().GetString("input-type")

	src, err := fileOrStdin(filename, cmd)
	if err != nil {
		return err
	}

	if slices.Contains(supportedTypes, inputType) {
		filename = "stdin:" + inputType
	}

	return gatecheck.List(cmd.OutOrStdout(), src, filename)
}

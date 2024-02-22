package cmd

import (
	"io"
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
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

	var src io.Reader

	switch {
	case filename != "":
		f, err := os.Open(filename)
		if err != nil {
			return err
		}
		src = f
	case slices.Contains(supportedTypes, inputType):
		filename = "stdin:" + inputType
		src = cmd.InOrStdin()
	default:
		slog.Error("")
	}

	return gatecheck.List(cmd.OutOrStdout(), src, filename)
}

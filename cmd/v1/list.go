package cmd

import (
	"log/slog"
	"net/http"
	"slices"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
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

	cmd.Flags().StringP("input-type", "i", "", "the input filetype if using STDIN [grype|semgrep|gitleaks|syft|bundle]")
	cmd.Flags().BoolP("all", "a", false, "list will EPSS scores and KEV Catalog check")

	viper.BindEnv("epss-url", "GATECHECK_EPSS_URL")

	return cmd
}

func runList(cmd *cobra.Command, args []string) error {
	slog.Debug("list artifact summary")
	filename := ""

	if len(args) > 0 {
		filename = args[0]
	}

	inputType, _ := cmd.Flags().GetString("input-type")
	listAll, err := cmd.Flags().GetBool("all")
	epssURL := viper.GetString("epss-url")

	src, err := fileOrStdin(filename, cmd)
	if err != nil {
		return err
	}

	if slices.Contains(supportedTypes, inputType) {
		filename = "stdin:" + inputType
	}

	if listAll {
		return gatecheck.ListAll(cmd.OutOrStdout(), src, filename, http.DefaultClient, epssURL)
	}
	return gatecheck.List(cmd.OutOrStdout(), src, filename)
}

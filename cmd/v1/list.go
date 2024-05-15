package cmd

import (
	"io"
	"log/slog"
	"net/http"
	"os"
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

	cmd.Flags().String("epss-file", "", "use this file for epss scores, will not query API")
	_ = viper.BindPFlag("cli.list.epss-file", cmd.Flags().Lookup("epss-file"))

	cmd.Flags().Bool("markdown", false, "print the list as markdown")

	return cmd
}

func runList(cmd *cobra.Command, args []string) error {
	slog.Debug("list artifact summary")
	filename := ""

	if len(args) > 0 {
		filename = args[0]
	}

	inputType, _ := cmd.Flags().GetString("input-type")
	listAll, _ := cmd.Flags().GetBool("all")
	markdown, _ := cmd.Flags().GetBool("markdown")

	epssURL := viper.GetString("api.epss-url")
	epssFilename := viper.GetString("cli.list.epss-file")

	displayFormat := "ascii"
	if markdown {
		displayFormat = "markdown"
	}

	src, err := fileOrStdin(filename, cmd)
	if err != nil {
		return err
	}

	if slices.Contains(supportedTypes, inputType) {
		filename = "stdin:" + inputType
	}

	var epssFile io.Reader

	if epssFilename != "" {
		slog.Debug("open epss", "filename", epssFilename)
		listAll = true
		epssFile, err = os.Open(epssFilename)
		if err != nil {
			return err
		}
	}

	if listAll {
		slog.Debug("listing with epss scores")
		return gatecheck.ListAll(
			cmd.OutOrStdout(),
			src,
			filename,
			http.DefaultClient,
			epssURL,
			epssFile,
			gatecheck.WithDisplayFormat(displayFormat),
		)
	}

	return gatecheck.List(
		cmd.OutOrStdout(),
		src,
		filename,
		gatecheck.WithDisplayFormat(displayFormat),
	)
}

package cmd

import (
	"io"
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func newConfigCommand() *cobra.Command {
	// common flags

	initCmd := newBasicCommand("init", "output an example configuration file", runConfigInit)
	initCmd.Flags().StringP("output", "o", "yaml", "config output format (<format>=<file>) empty will write to STDOUT, formats=[json yaml yml toml]")

	cmd := &cobra.Command{Use: "config", Short: "manage the gatecheck configuration file"}
	cmd.AddCommand(initCmd)
	return cmd
}

func runConfigInit(cmd *cobra.Command, _ []string) error {
	var targetWriter io.Writer

	output, _ := cmd.Flags().GetString("output")

	format, filename := ParsedOutput(output)

	switch {
	case filename == "":
		targetWriter = cmd.OutOrStdout()
	default:
		slog.Debug("open", "filename", filename)
		f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		targetWriter = f
	}

	return gatecheck.WriteDefaultConfig(targetWriter, format)
}

package cmd

import (
	"errors"
	"log/slog"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func newConfigCommand() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "manage the gatecheck configuration file",
	}

	initCmd := &cobra.Command{
		Use:   "init",
		Short: "print the default configuration file",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			output, _ := cmd.Flags().GetString("output")
			return gatecheck.EncodeConfigTo(cmd.OutOrStdout(), gatecheck.NewDefaultConfig(), output)
		},
	}

	convertCmd := &cobra.Command{
		Use:   "convert",
		Short: "convert an existing configuration file into another format",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			filename, _ := cmd.Flags().GetString("file")
			output, _ := cmd.Flags().GetString("output")
			if _, err := gatecheck.ConfigFormat(output); err != nil {
				return err
			}
			config := &gatecheck.Config{}
			err := gatecheck.NewConfigDecoder(filename).Decode(config)
			if errors.Is(err, gatecheck.ErrUnknownConfigKeys) {
				slog.Warn("config has keys gatecheck does not read; they are dropped from the output", "filename", filename, "keys", strings.TrimPrefix(err.Error(), gatecheck.ErrUnknownConfigKeys.Error()+": "))
			} else if err != nil {
				return err
			}
			return gatecheck.EncodeConfigTo(cmd.OutOrStdout(), config, output)
		},
	}

	convertCmd.Flags().StringP("file", "f", "gatecheck.yaml", "gatecheck validation config file")
	convertCmd.Flags().StringP("output", "o", "yaml", "format to write: json, yaml, yml, or toml")
	initCmd.Flags().StringP("output", "o", "yaml", "format to write: json, yaml, yml, or toml")
	_ = convertCmd.MarkFlagFilename("file", "json", "yaml", "yml", "toml")

	configCmd.AddCommand(initCmd, convertCmd)
	return configCmd
}

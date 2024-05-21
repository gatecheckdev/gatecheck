package cmd

import (
	"errors"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "manage the gatecheck configuration file",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "output an example configuration file",
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")

		switch output {
		case "json", ".json":
			output = ".json"
		case "toml", ".toml":
			output = ".toml"
		case "yaml", "yml", ".yaml", ".yml":
			output = ".yaml"
		default:
			return errors.New("invalid --output format, must be json,toml,yaml, or yml")
		}

		return gatecheck.NewConfigEncoder(cmd.OutOrStdout(), output).Encode(gatecheck.NewDefaultConfig())
	},
}

var configConvertCmd = &cobra.Command{
	Use:   "convert",
	Short: "convert and existing configuration file into another format",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		configFilename, _ := cmd.Flags().GetString("file")
		RuntimeConfig.gatecheckConfig = &gatecheck.Config{}
		err := gatecheck.NewConfigDecoder(configFilename).Decode(RuntimeConfig.gatecheckConfig)
		if err != nil {
			return err
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")

		switch output {
		case "json", ".json":
			output = ".json"
		case "toml", ".toml":
			output = ".toml"
		case "yaml", "yml", ".yaml", ".yml":
			output = ".yaml"
		default:
			return errors.New("invalid --output format, must be json, toml, yaml, or yml")
		}

		return gatecheck.NewConfigEncoder(cmd.OutOrStdout(), output).Encode(RuntimeConfig.gatecheckConfig)
	},
}

func newConfigCommand() *cobra.Command {
	configConvertCmd.Flags().StringP("file", "f", "gatecheck.yaml", "gatecheck validation config file")
	configConvertCmd.Flags().StringP("output", "o", "yaml", "Format to convert into formats=[json yaml yml toml]")
	configInitCmd.Flags().StringP("output", "o", "yaml", "Format to convert into formats=[json yaml yml toml]")

	_ = configConvertCmd.MarkFlagFilename("file", "json", "yaml", "yml", "toml")
	_ = configInitCmd.MarkFlagFilename("file", "json", "yaml", "yml", "toml")

	configCmd.AddCommand(configInitCmd, configConvertCmd)
	return configCmd
}

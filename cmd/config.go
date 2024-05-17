package cmd

import (
	"log/slog"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "manage the gatecheck configuration file",
}

var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "output an example configuration file",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")
		format, filename := ParsedOutput(output)
		dst, err := fileOrStdout(filename, cmd)
		if err != nil {
			return err
		}
		RuntimeConfig.configOutputWriter = dst
		RuntimeConfig.configOutputFormat = format
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		dst := RuntimeConfig.configOutputWriter
		fmt := RuntimeConfig.configOutputFormat
		return gatecheck.WriteDefaultConfig(dst, fmt)
	},
}

var configInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "debug output of the set configuration values",
	RunE: func(cmd *cobra.Command, args []string) error {
		configFilename, _ := cmd.Flags().GetString("config-file")

		slog.Debug("config info", "config_filename", configFilename)

		if configFilename == "" {
			return WriteConfigInfo(cmd.OutOrStdout(), viper.GetViper(), gatecheck.NewDefaultConfig())
		}

		config := new(gatecheck.Config)
		_ = LoadConfigFromFile(config, configFilename)

		return WriteConfigInfo(cmd.OutOrStdout(), viper.GetViper(), config)
	},
}

var configConvertCmd = &cobra.Command{
	Use:   "convert",
	Short: "convert and existing configuration file into another format",
	PreRunE: func(cmd *cobra.Command, args []string) error {
		output, _ := cmd.Flags().GetString("output")
		format, filename := ParsedOutput(output)
		dst, err := fileOrStdout(filename, cmd)
		if err != nil {
			return err
		}
		RuntimeConfig.configOutputWriter = dst
		RuntimeConfig.configOutputFormat = format

		inputFilename, _ := cmd.Flags().GetString("input-file")
		inputFiletype, _ := cmd.Flags().GetString("input-type")

		RuntimeConfig.gatecheckConfig = new(gatecheck.Config)
		err = LoadConfigFromFileOrReader(
			RuntimeConfig.gatecheckConfig, inputFilename, cmd.InOrStdin(), inputFiletype,
		)
		if err != nil {
			return err
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {

		dst := RuntimeConfig.configOutputWriter
		fmt := RuntimeConfig.configOutputFormat
		return gatecheck.EncodeConfigTo(dst, RuntimeConfig.gatecheckConfig, fmt)
	},
}

func newConfigCommand() *cobra.Command {
	configInitCmd.Flags().StringP("output", "o", "yaml", "config output format (<format>=<file>) empty will write to STDOUT, formats=[json yaml yml toml]")

	configConvertCmd.Flags().StringP("output", "o", "yaml", "config output format and optional output file (<format>=<file>) empty will write to STDOUT, formats=[json yaml yml toml]")
	configConvertCmd.Flags().StringP("input-type", "i", "", "config input format ONLY with STDIN, formats=[json yaml yml toml]")
	configConvertCmd.Flags().StringP("input-file", "f", "", "source file to convert")

	_ = configConvertCmd.MarkFlagFilename("input-file", "json", "yaml", "yml", "toml")

	cmd := &cobra.Command{}
	cmd.AddCommand(configInfoCmd, configInfoCmd, configConvertCmd)
	return cmd
}

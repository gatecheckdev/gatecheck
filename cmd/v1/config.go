package cmd

import (
	"fmt"
	"log/slog"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newConfigCommand() *cobra.Command {
	// common flags

	initCmd := newBasicCommand("init", "output an example configuration file", runConfigInit)
	initCmd.Flags().StringP("output", "o", "yaml", "config output format (<format>=<file>) empty will write to STDOUT, formats=[json yaml yml toml]")

	infoCmd := newBasicCommand("info", "debug output of the set configuration values", runConfigInfo)
	infoCmd.Flags().StringP("input-file", "f", "", "source file to import")
	infoCmd.Flags().StringP("input-type", "i", "", "config input format ONLY with STDIN, formats=[json yaml yml toml]")

	infoCmd.MarkFlagsOneRequired("input-file", "input-type")

	convertCmd := newBasicCommand("convert", "convert and existing configuration file into another format", runConfigConvert)
	convertCmd.Flags().StringP("output", "o", "yaml", "config output format and optional output file (<format>=<file>) empty will write to STDOUT, formats=[json yaml yml toml]")
	convertCmd.Flags().StringP("input-type", "i", "", "config input format ONLY with STDIN, formats=[json yaml yml toml]")
	convertCmd.Flags().StringP("input-file", "f", "", "source file to convert")

	_ = convertCmd.MarkFlagFilename("input-file", "json", "yaml", "yml", "toml")

	cmd := &cobra.Command{Use: "config", Short: "manage the gatecheck configuration file"}
	cmd.AddCommand(initCmd, infoCmd, convertCmd)
	return cmd
}

func runConfigInit(cmd *cobra.Command, _ []string) error {
	output, _ := cmd.Flags().GetString("output")

	format, filename := ParsedOutput(output)

	dst, err := fileOrStdout(filename, cmd)
	if err != nil {
		return nil
	}

	return gatecheck.WriteDefaultConfig(dst, format)
}

func runConfigInfo(cmd *cobra.Command, _ []string) error {
	inputFilename, _ := cmd.Flags().GetString("input-file")
	inputFiletype, _ := cmd.Flags().GetString("input-type")

	config, err := ConfigFromViperFileOrStdin(viper.GetViper(), inputFilename, inputFiletype, cmd)
	if err != nil {
		return err
	}

	slog.Debug("print config values", "config", config)
	for _, key := range viper.AllKeys() {
		fmt.Fprintf(cmd.OutOrStdout(), "%-30s %v\n", key, viper.Get(key))
	}

	return nil
}

func runConfigConvert(cmd *cobra.Command, _ []string) error {
	output, _ := cmd.Flags().GetString("output")

	outFormat, outFilename := ParsedOutput(output)

	dstFile, err := fileOrStdout(outFilename, cmd)
	if err != nil {
		return err
	}

	inputFilename, _ := cmd.Flags().GetString("input-file")
	inputFiletype, _ := cmd.Flags().GetString("input-type")

	config, err := ConfigFromViperFileOrStdin(viper.GetViper(), inputFilename, inputFiletype, cmd)
	if err != nil {
		return err
	}

	return gatecheck.EncodeConfigTo(dstFile, config, outFormat)
}

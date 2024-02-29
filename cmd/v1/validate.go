package cmd

import (
	"io"
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func newValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [FILE]",
		Short: "compare vulnerabilities to configured thresholds",
		Args:  cobra.ExactArgs(1),
		RunE:  runValidate,
	}

	cmd.Flags().StringP("config", "f", "", "threshold configuration file")

	cmd.Flags().String("epss-file", "", "use this file for epss scores, will not query API")
	_ = viper.BindPFlag("cli.epss-file", cmd.Flags().Lookup("epss-file"))

	cmd.Flags().String("kev-file", "", "use this file for kev catalog, will not query API")
	_ = viper.BindPFlag("cli.kev-file", cmd.Flags().Lookup("kev-file"))

	return cmd
}

// runValidate
//
// shell: gatecheck validate
func runValidate(cmd *cobra.Command, args []string) error {
	configFilename, _ := cmd.Flags().GetString("config")
	targetFilename := args[0]
	epssURL := viper.GetString("api.epss-url")
	kevURL := viper.GetString("api.kev-url")
	epssFilename := viper.GetString("cli.epss-file")
	kevFilename := viper.GetString("cli.kev-file")

	slog.Debug("read in config", "filename", configFilename, "target_filename", targetFilename)

	config := gatecheck.NewDefaultConfig()
	if configFilename != "" {
		err := LoadConfigFromFile(config, configFilename)
		if err != nil {
			return err
		}
	} else {
		slog.Warn("no configuration file given, will use default configuration file")
	}

	slog.Debug("open target file", "filename", targetFilename)
	targetFile, err := os.Open(targetFilename)
	if err != nil {
		return err
	}

	var epssFile, kevFile io.Reader

	if epssFilename != "" {
		slog.Debug("open epss file", "filename", epssFilename)
		epssFile, err = os.Open(epssFilename)
		if err != nil {
			return err
		}
	}

	if kevFilename != "" {
		slog.Debug("open kev file", "filename", epssFilename)
		kevFile, err = os.Open(kevFilename)
		if err != nil {
			return err
		}
	}
	return gatecheck.Validate(
		config,
		targetFile,
		targetFilename,
		gatecheck.WithEPSSURL(epssURL),
		gatecheck.WithKEVURL(kevURL),
		gatecheck.WithEPSSFile(epssFile),
		gatecheck.WithKEVFile(kevFile),
	)
}

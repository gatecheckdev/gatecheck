package cmd

import (
	"fmt"
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
	_ = viper.BindPFlag("cli.validate.epss-file", cmd.Flags().Lookup("epss-file"))

	cmd.Flags().String("kev-file", "", "use this file for kev catalog, will not query API")
	_ = viper.BindPFlag("cli.validate.kev-file", cmd.Flags().Lookup("kev-file"))

	cmd.Flags().Bool("audit", false, "audit mode - will run all rules but wil always exit 0 for validation failures")
	_ = viper.BindPFlag("cli.validate.audit", cmd.Flags().Lookup("audit"))

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

	epssFilename := viper.GetString("cli.validate.epss-file")
	kevFilename := viper.GetString("cli.validate.kev-file")

	audit := viper.GetBool("cli.validate.audit")

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
		slog.Debug("open kev file", "filename", kevFilename)
		kevFile, err = os.Open(kevFilename)
		if err != nil {
			return err
		}
	}

	err = gatecheck.Validate(
		config,
		targetFile,
		targetFilename,
		gatecheck.WithEPSSURL(epssURL),
		gatecheck.WithKEVURL(kevURL),
		gatecheck.WithEPSSFile(epssFile),
		gatecheck.WithKEVFile(kevFile),
	)

	if audit && err != nil {
		slog.Error("validation failure in audit mode")
		fmt.Fprintln(cmd.ErrOrStderr(), err)
		return nil
	}

	return err
}

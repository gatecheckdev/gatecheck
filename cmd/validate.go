package cmd

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var validateCmd = &cobra.Command{
	Use:   "validate [FILE]",
	Short: "compare vulnerabilities to configured thresholds",
	Args:  cobra.ExactArgs(1),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		configFilename := RuntimeConfig.ConfigFilename.Value().(string)

		RuntimeConfig.gatecheckConfig = gatecheck.NewDefaultConfig()
		if configFilename != "" {
			err := gatecheck.NewConfigDecoder(configFilename).Decode(RuntimeConfig.gatecheckConfig)
			if err != nil {
				return err
			}
		}

		var err error

		epssFilename := RuntimeConfig.EPSSFilename.Value().(string)
		if epssFilename != "" {
			RuntimeConfig.epssFile, err = os.Open(epssFilename)
		}
		if err != nil {
			return err
		}

		kevFilename := RuntimeConfig.KEVFilename.Value().(string)
		if kevFilename != "" {
			RuntimeConfig.kevFile, err = os.Open(kevFilename)
		}
		if err != nil {
			return err
		}

		targetFilename := args[0]
		slog.Debug("open target file", "filename", targetFilename)
		RuntimeConfig.targetFile, err = os.Open(targetFilename)
		if err != nil {
			return err
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		err := gatecheck.Validate(
			RuntimeConfig.gatecheckConfig,
			RuntimeConfig.targetFile,
			args[0],
			gatecheck.WithEPSSURL(RuntimeConfig.EPSSURL.Value().(string)),
			gatecheck.WithKEVURL(RuntimeConfig.KEVURL.Value().(string)),
			gatecheck.WithEPSSFile(RuntimeConfig.epssFile), // TODO: fix this
			gatecheck.WithKEVFile(RuntimeConfig.kevFile),
		)

		audit := RuntimeConfig.Audit.Value().(bool)
		if audit && err != nil {
			slog.Error("validation failure in audit mode")
			fmt.Fprintln(cmd.ErrOrStderr(), err)
			return nil
		}

		return err
	},
}

func newValidateCommand() *cobra.Command {

	RuntimeConfig.ConfigFilename.SetupCobra(validateCmd)
	RuntimeConfig.EPSSFilename.SetupCobra(validateCmd)
	RuntimeConfig.KEVFilename.SetupCobra(validateCmd)
	RuntimeConfig.Audit.SetupCobra(validateCmd)

	return validateCmd
}

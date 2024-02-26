package cmd

import (
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

func NewValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [FILE]",
		Short: "compare vulnerabilities to configured thresholds",
		Args:  cobra.ExactArgs(1),
		RunE:  runValidate,
	}

	cmd.Flags().StringP("config", "f", "", "threshold configuration file")

	return cmd
}

// runValidate
//
// shell: gatecheck validate
func runValidate(cmd *cobra.Command, args []string) error {
	configFilename, _ := cmd.Flags().GetString("config")
	targetFilename := args[0]

	slog.Debug("read in config", "filename", configFilename, "target_filename", targetFilename)

	config := gatecheck.NewDefaultConfig()
	if configFilename != "" {
		err := LoadConfigFromFile(viper.GetViper(), config, configFilename)

		if err != nil {
			return err
		}
	}

	slog.Debug("open target file")
	targetFile, err := os.Open(targetFilename)
	if err != nil {
		return err
	}

	return gatecheck.Validate(config, targetFile, targetFilename)
}

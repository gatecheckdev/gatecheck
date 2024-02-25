package cmd

import (
	"github.com/spf13/cobra"
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
	// configFilename, _ := cmd.Flags().GetString("config")
	// targetFilename := args[0]

	// slog.Debug("read in config", "filename", configFilename, "target_filename", targetFilename)

	// config, err := ConfigFromViperFileOrStdin(viper.GetViper(), configFilename, "", cmd)
	// if err != nil {
	// 	return err
	// }

	// slog.Debug("open target file")
	// targetFile, err := os.Open(targetFilename)
	// if err != nil {
	// 	return err
	// }
	return nil
	// return gatecheck.Validate(config, targetFile, targetFilename)
}

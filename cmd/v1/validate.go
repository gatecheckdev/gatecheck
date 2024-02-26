package cmd

import (
	"log/slog"
	"net/http"
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
	_ = viper.BindEnv("api.epss-url", "GATECHECK_EPSS_URL")
	_ = viper.BindEnv("api.kev-url", "GATECHECK_KEV_URL")

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

	epssOptions := gatecheck.WithEPSSDataFetch(http.DefaultClient, epssURL)
	kevOptions := gatecheck.WithKEVDataFetch(http.DefaultClient, kevURL)

	switch {
	case epssURL != "" && kevURL != "":
		return gatecheck.Validate(config, targetFile, targetFilename, epssOptions, kevOptions)
	case epssURL != "":
		return gatecheck.Validate(config, targetFile, targetFilename, epssOptions)
	case kevURL != "":
		return gatecheck.Validate(config, targetFile, targetFilename, kevOptions)
	default:
		return gatecheck.Validate(config, targetFile, targetFilename)
	}
}

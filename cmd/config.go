package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/spf13/cobra"
)

func NewConfigCmd() *cobra.Command {

	var configCmd = &cobra.Command{
		Use:   "config",
		Short: "Configuration file for the predetermined thresholds",
	}

	var configInitCmd = &cobra.Command{
		Use:   "init <PATH|FLE> [PROJECT NAME]",
		Short: "Create a default configuration file",
		Args:  cobra.RangeArgs(1, 2),
		Long: `Passing a directory will create the gatecheck.yaml file in that
				directory. A directory must EXIST before a file will be created
				in that directory. The name of the file can be specified but you
				will have to use the --config option to specify that specific
				configuration file.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Set the project name
			projectName := "Project Name"
			if len(args) == 2 {
				projectName = args[1]
			}

			targetFile, err := internal.NewFile(args[0], DefaultConfigFile)

			if err != nil {
				return err
			}

			// Create a new configuration
			newConfig := config.NewConfig(projectName)

			// Write the new configuration to file
			_ = json.NewEncoder(targetFile).Encode(newConfig)

			_, _ = fmt.Fprintln(cmd.OutOrStderr(), "New configuration file crated")
			return nil
		},
	}

	configCmd.AddCommand(configInitCmd)

	return configCmd
}

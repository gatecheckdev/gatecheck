package cmd

import "github.com/spf13/cobra"

func newConfigCommand() *cobra.Command {
	cmd := &cobra.Command{Use: "config", Short: "manage the gatecheck configuration file"}

	return cmd
}

func runConfigInit(cmd *cobra.Command, _ []string) error {
	return nil
}

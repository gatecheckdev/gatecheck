package cmd

import "github.com/spf13/cobra"

// newBasicCommand is a simple wrapper that fills the minimum necessary fields for cobra commands
func newBasicCommand(use string, short string, runE func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, RunE: runE}
}

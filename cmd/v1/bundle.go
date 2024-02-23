package cmd

import (
	"log/slog"

	"github.com/spf13/cobra"
)

func newBundleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "create and manage a gatecheck bundle",
		Args:  cobra.ExactArgs(1),
	}

	addCmd := newBasicCommand("add", "add a file to a bundle", runAdd)
	rmCmd := newBasicCommand("rm", "remove a file from a bundle", runRm)

	cmd.PersistentFlags().StringP("output", "o", "gatecheck-bundle.tar.gz", "bundle file output destination")

	addCmd.Flags().StringSliceP("tag", "t", []string{}, "file properties for metadata")

	cmd.AddCommand(addCmd, rmCmd)
	return cmd
}

// runAdd
// shell: gatecheck bundle add <file> -o gatecheck-bundle.tar.gz -t custom-tag-value
func runAdd(cmd *cobra.Command, args []string) error {
	filename := args[0]
	bundleFilename, _ := cmd.Flags().GetString("output")
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("add file to bundle", "filename", filename, "bundle_output_filename",
		bundleFilename, "tags", tags)
	return nil
}

// runRm
// shell: gatecheck bundle rm <file label> -o gatecheck-bundle.tar.gz
func runRm(cmd *cobra.Command, args []string) error {
	fileLabel := args[0]
	bundleFilename, _ := cmd.Flags().GetString("output")
	slog.Debug("add file to bundle", "file_label", fileLabel,
		"bundle_output_filename", bundleFilename)

	return nil
}

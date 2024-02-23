package cmd

import (
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func newBundleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "create and manage a gatecheck bundle",
		Args:  cobra.ExactArgs(1),
	}

	createCmd := newBasicCommand("create", "create a new bundle with a new file", runBundleCreate)
	addCmd := newBasicCommand("add", "add a file to a bundle", runBundleAdd)
	rmCmd := newBasicCommand("rm", "remove a file from a bundle", runBundleRm)

	cmd.PersistentFlags().StringP("output", "o", "gatecheck-bundle.tar.gz", "bundle file output destination")

	addCmd.Flags().StringSliceP("tag", "t", []string{}, "file properties for metadata")
	createCmd.Flags().StringSliceP("tag", "t", []string{}, "file properties for metadata")

	cmd.AddCommand(createCmd, addCmd, rmCmd)
	return cmd
}

func runBundleCreate(cmd *cobra.Command, args []string) error {
	srcFilename := args[0]
	bundleFilename, _ := cmd.Flags().GetString("output")
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("create a new bundle", "filename", srcFilename, "bundle_output_filename",
		bundleFilename, "tags", tags)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	srcFile, err := os.Open(srcFilename)
	if err != nil {
		return err
	}

	return gatecheck.CreateBundle(bundleFile, srcFile, srcFilename, tags)
}

// runBundleAdd
// shell: gatecheck bundle add <file> -o gatecheck-bundle.tar.gz -t custom-tag-value
func runBundleAdd(cmd *cobra.Command, args []string) error {
	srcFilename := args[0]
	bundleFilename, _ := cmd.Flags().GetString("output")
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("add file to bundle", "filename", srcFilename, "bundle_output_filename",
		bundleFilename, "tags", tags)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	srcFile, err := os.Open(srcFilename)
	if err != nil {
		return err
	}

	return gatecheck.AppendToBundle(bundleFile, srcFile, srcFilename, tags)
}

// runBundleRm
// shell: gatecheck bundle rm <file label> -o gatecheck-bundle.tar.gz
func runBundleRm(cmd *cobra.Command, args []string) error {
	fileLabel := args[0]
	bundleFilename, _ := cmd.Flags().GetString("output")
	slog.Debug("add file to bundle", "file_label", fileLabel,
		"bundle_output_filename", bundleFilename)

	return nil
}

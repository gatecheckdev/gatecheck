package cmd

import (
	"log/slog"
	"os"
	"path"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func newBundleCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bundle",
		Short: "create and manage a gatecheck bundle",
	}

	createCmd := newBasicCommand("create BUNDLE_FILE TARGET_FILE", "create a new bundle with a new file", runBundleCreate)
	createCmd.Args = cobra.ExactArgs(2)
	createCmd.Flags().StringSliceP("tag", "t", []string{}, "file properties for metadata")

	addCmd := newBasicCommand("add BUNDLE_FILE TARGET_FILE", "add a file to a bundle", runBundleAdd)
	addCmd.Args = cobra.ExactArgs(2)
	addCmd.Flags().StringSliceP("tag", "t", []string{}, "file properties for metadata")

	rmCmd := newBasicCommand("rm BUNDLE_FILE TARGET_FILE", "remove a file from a bundle by label", runBundleRm)
	rmCmd.Args = cobra.ExactArgs(2)

	cmd.AddCommand(createCmd, addCmd, rmCmd)
	return cmd
}

func runBundleCreate(cmd *cobra.Command, args []string) error {
	bundleFilename := args[0]
	targetFilename := args[1]
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("create a new bundle", "bundle_filename", bundleFilename, "target_filename", targetFilename)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	targetFile, err := os.Open(targetFilename)
	if err != nil {
		return err
	}

	label := path.Base(targetFilename)
	return gatecheck.CreateBundle(bundleFile, targetFile, label, tags)
}

// runBundleAdd
// shell: gatecheck bundle add <file> -o gatecheck-bundle.tar.gz -t custom-tag-value
func runBundleAdd(cmd *cobra.Command, args []string) error {
	bundleFilename := args[0]
	targetFilename := args[1]
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("add new bundle", "bundle_filename", bundleFilename, "target_filename", targetFilename)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	targetFile, err := os.Open(targetFilename)
	if err != nil {
		return err
	}
	label := path.Base(targetFilename)

	return gatecheck.AppendToBundle(bundleFile, targetFile, label, tags)
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

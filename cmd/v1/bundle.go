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

	rmCmd := newBasicCommand("remove BUNDLE_FILE TARGET_FILE", "remove a file from a bundle by label", runBundleRm)
	rmCmd.Aliases = []string{"rm"}
	rmCmd.Args = cobra.ExactArgs(2)

	cmd.AddCommand(createCmd, addCmd, rmCmd)
	return cmd
}

// runBundleCreate
//
// shell: gatecheck bundle create
func runBundleCreate(cmd *cobra.Command, args []string) error {
	bundleFilename := args[0]
	targetFilename := args[1]
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("create a new bundle", "bundle_filename", bundleFilename, "target_filename", targetFilename)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_CREATE|os.O_WRONLY, 0o644)
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
//
// shell: gatecheck bundle add
func runBundleAdd(cmd *cobra.Command, args []string) error {
	bundleFilename := args[0]
	targetFilename := args[1]
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("add new bundle", "bundle_filename", bundleFilename, "target_filename", targetFilename)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0o644)
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
//
// shell: gatecheck bundle rm
func runBundleRm(cmd *cobra.Command, args []string) error {
	bundleFilename := args[0]
	label := args[1]
	slog.Debug("remove from bundle", "bundle_filename", bundleFilename, "label", label)
	bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0o644)
	if err != nil {
		return err
	}

	return gatecheck.RemoveFromBundle(bundleFile, label)
}

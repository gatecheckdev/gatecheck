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

	cmd.PersistentFlags().StringP("bundle-file", "f", "gatecheck-bundle.tar.gz", "target bundle file")
	cmd.PersistentFlags().StringP("input-file", "i", "", "input file")

	createCmd := newBasicCommand("create", "create a new bundle with a new file", runBundleCreate)
	addCmd := newBasicCommand("add", "add a file to a bundle", runBundleAdd)
	rmCmd := newBasicCommand("rm", "remove a file from a bundle", runBundleRm)

	addCmd.Flags().StringSliceP("tag", "t", []string{}, "file properties for metadata")
	createCmd.Flags().StringSliceP("tag", "t", []string{}, "file properties for metadata")

	cmd.AddCommand(createCmd, addCmd, rmCmd)
	return cmd
}

func runBundleCreate(cmd *cobra.Command, args []string) error {
	bundleFilename, _ := cmd.Flags().GetString("bundle-file")
	inputFilename, _ := cmd.Flags().GetString("input-file")
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("create a new bundle", "bundle_filename", bundleFilename, "input_filename", inputFilename)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	inputFile, err := os.Open(inputFilename)
	if err != nil {
		return err
	}

	label := path.Base(inputFilename)
	return gatecheck.CreateBundle(bundleFile, inputFile, label, tags)
}

// runBundleAdd
// shell: gatecheck bundle add <file> -o gatecheck-bundle.tar.gz -t custom-tag-value
func runBundleAdd(cmd *cobra.Command, args []string) error {
	bundleFilename, _ := cmd.Flags().GetString("bundle-file")
	inputFilename, _ := cmd.Flags().GetString("input-file")
	tags, _ := cmd.Flags().GetStringSlice("tag")

	slog.Debug("add new bundle", "bundle_filename", bundleFilename, "input_filename", inputFilename)

	bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0644)
	if err != nil {
		return err
	}

	inputFile, err := os.Open(inputFilename)
	if err != nil {
		return err
	}
	label := path.Base(inputFilename)

	return gatecheck.AppendToBundle(bundleFile, inputFile, label, tags)
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

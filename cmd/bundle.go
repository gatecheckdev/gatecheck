package cmd

import (
	"io"
	"os"
	"path"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func newBundleCommand() *cobra.Command {
	bundleCmd := &cobra.Command{
		Use:   "bundle",
		Short: "create and manage a gatecheck bundle",
	}

	createCmd := &cobra.Command{
		Use:     "create BUNDLE_FILE TARGET_FILE",
		Short:   "create a new bundle with one file, replacing BUNDLE_FILE if it exists",
		Aliases: []string{"init"},
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := os.Open(args[1])
			if err != nil {
				return err
			}
			defer func() { _ = target.Close() }()
			bundleFile, err := os.OpenFile(args[0], os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return err
			}
			err = gatecheck.CreateBundle(bundleFile, target, path.Base(args[1]), stringSliceSetting(cmd, "tag", "GATECHECK_BUNDLE_TAG"))
			return closeAfter(bundleFile, err)
		},
	}

	addCmd := &cobra.Command{
		Use:   "add BUNDLE_FILE TARGET_FILE",
		Short: "add a file to a bundle",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := os.Open(args[1])
			if err != nil {
				return err
			}
			defer func() { _ = target.Close() }()
			bundleFile, err := os.OpenFile(args[0], os.O_RDWR, 0o644)
			if err != nil {
				return err
			}
			err = gatecheck.AppendToBundle(bundleFile, target, path.Base(args[1]), stringSliceSetting(cmd, "tag", "GATECHECK_BUNDLE_TAG"))
			return closeAfter(bundleFile, truncateAtOffset(bundleFile, err))
		},
	}

	removeCmd := &cobra.Command{
		Use:     "remove BUNDLE_FILE LABEL",
		Short:   "remove a file from a bundle by label",
		Aliases: []string{"rm"},
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			bundleFile, err := os.OpenFile(args[0], os.O_RDWR, 0o644)
			if err != nil {
				return err
			}
			err = gatecheck.RemoveFromBundle(bundleFile, args[1])
			return closeAfter(bundleFile, truncateAtOffset(bundleFile, err))
		},
	}

	for _, c := range []*cobra.Command{createCmd, addCmd} {
		c.Flags().StringSliceP("tag", "t", nil, "tags for the added file, repeatable or comma-separated (env GATECHECK_BUNDLE_TAG)")
	}
	bundleCmd.AddCommand(createCmd, addCmd, removeCmd)
	return bundleCmd
}

// truncateAtOffset drops bytes left over from a longer old bundle after it
// was rewritten in place.
func truncateAtOffset(f *os.File, err error) error {
	if err != nil {
		return err
	}
	offset, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	return f.Truncate(offset)
}

func closeAfter(f *os.File, err error) error {
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

package cmd

import (
	"os"
	"path"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/sagikazarmark/slog-shim"
	"github.com/spf13/cobra"
)

var bundleCmd = &cobra.Command{
	Use:   "bundle",
	Short: "create and manage a gatecheck bundle",
}

var bundleCreateCmd = &cobra.Command{
	Use:     "create BUNDLE_FILE TARGET_FILE",
	Short:   "create a new bundle with a new file",
	Aliases: []string{"init"},
	Args:    cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		bundleFilename := args[0]
		targetFilename := args[1]

		bundleFile, err := os.OpenFile(bundleFilename, os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		targetFile, err := os.Open(targetFilename)
		if err != nil {
			return err
		}

		RuntimeConfig.bundleFile = bundleFile
		RuntimeConfig.targetFile = targetFile
		RuntimeConfig.BundleTagValue = RuntimeConfig.BundleTag.Value().([]string)
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFilename := args[1]
		label := path.Base(targetFilename)
		bf, tf := RuntimeConfig.bundleFile, RuntimeConfig.targetFile
		tags := RuntimeConfig.BundleTagValue
		return gatecheck.CreateBundle(bf, tf, label, tags)
	},
}

var bundleAddCmd = &cobra.Command{
	Use:   "add BUNDLE_FILE TARGET_FILE",
	Short: "add a file to a bundle",
	Args:  cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		bundleFilename := args[0]
		targetFilename := args[1]

		bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0o644)
		if err != nil {
			return err
		}
		targetFile, err := os.Open(targetFilename)
		if err != nil {
			return err
		}

		RuntimeConfig.bundleFile = bundleFile
		RuntimeConfig.targetFile = targetFile
		RuntimeConfig.BundleTagValue = RuntimeConfig.BundleTag.Value().([]string)
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		targetFilename := args[1]
		slog.Info("bundle tag", "environment", os.Getenv("GATECHECK_BUNDLE_TAG"))
		label := path.Base(targetFilename)
		bf, tf := RuntimeConfig.bundleFile, RuntimeConfig.targetFile
		tags := RuntimeConfig.BundleTagValue
		return gatecheck.AppendToBundle(bf, tf, label, tags)
	},
}

var bundleRemoveCmd = &cobra.Command{
	Use:     "remove BUNDLE_FILE TARGET_FILE",
	Short:   "remove a file from a bundle by label",
	Aliases: []string{"rm"},
	Args:    cobra.ExactArgs(2),
	PreRunE: func(cmd *cobra.Command, args []string) error {
		bundleFilename := args[0]

		bundleFile, err := os.OpenFile(bundleFilename, os.O_RDWR, 0o644)
		if err != nil {
			return err
		}
		RuntimeConfig.bundleFile = bundleFile
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		label := args[1]
		return gatecheck.RemoveFromBundle(RuntimeConfig.bundleFile, label)
	},
}

func newBundleCommand() *cobra.Command {
	RuntimeConfig.BundleTag.SetupCobra(bundleCreateCmd)
	RuntimeConfig.BundleTag.SetupCobra(bundleAddCmd)

	bundleCmd.AddCommand(bundleCreateCmd, bundleAddCmd, bundleRemoveCmd)
	return bundleCmd
}

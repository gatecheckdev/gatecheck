package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"

	gio "github.com/gatecheckdev/gatecheck/internal/io"
	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/spf13/cobra"
)

func NewBundleCmd(newAsyncDecoder func() AsyncDecoder) *cobra.Command {
	var bundleCmd = &cobra.Command{
		Use:   "bundle [FILE ...]",
		Short: "Create a compressed tarball with artifacts",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outputFilename, _ := cmd.Flags().GetString("output")
			allowMissingFlag, _ := cmd.Flags().GetBool("skip-missing")
			properties, _ := cmd.Flags().GetStringToString("properties")

			outputFile, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_RDWR, 0664)
			if err != nil {
				return fmt.Errorf("%w: bundle output file: %v", ErrorFileAccess, err)
			}
			info, _ := outputFile.Stat()

			var bundle *archive.Bundle
			if info.Size() != 0 {
				obj, err := archive.NewBundleDecoder().DecodeFrom(outputFile)
				if err != nil {
					return fmt.Errorf("%w: existing bundle decoding: %v", ErrorEncoding, err)
				}
				bundle = obj.(*archive.Bundle)
			}

			if bundle == nil {
				bundle = archive.NewBundle()
			}
			for _, filename := range args {
				f, err := os.Open(filename)
				if errors.Is(err, os.ErrNotExist) && allowMissingFlag {
					log.Infof("%s does not exist --skip-missing flag active", filename)
					continue
				}
				if err != nil {
					return fmt.Errorf("%w: bundle argument: %v", ErrorFileAccess, err)
				}
				label := path.Base(filename)
				log.Infof("Adding file with label %s to bundle", label)
				_ = bundle.AddFrom(f, label, properties)
			}

			log.Info("Truncating existing file...")
			_ = outputFile.Truncate(0)
			_, _ = outputFile.Seek(0, io.SeekStart)
			log.Info("Writing bundle to file...")
			return archive.NewBundleEncoder(outputFile).Encode(bundle)
		},
	}

	var lsCmd = &cobra.Command{
		Use:   "ls [FILE]",
		Args:  cobra.MaximumNArgs(1),
		Short: "List contents in bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			filename := archive.DefaultBundleFilename
			if len(args) == 1 {
				filename = args[0]
			}
			obj, err := archive.NewBundleDecoder().DecodeFrom(gio.NewLazyReader(filename))
			if err != nil {
				return fmt.Errorf("%w: bundle decoding: %v", ErrorEncoding, err)
			}
			bundle := obj.(*archive.Bundle)
			printBundleContentTable(cmd.OutOrStdout(), bundle, newAsyncDecoder)
			return nil
		},
	}

	bundleCmd.AddCommand(lsCmd)
	bundleCmd.Flags().StringP("output", "o", archive.DefaultBundleFilename, "output bundle file")
	bundleCmd.Flags().BoolP("skip-missing", "m", false, "Don't fail if a file doesn't exist")
	bundleCmd.Flags().StringToStringP("properties", "p", nil, "Artifact properties in key=value format")
	bundleCmd.MarkFlagFilename("output")
	return bundleCmd

}

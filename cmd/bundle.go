package cmd

import (
	"fmt"
	"os"
	"path"

	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/spf13/cobra"
)

func NewBundleCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "bundle [FILE ...]",
		Short: "Add reports to Gatecheck Report",
		RunE: func(cmd *cobra.Command, args []string) error {
			// Flag is required, ignore errors
			outputFilename, _ := cmd.Flags().GetString("output")

			log.Infof("Opening target output Bundle file: %s", outputFilename)
			outputFile, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_RDWR, 0644)

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			bun := artifact.NewBundle()
			// Attempt to decode the file into the bundle object
			if info, _ := outputFile.Stat(); info.Size() != 0 {
				log.Infof("Existing Bundle File Size: %d", info.Size())
				log.Infof("Decoding bundle...")
				if err := artifact.NewBundleDecoder(outputFile).Decode(bun); err != nil {
					return fmt.Errorf("%w: %v", ErrorEncoding, err)
				}
				log.Info("Successful bundle decode, new files will be added to existing bundle")
			}

			// Open each file, create a bundle artifact and add it to the bundle object
			for _, v := range args {
				log.Infof("Opening File: %s", v)
				f, err := os.Open(v)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}
				label := path.Base(v)
				// File already opened, shouldn't have a reason to error
				art, _ := artifact.NewArtifact(label, f)

				// Error would only occur on a missing label which isn't possible here
				_ = bun.Add(art)

				log.Infof("New Artifact: %s", art.String())
			}
			log.Info(bun.String())

			log.Info("Truncating existing file..")
			_ = outputFile.Truncate(0)
			_, _ = outputFile.Seek(0, 0)

			log.Info("Writing bundle to file..")
			// Finish by encoding the bundle to the file
			return artifact.NewBundleEncoder(outputFile).Encode(bun)
		},
	}

	cmd.Flags().StringP("output", "o", "", "output filename")
	_ = cmd.MarkFlagFilename("output", "gatecheck")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

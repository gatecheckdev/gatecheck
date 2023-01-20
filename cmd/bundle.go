package cmd

import (
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/spf13/cobra"
	"io"
	"os"
)

func NewBundleCmd() *cobra.Command {
	var cmd = &cobra.Command{
		Use:   "bundle [FILE ...]",
		Short: "Add reports to Gatecheck Report",
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			if verbose, _ := cmd.Flags().GetBool("verbose"); verbose == false {
				out = io.Discard
			}
			// Flag is required, ignore errors
			outputFilename, _ := cmd.Flags().GetString("output")
			outputFile, err := os.OpenFile(outputFilename, os.O_CREATE|os.O_RDWR, 0644)

			if err != nil {
				return fmt.Errorf("%w: %v", ErrorFileAccess, err)
			}

			bun := artifact.NewBundle()
			// Attempt to decode the file into the bundle object
			if info, _ := outputFile.Stat(); info.Size() != 0 {
				if err := artifact.NewBundleDecoder(outputFile).Decode(bun); err != nil {
					return fmt.Errorf("%w: %v", ErrorEncoding, err)
				}
				_, _ = fmt.Fprintln(out, "Adding to existing bundle")
			}

			// Open each file, create a bundle artifact and add it to the bundle object
			for _, v := range args {
				f, err := os.Open(v)
				if err != nil {
					return fmt.Errorf("%w: %v", ErrorFileAccess, err)
				}

				art, err := artifact.NewArtifact(v, f)
				if err != nil {
					return err
				}

				if err := bun.Add(art); err != nil {
					return err
				}
				_, _ = fmt.Fprintln(out, "Adding", art.String())
			}

			_, _ = fmt.Fprintln(out, bun.String())
			_ = outputFile.Truncate(0)
			_, _ = outputFile.Seek(0, 0)

			// Finish by encoding the bundle to the file
			return artifact.NewBundleEncoder(outputFile).Encode(bun)
		},
	}

	cmd.Flags().BoolP("verbose", "v", false, "verbose output for debugging")
	cmd.Flags().StringP("output", "o", "", "output filename")
	_ = cmd.MarkFlagFilename("output", "gatecheck")
	_ = cmd.MarkFlagRequired("output")
	return cmd
}

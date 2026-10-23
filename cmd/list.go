package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "print a table of the findings in a report or files in a gatecheck bundle",
	Aliases: []string{"ls", "print"},
	PreRunE: func(cmd *cobra.Command, args []string) error {
		inputType, _ := cmd.Flags().GetString("input-type")
		if inputType == "" && len(args) == 0 {
			return errors.New("need either input-type for STDIN or filename as argument")
		}

		var err error = nil

		if len(args) == 0 {
			RuntimeConfig.listSrcReader = cmd.InOrStdin()
			RuntimeConfig.listSrcName = fmt.Sprintf("stdin:%s", inputType)
		} else {
			RuntimeConfig.listSrcReader, err = os.Open(args[0])
			RuntimeConfig.listSrcName = args[0]
		}

		if err != nil {
			return err
		}

		RuntimeConfig.listFormat = "ascii"

		if markdownFlag, _ := cmd.Flags().GetBool("markdown"); markdownFlag {
			RuntimeConfig.listFormat = "markdown"
		}

		if epss, _ := cmd.Flags().GetBool("epss"); !epss {
			return nil
		}

		RuntimeConfig.epssFile = nil

		epssFilename := RuntimeConfig.EPSSFilename.Value().(string)

		if epssFilename == "" {
			return nil
		}

		RuntimeConfig.epssFile, err = os.Open(epssFilename)
		if err != nil {
			return err
		}

		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		epss, _ := cmd.Flags().GetBool("epss")

		dst := cmd.OutOrStdout()
		src := RuntimeConfig.listSrcReader
		srcName := RuntimeConfig.listSrcName
		displayOpt := gatecheck.WithDisplayFormat(RuntimeConfig.listFormat)

		if !epss {
			return gatecheck.List(dst, src, srcName, displayOpt)
		}

		epssURL := RuntimeConfig.EPSSURL.Value().(string)
		epssFile := RuntimeConfig.epssFile

		// if file is nil, API will be used
		// if epssURL is empty, default API will be used
		epssOpt, err := gatecheck.WithEPSS(epssFile, epssURL, epssCacheOptions()...)
		if err != nil {
			return err
		}
		return gatecheck.List(dst, src, srcName, displayOpt, epssOpt)
	},
}

var listAllCmd = &cobra.Command{
	Use:   "list-all [FILE...]",
	Short: "list multiple report files",
	RunE: func(cmd *cobra.Command, args []string) error {
		epss, _ := cmd.Flags().GetBool("epss")
		markdown, _ := cmd.Flags().GetBool("markdown")
		slog.Debug("run list all", "epss", fmt.Sprintf("%v", epss), "markdown", fmt.Sprintf("%v", markdown))

		for _, filename := range args {
			cmd.Printf("%s\n", filename)

			src, err := os.Open(filename)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					slog.Error("file not found, skip", "filename", filename)
					continue
				}
				slog.Error("cannot open file, skip", "filename", filename, "error", err)
				continue
			}
			content, err := io.ReadAll(src)
			if closeErr := src.Close(); closeErr != nil {
				slog.Debug("close file", "filename", filename, "error", closeErr)
			}
			if err != nil {
				slog.Error("cannot read file, skip", "filename", filename, "error", err)
				continue
			}

			supported, withEPSS := gatecheck.ListAllAction(content, filename)
			if !supported {
				slog.Warn("file not supported, skip", "filename", filename)
				continue
			}

			epssURL := RuntimeConfig.EPSSURL.Value().(string)
			epssFile := RuntimeConfig.epssFile

			opts := []gatecheck.ListOptionFunc{}
			displayOpt := gatecheck.WithDisplayFormat("ascii")
			if markdown {
				displayOpt = gatecheck.WithDisplayFormat("markdown")
			}
			opts = append(opts, displayOpt)

			if epss && withEPSS {
				epssOpt, err := gatecheck.WithEPSS(epssFile, epssURL, epssCacheOptions()...)
				if err != nil {
					slog.Error("epss fetch failure, skip", "filename", filename, "error", err)
					continue
				}
				opts = append(opts, epssOpt)
			}

			dst := cmd.OutOrStdout()
			err = gatecheck.List(dst, bytes.NewReader(content), filename, opts...)
			if err != nil {
				slog.Error("cannot list report, skip", "filename", filename, "error", err)
				continue
			}

		}
		return nil
	},
}

func newListAllCommand() *cobra.Command {
	listAllCmd.Flags().Bool("markdown", false, "print as a markdown table")
	listAllCmd.Flags().Bool("epss", false, "List with EPSS data")
	RuntimeConfig.EPSSCacheDir.SetupCobra(listAllCmd)
	RuntimeConfig.EPSSNoCache.SetupCobra(listAllCmd)
	return listAllCmd
}

func newListCommand() *cobra.Command {
	listCmd.Flags().StringP("input-type", "i", "", "stdin type word used when the report content is ambiguous [grype|cyclonedx|semgrep|gitleaks|trivy|osv|syft|sarif|bundle|lcov]")
	listCmd.Flags().Bool("markdown", false, "print as a markdown table")
	listCmd.Flags().Bool("epss", false, "List with EPSS data")
	RuntimeConfig.EPSSURL.SetupCobra(listCmd)
	RuntimeConfig.EPSSFilename.SetupCobra(listCmd)
	RuntimeConfig.EPSSCacheDir.SetupCobra(listCmd)
	RuntimeConfig.EPSSNoCache.SetupCobra(listCmd)
	return listCmd
}

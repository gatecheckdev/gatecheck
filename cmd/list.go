package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

func addListFormatFlags(cmd *cobra.Command) {
	cmd.Flags().String("format", "table", "output format: "+strings.Join(gatecheck.ListFormats, ", "))
	cmd.Flags().Bool("markdown", false, "print as a markdown table, the same as --format markdown")
	cmd.Flags().Bool("epss", false, "add EPSS scores to Grype, CycloneDX, Trivy, and osv-scanner tables")
	addEPSSFlags(cmd, true)
}

func listFormat(cmd *cobra.Command) (string, error) {
	listFmt, _ := cmd.Flags().GetString("format")
	if markdown, _ := cmd.Flags().GetBool("markdown"); markdown {
		if cmd.Flags().Changed("format") && listFmt != "markdown" {
			return "", fmt.Errorf("--markdown conflicts with --format %s", listFmt)
		}
		listFmt = "markdown"
	}
	if err := oneOf("--format", listFmt, gatecheck.ListFormats...); err != nil {
		return "", err
	}
	return listFmt, nil
}

// epssListOption loads EPSS data once for list and list-all.
func epssListOption(cmd *cobra.Command) (gatecheck.ListOptionFunc, error) {
	var file *os.File
	if name := stringSetting(cmd, "epss-filename", "GATECHECK_EPSS_FILENAME"); name != "" {
		f, err := os.Open(name)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		file = f
	}
	url := stringSetting(cmd, "epss-url", "GATECHECK_EPSS_URL")
	return gatecheck.WithEPSS(file, url, epssCacheOptions(cmd)...)
}

func newListCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "list [FILE]",
		Short:   "print a table of the findings in a report or files in a gatecheck bundle",
		Aliases: []string{"ls", "print"},
		Args:    cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			inputType, _ := cmd.Flags().GetString("input-type")
			if inputType == "" && len(args) == 0 {
				return errors.New("need either --input-type for stdin or a filename argument")
			}
			listFmt, err := listFormat(cmd)
			if err != nil {
				return err
			}

			src := cmd.InOrStdin()
			srcName := "stdin:" + inputType
			if len(args) == 1 {
				f, err := os.Open(args[0])
				if err != nil {
					return err
				}
				defer func() { _ = f.Close() }()
				src = f
				srcName = args[0]
				if inputType != "" {
					srcName = inputType
				}
			}

			opts := []gatecheck.ListOptionFunc{gatecheck.WithDisplayFormat(listFmt)}
			if epss, _ := cmd.Flags().GetBool("epss"); epss {
				epssOpt, err := epssListOption(cmd)
				if err != nil {
					return err
				}
				opts = append(opts, epssOpt)
			}
			return gatecheck.List(cmd.OutOrStdout(), src, srcName, opts...)
		},
	}
	cmd.Flags().StringP("input-type", "i", "", "report type when the contents are ambiguous, and the type of stdin when FILE is omitted ["+inputTypes+"]")
	addListFormatFlags(cmd)
	return cmd
}

func newListAllCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-all FILE...",
		Short: "list multiple report files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			listFmt, err := listFormat(cmd)
			if err != nil {
				return err
			}
			withEPSS, _ := cmd.Flags().GetBool("epss")
			var epssOpt gatecheck.ListOptionFunc

			type listed struct {
				File   string          `json:"file"`
				Report json.RawMessage `json:"report"`
			}
			listedJSON := []listed{}

			var failed int
			for _, filename := range args {
				content, err := os.ReadFile(filename)
				if err != nil {
					slog.Error("cannot read file, skip", "filename", filename, "error", err)
					failed++
					continue
				}
				supported, epssCapable := gatecheck.ListAllAction(content, filename)
				if !supported {
					slog.Warn("file not supported, skip", "filename", filename)
					continue
				}
				opts := []gatecheck.ListOptionFunc{gatecheck.WithDisplayFormat(listFmt)}
				if withEPSS && epssCapable {
					if epssOpt == nil {
						if epssOpt, err = epssListOption(cmd); err != nil {
							return err
						}
					}
					opts = append(opts, epssOpt)
				}
				if listFmt == "json" {
					var buf bytes.Buffer
					if err := gatecheck.List(&buf, bytes.NewReader(content), filename, opts...); err != nil {
						slog.Error("cannot list report, skip", "filename", filename, "error", err)
						failed++
						continue
					}
					listedJSON = append(listedJSON, listed{File: filename, Report: bytes.TrimSpace(buf.Bytes())})
					continue
				}
				cmd.Printf("%s\n", filename)
				if err := gatecheck.List(cmd.OutOrStdout(), bytes.NewReader(content), filename, opts...); err != nil {
					slog.Error("cannot list report, skip", "filename", filename, "error", err)
					failed++
				}
			}
			if listFmt == "json" {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(listedJSON); err != nil {
					return err
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d files could not be listed", failed, len(args))
			}
			return nil
		},
	}
	addListFormatFlags(cmd)
	return cmd
}

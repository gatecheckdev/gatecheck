package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
)

var validateFormats = []string{"table", "markdown", "json"}

func newValidateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate [FILE]",
		Short: "compare a report or bundle to configured thresholds",
		Long: `Compare a report or bundle to the thresholds in a config file.

FILE is required unless --input-type is set, in which case the report is read
from stdin. Exit status: 0 pass, 1 threshold failure, 2 usage, file, or
decode error, 3 EPSS or KEV data could not be loaded. --audit turns a
threshold failure into exit 0. It does not hide any other error.`,
		Args: cobra.MaximumNArgs(1),
		RunE: runValidate,
	}
	flags := cmd.Flags()
	flags.StringP("config", "f", "", "validation config file (env GATECHECK_CONFIG_FILENAME)")
	flags.StringP("input-type", "i", "", "report type when the contents are ambiguous, and the type of stdin when FILE is omitted ["+inputTypes+"]")
	flags.BoolP("audit", "a", false, "exit 0 when a threshold fails; other errors still fail (env GATECHECK_AUDIT)")
	flags.String("format", "", "also print the result to stdout: "+strings.Join(validateFormats, ", "))
	flags.StringSlice("vex", nil, "OpenVEX or CycloneDX VEX file; findings it marks not_affected, fixed, false_positive, or resolved are skipped (repeatable, env GATECHECK_VEX)")
	addEPSSFlags(cmd, true)
	addKEVFlags(cmd)
	_ = cmd.MarkFlagFilename("config", "json", "yaml", "yml", "toml")
	return cmd
}

func runValidate(cmd *cobra.Command, args []string) error {
	outputFormat, _ := cmd.Flags().GetString("format")
	if outputFormat != "" {
		if err := oneOf("--format", outputFormat, validateFormats...); err != nil {
			return err
		}
	}
	audit, err := boolSetting(cmd, "audit", "GATECHECK_AUDIT")
	if err != nil {
		return err
	}
	inputType, _ := cmd.Flags().GetString("input-type")
	if len(args) == 0 && inputType == "" {
		return errors.New("need a FILE argument, or --input-type to read the report from stdin")
	}

	config, err := loadValidateConfig(cmd)
	if err != nil {
		return err
	}

	var src io.Reader
	name := "stdin"
	if len(args) == 1 {
		name = args[0]
		slog.Debug("open target file", "filename", name)
		f, err := os.Open(name)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		src = f
	} else {
		src = cmd.InOrStdin()
	}
	kindHint := name
	if inputType != "" {
		kindHint = inputType
	}

	opts, closeFiles, err := fetchOptions(cmd)
	if err != nil {
		return err
	}
	defer closeFiles()
	opts = append(opts, gatecheck.WithVEXFiles(stringSliceSetting(cmd, "vex", "GATECHECK_VEX")...))

	validateErr := gatecheck.Validate(config, src, kindHint, opts...)

	if outputFormat != "" {
		if err := writeValidateResult(cmd.OutOrStdout(), outputFormat, name, validateErr); err != nil {
			return err
		}
	}
	if audit && errors.Is(validateErr, gatecheck.ErrValidationFailure) {
		slog.Warn("validation failure ignored in audit mode")
		_, _ = fmt.Fprintln(cmd.ErrOrStderr(), validateErr)
		return nil
	}
	return validateErr
}

func loadValidateConfig(cmd *cobra.Command) (*gatecheck.Config, error) {
	config := gatecheck.NewDefaultConfig()
	filename := stringSetting(cmd, "config", "GATECHECK_CONFIG_FILENAME")
	if filename == "" {
		slog.Warn("no config file; using the default config, which has every rule disabled")
		return config, nil
	}
	err := gatecheck.NewConfigDecoder(filename).Decode(config)
	if errors.Is(err, gatecheck.ErrUnknownConfigKeys) {
		slog.Warn("config has keys gatecheck does not read; check them for typos", "filename", filename, "keys", strings.TrimPrefix(err.Error(), gatecheck.ErrUnknownConfigKeys.Error()+": "))
		return config, nil
	}
	if err != nil {
		return nil, err
	}
	return config, nil
}

type validateResult struct {
	Report   string   `json:"report"`
	Passed   bool     `json:"passed"`
	Failures []string `json:"failures"`
	Error    string   `json:"error,omitempty"`
}

func newValidateResult(name string, err error) validateResult {
	result := validateResult{Report: name, Passed: err == nil, Failures: []string{}}
	if err == nil {
		return result
	}
	if !errors.Is(err, gatecheck.ErrValidationFailure) {
		result.Error = err.Error()
		return result
	}
	prefix := gatecheck.ErrValidationFailure.Error() + ": "
	var walk func(error)
	walk = func(e error) {
		if joined, ok := e.(interface{ Unwrap() []error }); ok {
			for _, child := range joined.Unwrap() {
				walk(child)
			}
			return
		}
		if errors.Is(e, gatecheck.ErrValidationFailure) {
			result.Failures = append(result.Failures, strings.TrimPrefix(e.Error(), prefix))
			return
		}
		result.Error = e.Error()
	}
	walk(err)
	return result
}

func writeValidateResult(w io.Writer, outputFormat, name string, err error) error {
	result := newValidateResult(name, err)
	if outputFormat == "json" {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}
	table := format.NewTable(w)
	if outputFormat == "markdown" {
		format.SetMarkdown(table)
	}
	table.Header([]string{"Report", "Result", "Detail"})
	switch {
	case result.Passed:
		_ = table.Append([]string{name, "pass", "-"})
	case result.Error != "" && len(result.Failures) == 0:
		_ = table.Append([]string{name, "error", result.Error})
	default:
		for _, failure := range result.Failures {
			_ = table.Append([]string{name, "fail", failure})
		}
		if result.Error != "" {
			_ = table.Append([]string{name, "error", result.Error})
		}
	}
	return table.Render()
}

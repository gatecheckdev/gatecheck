package cmd

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newBasicCommand is a simple wrapper that fills the minimum necessary fields for cobra commands
func newBasicCommand(use string, short string, runE func(*cobra.Command, []string) error) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, RunE: runE}
}

// ParsedOutput splits the format and filename
//
// expects the `--output` argument in the <format>=<filename> format
func ParsedOutput(output string) (format, filename string) {
	switch {
	case strings.Contains(output, "="):
		parts := strings.Split(output, "=")
		return parts[0], parts[1]
	default:
		return output, ""
	}
}

func fileOrStdout(filename string, cmd *cobra.Command) (io.Writer, error) {
	switch {
	case filename == "":
		slog.Debug("output to stdout", "function", "fileOrStdout")
		return cmd.OutOrStdout(), nil
	default:
		slog.Debug("open", "filename", filename, "function", "fileOrStdout")
		return os.Open(filename)
	}
}

func fileOrStdin(filename string, cmd *cobra.Command) (io.Reader, error) {
	switch {
	case filename == "":
		slog.Debug("config from stdin")
		return cmd.InOrStdin(), nil
	default:
		slog.Debug("open", "filename", filename, "function", "fileOrStdin")
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		return f, err
	}
}

// LoadConfigFromFileOrReader will either load the config object with values after opening file or reading in from src
//
// Either a filename or a src and filetype must be defined or this function will error
func LoadConfigFromFileOrReader(config *gatecheck.Config, filename string, src io.Reader, filetype string) error {
	slog.Debug("load config from file or reader", "filename", filename, "filetype", filetype)
	switch {
	case filename != "":
		return LoadConfigFromFile(config, filename)
	case filetype != "":
		return LoadConfigFromReader(config, src, filetype)
	default:
		return errors.New("No filetype or filename specified, cannot load config")
	}
}

// LoadConfigFromReader loads config object with values from src. filetype is mandatory
func LoadConfigFromReader(config *gatecheck.Config, src io.Reader, filetype string) error {
	slog.Debug("load config from reader", "filetype", filetype)
	v := viper.New()
	v.SetConfigType(filetype)
	if err := v.ReadConfig(src); err != nil {
		return err
	}

	if err := v.Unmarshal(config); err != nil {
		return err
	}

	return nil
}

// LoadConfigFromFile loads config object with values after reading the file
func LoadConfigFromFile(config *gatecheck.Config, filename string) error {
	slog.Debug("load config from file", "filename", filename)
	v := viper.New()
	v.SetConfigFile(filename)
	if err := v.ReadInConfig(); err != nil {
		return err
	}
	if err := v.UnmarshalExact(config); err != nil {
		return err
	}

	return nil
}

// WriteConfigInfo as a human readable display table
func WriteConfigInfo(w io.Writer, v *viper.Viper, config *gatecheck.Config) error {
	table := format.NewTable()
	table.AppendRow("key", "Value")

	for _, key := range viper.AllKeys() {
		table.AppendRow(key, fmt.Sprintf("%v", viper.Get(key)))
	}

	_, infoErr := format.NewTableWriter(table).WriteTo(w)
	_, configErr := fmt.Fprintln(w, config.String())
	return errors.Join(infoErr, configErr)
}

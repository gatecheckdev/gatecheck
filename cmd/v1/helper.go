package cmd

import (
	"bytes"
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
func LoadConfigFromFileOrReader(v *viper.Viper, config *gatecheck.Config, filename string, src io.Reader, filetype string) error {
	slog.Debug("load config from file or reader", "filename", filename, "filetype", filetype)
	switch {
	case filename != "":
		return LoadConfigFromFile(v, config, filename)
	case filetype != "":
		return LoadConfigFromReader(v, config, src, filetype)
	default:
		return errors.New("No filetype or filename specified, cannot load config")
	}
}

// LoadConfigFromReader loads config object with values from src. filetype is mandatory
func LoadConfigFromReader(v *viper.Viper, config *gatecheck.Config, src io.Reader, filetype string) error {
	slog.Debug("load config from reader", "filetype", filetype)
	v.SetConfigType(filetype)
	if err := v.ReadConfig(src); err != nil {
		return err
	}
	err := LoadConfig(v, config)

	return err
}

// LoadConfigFromFile loads config object with values after reading the file
func LoadConfigFromFile(v *viper.Viper, config *gatecheck.Config, filename string) error {
	slog.Debug("load config from file", "filename", filename)
	v.SetConfigFile(filename)
	if err := v.ReadInConfig(); err != nil {
		return err
	}

	err := LoadConfig(v, config)

	return err
}

// LoadConfig unmarshals the viper settings into a given config object
func LoadConfig(v *viper.Viper, config *gatecheck.Config) error {
	slog.Debug("load config, unmarshal config object into viper")
	if err := v.Unmarshal(config); err != nil {
		return err
	}

	configViper := viper.New()
	buf := new(bytes.Buffer)

	_ = json.NewEncoder(buf).Encode(config)
	configViper.SetConfigType("json")
	if err := configViper.ReadConfig(buf); err != nil {
		return err
	}

	for key, value := range configViper.AllSettings() {
		v.Set("config."+key, value)
	}

	return nil
}

// WriteViperValues as a human readable display table
func WriteViperValues(w io.Writer, v *viper.Viper) error {
	table := format.NewTable()

	table.AppendRow("key", "Value")

	for _, key := range viper.AllKeys() {
		table.AppendRow(key, fmt.Sprintf("%v", viper.Get(key)))
	}

	_, err := format.NewTableWriter(table).WriteTo(w)
	return err
}

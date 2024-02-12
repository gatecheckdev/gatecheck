package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

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

func ConfigFromViperFileOrStdin(v *viper.Viper, filename string, filetype string, cmd *cobra.Command) (map[string]any, error) {
	slog.Debug("viper read config", "filename", filename, "stdin_file_type", filetype)
	switch {
	case filename != "":
		v.SetConfigFile(filename)
		if err := v.ReadInConfig(); err != nil {
			return nil, err
		}
	case filetype != "":
		v.SetConfigType(filetype)
		if err := v.ReadConfig(cmd.InOrStdin()); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("cannot load config without a filename or a filetype if using STDIN filename='%s' filetype='%s'", filename, filetype)
	}
	return config(v), nil
}

func config(v *viper.Viper) map[string]any {
	pr, pw := io.Pipe()

	go func() {
		_ = json.NewEncoder(pw).Encode(v.AllSettings())
	}()
	config := map[string]any{}
	_ = json.NewDecoder(pr).Decode(&config)
	return config
}

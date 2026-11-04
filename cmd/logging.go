package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/lmittmann/tint"
	"github.com/spf13/cobra"
)

var (
	logLevels  = []string{"debug", "info", "warn", "error"}
	logFormats = []string{"text", "json"}
)

func addLoggingFlags(root *cobra.Command) {
	flags := root.PersistentFlags()
	flags.BoolP("verbose", "v", false, "debug logging, the same as --log-level debug (env GATECHECK_VERBOSE)")
	flags.Bool("silent", false, "only warnings and errors, the same as --log-level warn (env GATECHECK_SILENT)")
	flags.String("log-level", "info", "log level: "+strings.Join(logLevels, ", ")+" (env GATECHECK_LOG_LEVEL)")
	flags.String("log-format", "text", "log format on stderr: "+strings.Join(logFormats, ", ")+" (env GATECHECK_LOG_FORMAT)")
	root.MarkFlagsMutuallyExclusive("verbose", "silent", "log-level")
}

// logLevel picks the level. Flags beat environment variables. Among flags or
// among variables, verbose and silent beat a log level.
func logLevel(cmd *cobra.Command) (slog.Level, error) {
	flags := cmd.Flags()
	switch {
	case flags.Changed("verbose"):
		return slog.LevelDebug, nil
	case flags.Changed("silent"):
		return slog.LevelWarn, nil
	case flags.Changed("log-level"):
		v, _ := flags.GetString("log-level")
		return parseLevel(v, "--log-level")
	}
	verbose, err := boolSetting(cmd, "verbose", "GATECHECK_VERBOSE")
	if err != nil {
		return 0, err
	}
	silent, err := boolSetting(cmd, "silent", "GATECHECK_SILENT")
	if err != nil {
		return 0, err
	}
	switch {
	case verbose && silent:
		return 0, fmt.Errorf("GATECHECK_VERBOSE and GATECHECK_SILENT cannot both be true")
	case verbose:
		return slog.LevelDebug, nil
	case silent:
		return slog.LevelWarn, nil
	}
	return parseLevel(stringSetting(cmd, "log-level", "GATECHECK_LOG_LEVEL"), "log level")
}

func parseLevel(v, name string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid %s %q, must be one of %s", name, v, strings.Join(logLevels, ", "))
	}
}

// setupLogging installs the default slog logger on the command's stderr.
func setupLogging(cmd *cobra.Command) error {
	level, err := logLevel(cmd)
	if err != nil {
		return err
	}
	logFormat := strings.ToLower(stringSetting(cmd, "log-format", "GATECHECK_LOG_FORMAT"))
	if err := oneOf("log format", logFormat, logFormats...); err != nil {
		return err
	}
	slog.SetDefault(slog.New(newLogHandler(cmd.ErrOrStderr(), logFormat, level)))
	slog.Debug("logging configured", "level", level.String(), "format", logFormat)
	return nil
}

func newLogHandler(w io.Writer, format string, level slog.Level) slog.Handler {
	if format == "json" {
		return slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})
	}
	return tint.NewTextHandler(w, &tint.Options{
		Level:      level,
		TimeFormat: time.TimeOnly,
		NoColor:    !colorOutput(w),
	})
}

// colorOutput is true for a terminal when NO_COLOR is unset.
func colorOutput(w io.Writer) bool {
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

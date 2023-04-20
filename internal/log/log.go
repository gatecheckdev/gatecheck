package log

import (
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/rs/zerolog"
)

var writer = log.Default().Writer()
var logger = zerolog.New(writer).With().Timestamp().Logger()
var start = time.Now()

var elapseLabel = "elapsed_ms"

type LogLevel zerolog.Level

const (
	Disabled   LogLevel = LogLevel(zerolog.Disabled)
	DebugLevel LogLevel = LogLevel(zerolog.DebugLevel)
	WarnLevel  LogLevel = LogLevel(zerolog.WarnLevel)
)

func Info(msg string) {
	logger.Info().Int64(elapseLabel, getElapsed()).Msg(msg)
}

func Infof(format string, v ...any) {
	logger.Info().Int64(elapseLabel, getElapsed()).Msg(fmt.Sprintf(format, v...))
}

func Warn(msg string) {
	logger.Warn().Int64(elapseLabel, getElapsed()).Msg(msg)
}

func Warnf(format string, v ...any) {
	logger.Warn().Int64(elapseLabel, getElapsed()).Msg(fmt.Sprintf(format, v...))
}

func Start() {
	start = time.Now()
	Info("Logging Started")
}

func StartCLIOutput(w io.Writer) {
	start = time.Now()

	output := zerolog.ConsoleWriter{Out: w}

	output.FormatLevel = func(i interface{}) string {
		return strings.ToUpper(fmt.Sprintf("| %-6s|", i))
	}

	logger = logger.Output(output)

	Info("Logging Started")
}

func SetLogLevel(l LogLevel) {
	zerolog.SetGlobalLevel(zerolog.Level(l))
}

func getElapsed() int64 {
	return time.Since(start).Milliseconds()
}

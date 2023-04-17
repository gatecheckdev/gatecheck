package log

import (
	"fmt"
	"io"
	"log"
	"time"

	"github.com/fatih/color"
)

var writer = log.Default().Writer()
var infoLogger = log.New(writer, "INFO  ", log.Lmsgprefix)
var warnLogger = log.New(writer, "WARN  ", log.Lmsgprefix)
var errorLogger = log.New(writer, "ERROR ", log.Lmsgprefix)
var start = time.Now()

type printer interface {
	Print(v ...any)
}

func Info(msg string) {
	fprint(infoLogger, msg, color.Reset)
}

func Infof(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	fprint(infoLogger, msg, color.FgWhite)
}

func Warn(msg string) {
	fprint(warnLogger, msg, color.FgYellow)
}

func Warnf(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	fprint(warnLogger, msg, color.FgYellow)
}
func Error(msg string) {
	fprint(errorLogger, msg, color.FgRed)
}

func Errorf(format string, v ...any) {
	msg := fmt.Sprintf(format, v...)
	fprint(errorLogger, msg, color.FgRed)
}

func fprint(f printer, msg string, c color.Attribute) {
	color.Set(c)
	f.Print(getElapsed(), msg)
	color.Unset()
}

func Start() {
	start = time.Now()
	Info("Logging Started")
}

func NoColor() {
	color.NoColor = true
}

func SetOutput(w io.Writer) {
	infoLogger.SetOutput(w)
	warnLogger.SetOutput(w)
	errorLogger.SetOutput(w)
}

func getElapsed() string {
	elapsed := time.Since(start)
	return fmt.Sprintf("[%s] ", elapsed.String())
}

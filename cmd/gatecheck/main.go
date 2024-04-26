// Package main executes the CLI for gatecheck
package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"time"

	"github.com/lmittmann/tint"

	cmdV1 "github.com/gatecheckdev/gatecheck/cmd/v1"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
)

const (
	exitSystemFail     int = -1
	exitOk                 = 0
	exitValidationFail     = 1
	exitFileAccessFail     = 2
)

// GatecheckVersion see CHANGELOG.md
const GatecheckVersion = "[Not Provided]"

// all variables here are provided as build-time arguments, with clear default values
var (
	cliVersion     = "[Not Provided]"
	buildDate      = "[Not Provided]"
	gitCommit      = "[Not Provided]"
	gitDescription = "[Not Provided]"
)

func main() {
	os.Exit(run())
}

func run() int {
	cmdV1.ApplicationMetadata = gatecheck.ApplicationMetadata{
		CLIVersion:     cliVersion,
		GitCommit:      gitCommit,
		BuildDate:      buildDate,
		GitDescription: gitDescription,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
	}

	// Colorized logging output for the CLI
	logHandler := tint.NewHandler(os.Stderr, &tint.Options{Level: cmdV1.LogLeveler, TimeFormat: time.TimeOnly})
	slog.SetDefault(slog.New(logHandler))

	command := cmdV1.NewGatecheckCommand()

	err := command.Execute()
	if errors.Is(gatecheck.ErrValidationFailure, err) {
		return exitValidationFail
	}
	if err != nil {
		return exitSystemFail
	}
	return exitOk
}

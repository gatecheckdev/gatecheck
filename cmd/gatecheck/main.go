// Package main executes the CLI for gatecheck
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/gatecheckdev/gatecheck/cmd"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
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
	cmd.ApplicationMetadata = gatecheck.ApplicationMetadata{
		CLIVersion:     cliVersion,
		GitCommit:      gitCommit,
		BuildDate:      buildDate,
		GitDescription: gitDescription,
		Platform:       fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		GoVersion:      runtime.Version(),
		Compiler:       runtime.Compiler,
	}
	epss.SetVersion(cliVersion)
	return status(cmd.NewGatecheckCommand().Execute())
}

func status(err error) int {
	return cmd.ExitCode(err)
}

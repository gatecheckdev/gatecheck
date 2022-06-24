package main

import (
	"errors"
	"fmt"
	"github.com/gatecheckdev/gatecheck/cmd"
	"github.com/gatecheckdev/gatecheck/internal"
	"os"
)

const ExitSystemFail int = -1
const ExitOk int = 0
const ExitFileAccessFail int = 2

//const ExitValidationFail = 1

func main() {
	err := cmd.RootCmd.Execute()

	if errors.Is(err, internal.ErrorFileAccess) {
		fmt.Println(err)
		os.Exit(ExitFileAccessFail)
	}
	if errors.Is(err, internal.ErrorFileExists) {
		os.Exit(ExitFileAccessFail)
	}
	if err != nil {
		os.Exit(ExitSystemFail)
	}
	os.Exit(ExitOk)
}

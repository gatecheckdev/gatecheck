package main

import (
	"errors"
	"fmt"
	"github.com/gatecheckdev/gatecheck/cmd"
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/pkg/exporter/defectDojo"
	"os"
	"time"
)

const ExitSystemFail int = -1
const ExitOk int = 0
const ExitFileAccessFail int = 2
const ExitValidationFail = 1

func main() {
	dojoKey := os.Getenv("GATECHECK_DD_API_KEY")
	dojoUrl := os.Getenv("GATECHECK_DD_API_URL")
	e := defectDojo.NewExporter(defectDojo.Config{
		ProductTypeName:    os.Getenv("GATECHECK_DD_PRODUCT_TYPE"),
		ProductName:        os.Getenv("GATECHECK_DD_PRODUCT"),
		EngagementName:     os.Getenv("GATECHECK_DD_ENGAGEMENT"),
		EngagementDuration: time.Hour * 48,
		CommitHash:         os.Getenv("GATECHECK_DD_COMMIT_HASH"),
		BranchTag:          os.Getenv("GATECHECK_DD_BRANCH_TAG"),
		SourceURL:          os.Getenv("GATECHECK_DD_SOURCE_URL"),
	}).WithService(defectDojo.NewDefaultService(dojoKey, dojoUrl))
	command := cmd.NewRootCmd(e)
	err := command.Execute()

	if errors.Is(err, internal.ErrorFileAccess) {
		fmt.Println(err)
		os.Exit(ExitFileAccessFail)
	}
	if errors.Is(err, internal.ErrorFileExists) {
		os.Exit(ExitFileAccessFail)
	}
	if errors.Is(err, internal.ErrorValidation) {
		os.Exit(ExitValidationFail)
	}

	if err != nil {
		os.Exit(ExitSystemFail)
	}
	os.Exit(ExitOk)
}
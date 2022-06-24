package internal

import (
	"errors"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/report"
	"os"
	"path"
)

var ErrorFileAccess = errors.New("file access error")
var ErrorFileExists = errors.New("file already exists")
var ErrorFileNotExists = errors.New("file does not exists")
var ErrorConfig = errors.New("error decoding the configuration file")
var ErrorDecode = errors.New("error decoding a file")

func ConfigAndReportFrom(configFile string, reportFile string) (*config.Config, *report.Report, error) {
	GateCheckConfig, err := ConfigFromFile(configFile)
	if err != nil {
		return nil, nil, err
	}
	GateCheckReport, err := ReportFromFile(reportFile, *GateCheckConfig)
	if err != nil {
		return nil, nil, err
	}
	return GateCheckConfig, GateCheckReport, nil
}

func ConfigFromFile(configFile string) (*config.Config, error) {
	if _, err := os.Stat(configFile); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileNotExists, err)
	}

	f, err := os.Open(configFile)
	if err != nil {

		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}

	loadedConfig, err := config.NewReader(f).ReadConfig()
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorConfig, err)
	}
	return loadedConfig, nil
}

func ReportFromFile(reportFile string, c config.Config) (*report.Report, error) {

	f, err := os.Open(reportFile)
	// If the file doesn't exist, return a new report
	if errors.Is(err, os.ErrNotExist) {
		newReport := report.NewReport(c.ProjectName).WithConfig(&c)
		return newReport, nil
	}

	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}

	loadedReport, err := report.NewReader(f).ReadReport()
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorDecode, err)
	}

	return loadedReport, err
}

func ReportToFile(reportFilename string, r *report.Report) error {
	f, err := os.OpenFile(reportFilename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}

	return report.NewWriter(f).WriteReport(r)
}

func GrypeScanFromFile(scanFilename string) (*grype.ScanReport, error) {
	f, err := os.Open(scanFilename)
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}
	scan, err := grype.NewScanReportReader(f).ReadScan()
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorDecode, err)
	}
	return scan, nil
}

// NewFile will create a file if dir with defaultFile name or the file
func NewFile(dirOrFile string, defaultFilename string) (*os.File, error) {
	fileInfo, err := os.Stat(dirOrFile)

	// Catch an error other than the file not existing, like bad file name
	if err != nil {
		if os.IsNotExist(err) == false {
			return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
		}
		// File doesn't exist, create the file
		f, _ := os.Create(dirOrFile)

		return f, nil
	}

	// A directory was passed so append the file name
	if fileInfo.IsDir() {
		f, createError := os.Create(path.Join(dirOrFile, defaultFilename))
		if createError != nil {
			return nil, fmt.Errorf("%w : %v\n%s %s", ErrorFileAccess, createError, dirOrFile, defaultFilename)
		}
		return f, nil
	}

	// The file already exists
	return nil, ErrorFileExists

}

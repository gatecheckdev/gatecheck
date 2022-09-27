package internal

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/report"
	"gopkg.in/yaml.v3"
	"os"
	"path"
)

var ErrorFileAccess = errors.New("file access error")
var ErrorFileExists = errors.New("file already exists")
var ErrorFileNotExists = errors.New("file does not exists")
var ErrorConfig = errors.New("error decoding the configuration file")
var ErrorDecode = errors.New("error decoding a file")
var ErrorValidation = errors.New("report failed validation")

// ConfigAndReportFrom loads a Gatecheck config and report from given filenames
func ConfigAndReportFrom(configFile string, reportFile string) (*config.Config, *report.Report, error) {
	gatecheckConfig, err := ConfigFromFile(configFile)
	if err != nil {
		return nil, nil, err
	}
	gatecheckReport, err := ReportFromFile(reportFile)

	if err != nil {
		return nil, nil, err
	}

	gatecheckReport = gatecheckReport.WithConfig(gatecheckConfig)

	return gatecheckConfig, gatecheckReport, nil
}

// ConfigFromFile loads a Gatecheck config from a given filename
func ConfigFromFile(configFile string) (*config.Config, error) {
	if _, err := os.Stat(configFile); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileNotExists, err)
	}

	f, err := os.Open(configFile)
	if err != nil {

		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}

	loadedConfig := new(config.Config)
	if err := yaml.NewDecoder(f).Decode(loadedConfig); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorConfig, err)
	}

	return loadedConfig, nil
}

// ReportFromFile loads a Gatecheck report from a given filename
func ReportFromFile(reportFile string) (*report.Report, error) {

	f, err := os.Open(reportFile)
	// If the file doesn't exist, return a new report
	if errors.Is(err, os.ErrNotExist) {
		newReport := report.NewReport("").WithConfig(config.NewConfig(""))
		return newReport, nil
	}

	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}

	loadedReport := new(report.Report)
	if err := json.NewDecoder(f).Decode(loadedReport); err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorDecode, err)
	}

	return loadedReport, err
}

// ReportToFile saves a Gatecheck report to a file, given a filename
func ReportToFile(reportFilename string, r *report.Report) error {
	f, err := os.OpenFile(reportFilename, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		return fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}

	return json.NewEncoder(f).Encode(r)
}

// GrypeScanFromFile loads a report from a Grype Scan given the scan's filename
func GrypeScanFromFile(scanFilename string) (*grype.ScanReport, error) {
	f, err := os.Open(scanFilename)
	if err != nil {
		return nil, fmt.Errorf("%w : %v", ErrorFileAccess, err)
	}
	scan := new(grype.ScanReport)
	if err := json.NewDecoder(f).Decode(scan); err != nil {
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

package artifacts

import (
	"errors"
	"github.com/easy-up/go-coverage"
	"log/slog"
	"strings"
)

func example() (coverage.Report, error) {
	lcovParser := coverage.New(coverage.LCOV)
	report, err := lcovParser.Parse("./path/to/lcov.info")
	if err != nil {
		// Handle error
		return coverage.Report{}, err
	}
	// Use the parsed report
	return report, nil
}

func IsCoverageReport(inputFilename string) bool {
	return strings.Contains(inputFilename, "lcov") ||
		strings.HasSuffix(inputFilename, ".info") ||
		strings.Contains(inputFilename, "clover") ||
		strings.Contains(inputFilename, "cobertura") ||
		strings.Contains(inputFilename, "coverage")
}

func GetCoverageMode(inputFilename string) (coverage.CoverageMode, error) {
	var coverageFormat coverage.CoverageMode
	if strings.Contains(inputFilename, "lcov") || strings.HasSuffix(inputFilename, ".info") {
		coverageFormat = coverage.LCOV
	} else if strings.Contains(inputFilename, "clover") {
		coverageFormat = coverage.CLOVER
	} else if strings.HasSuffix(inputFilename, ".xml") {
		coverageFormat = coverage.COBERTURA
	} else {
		slog.Error("unsupported coverage file type, cannot be determined from filename", "filename", inputFilename)
		return "", errors.New("failed to list coverage content")
	}
	return coverageFormat, nil
}

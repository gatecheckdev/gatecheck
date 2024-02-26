package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/v1"
)

// Validate against config thresholds
func Validate(config *Config, targetSrc io.Reader, targetfilename string) error {

	var decoder interface {
		Decode(any) error
	}
	decoder = json.NewDecoder(targetSrc)

	switch {
	case strings.Contains(targetfilename, "grype"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "grype")
		report := &artifacts.GrypeReportMin{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}
		return validateGrype(config, report)

	case strings.Contains(targetfilename, "semgrep"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "semgrep")
		report := &semgrep.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}

	case strings.Contains(targetfilename, "gitleaks"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "gitleaks")
		report := &gitleaks.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}

	case strings.Contains(targetfilename, "syft"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "syft")
		slog.Warn("syft decoder is not supported yet")
		return nil

	case strings.Contains(targetfilename, "cyclonedx"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "cyclonedx")
		report := &cyclonedx.ScanReport{}
		if err := decoder.Decode(report); err != nil {
			slog.Error("error decoding grype report during validation", "error", err)
			return errors.New("failed to decode report")
		}

	case strings.Contains(targetfilename, "bundle"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "bundle")
		// bundle, err := archive.UntarGzipBundle(src)
		// if err != nil {
		// 	return err
		// }
		// _, err = fmt.Fprintln(dst, bundle.Content())
		return errors.New("bundle validation not yet supported.")

	default:
		slog.Error("invalid input filetype", "filename", targetfilename)
		return errors.New("failed to validate artifact content")
	}

	return nil
}

func ruleGrypeLimit(config *Config, report *artifacts.GrypeReportMin) bool {
	limits := map[string]limit{
		"critical": config.Grype.SeverityLimit.Critical,
		"high":     config.Grype.SeverityLimit.High,
		"medium":   config.Grype.SeverityLimit.Medium,
		"low":      config.Grype.SeverityLimit.Low,
	}
	for severity, configLimit := range limits {
		matches := report.SelectBySeverity(severity)
		matchCount := len(matches)
		if !configLimit.Enabled {
			slog.Debug("severity limit not enabled", "artifact", "grype", "severity", severity, "reported", matchCount)
			return true
		}
		if matchCount > int(configLimit.Limit) {
			slog.Error("grype severity limit exceeded", "severity", severity, "report", matchCount, "limit", configLimit.Limit)
			return false
		}
		slog.Debug("severity limit valid", "artifact", "grype", "severity", severity, "reported", matchCount)
		return true

	}
	return false
}

func ruleGrypeCVEDeny(config *Config, report *artifacts.GrypeReportMin) bool {
	if !config.Grype.CVELimit.Enabled {
		slog.Debug("cve id limits not enabled", "artifact", "grype", "count_denied", len(config.Grype.CVELimit.CVEs))
		return true
	}
	for _, cve := range config.Grype.CVELimit.CVEs {
		contains := slices.ContainsFunc(report.Matches, func(match artifacts.GrypeMatch) bool {
			return strings.ToLower(match.Vulnerability.ID) == cve.ID
		})

		if contains {
			slog.Error("cve matched to Deny List", "id", cve.ID, "metadata", fmt.Sprintf("%+v", cve))
			return false
		}
	}
	return true

}

func ruleGrypeCVEAllow(config *Config, report *artifacts.GrypeReportMin) {
	if !config.Grype.CVERiskAcceptance.Enabled {
		return
	}
	matches := slices.DeleteFunc(report.Matches, func(match artifacts.GrypeMatch) bool {
		allowed := slices.ContainsFunc(config.Grype.CVELimit.CVEs, func(cve configCVE) bool {
			return cve.ID == match.Vulnerability.ID
		})
		if allowed {
			slog.Info("CVE explicitly allowed, removing from subsequent rules",
				"id", match.Vulnerability.ID, "severity", match.Vulnerability.Severity)
		}
		return allowed
	})

	report.Matches = matches
}

func validateGrype(config *Config, report *artifacts.GrypeReportMin) error {

	// 1. Deny List - Fail Matching
	if !ruleGrypeCVEDeny(config, report) {
		return errors.New("grype validation failure: CVE explicitly denied")
	}

	// 2. CVE Allowance - remove from matches
	ruleGrypeCVEAllow(config, report)

	// 3. KEV Catalog Deny List - fail matching TODO: Implement

	// 4. EPSS Allowance - remove from matches TODO: Implement

	// 5. EPSS Limit - Fail Exceeding TODO: Implement

	// 6. Threshold Validation
	if !ruleGrypeLimit(config, report) {
		return errors.New("grype validation failure: Severity Limit Exceeded")
	}

	return nil
}

func validateLimit(configLimit limit, severity string, count int) {
	if !configLimit.Enabled {
		slog.Debug("limit not enabled", "severity", severity, "count", count)
	}
}

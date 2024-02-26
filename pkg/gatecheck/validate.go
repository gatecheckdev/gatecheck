package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/v1"
	"github.com/gatecheckdev/gatecheck/pkg/epss/v1"
	"github.com/gatecheckdev/gatecheck/pkg/kev/v1"
)

type Options struct {
	epssClient *http.Client
	epssURL    string

	kevClient *http.Client
	kevURL    string
}

type optionFunc func(*Options)

func WithEPSSDataFetch(client *http.Client, url string) optionFunc {
	return func(o *Options) {
		o.epssClient = client
		o.epssURL = url
	}
}

func WithKEVDataFetch(client *http.Client, url string) optionFunc {
	return func(o *Options) {
		o.kevClient = client
		o.epssURL = url
	}
}

// Validate against config thresholds
func Validate(config *Config, targetSrc io.Reader, targetfilename string, optionFuncs ...optionFunc) error {
	options := new(Options)
	for _, f := range optionFuncs {
		f(options)
	}

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
		var catalog *kev.Catalog
		var epssData *epss.Data

		if config.Grype.KEVLimitEnabled {
			catalog = kev.NewCatalog()
			err := kev.FetchData(catalog, kev.FetchOptions{Client: options.kevClient, URL: options.kevURL})
			if err != nil {
				return err
			}
		}

		if config.Grype.EPSSLimit.Enabled {
			err := epss.FetchData(epssData, epss.FetchOptions{Client: options.epssClient, URL: options.epssURL})
			if err != nil {
				return err
			}
		}

		return validateGrype(config, report, catalog, epssData)

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
	validationPass := true

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
			continue
		}
		if matchCount > int(configLimit.Limit) {
			slog.Error("grype severity limit exceeded", "severity", severity, "report", matchCount, "limit", configLimit.Limit)
			validationPass = false
		}
		slog.Debug("severity limit valid", "artifact", "grype", "severity", severity, "reported", matchCount)
	}

	return validationPass
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
		slog.Debug("cve risk acceptance not enabled", "artifact", "grype")
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

func ruleGrypeKEVLimit(config *Config, report *artifacts.GrypeReportMin, catalog *kev.Catalog) bool {
	if !config.Grype.KEVLimitEnabled {
		slog.Debug("kev limit not enabled", "artifact", "grype")
		return true
	}
	if catalog == nil {
		slog.Error("kev limit enabled but no catalog data exists")
		return false
	}
	// Check if vulnerability is in the KEV Catalog
	for _, vulnerability := range report.Matches {
		inKEVCatalog := slices.ContainsFunc(catalog.Vulnerabilities, func(kevVul kev.Vulnerability) bool {
			return kevVul.CveID == vulnerability.Vulnerability.ID
		})
		if inKEVCatalog {
			return false
		}
	}
	return true
}

func ruleGrypeEPSSAllow(config *Config, report *artifacts.GrypeReportMin, data *epss.Data) {
	if !config.Grype.EPSSRiskAcceptance.Enabled {
		slog.Debug("epss risk acceptance not enabled", "artifact", "grype")
		return
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists")
		return
	}
	matches := slices.DeleteFunc(report.Matches, func(match artifacts.GrypeMatch) bool {
		epssCVE, ok := data.CVEs[match.Vulnerability.ID]
		if !ok {
			slog.Debug("no epss score", "cve_id", match.Vulnerability.ID, "severity", match.Vulnerability.Severity)
			return false
		}
		riskAccepted := config.Grype.EPSSRiskAcceptance.Score > epssCVE.EPSSValue()
		if riskAccepted {
			slog.Info(
				"risk accepted: epss score is below risk acceptance threshold",
				"cve_id", match.Vulnerability.ID,
				"severity", match.Vulnerability.Severity,
				"epss_score", epssCVE.EPSS,
				"epss_risk_acceptance_score", config.Grype.EPSSRiskAcceptance.Score,
			)
			return true
		}
		return false
	})

	report.Matches = matches
}

func ruleGrypeEPSSLimit(config *Config, report *artifacts.GrypeReportMin, data *epss.Data) bool {
	if !config.Grype.EPSSLimit.Enabled {
		slog.Debug("epss limit not enabled", "artifact", "grype")
		return true
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists")
		return false
	}

	badCVEs := make([]epss.CVE, 0)

	for _, match := range report.Matches {
		epssCVE, ok := data.CVEs[match.Vulnerability.ID]
		if !ok {
			continue
		}
		// add to badCVEs if the score is higher than the limit
		if epssCVE.EPSSValue() > config.Grype.EPSSLimit.Score {
			badCVEs = append(badCVEs, epssCVE)
			slog.Warn(
				"epss score limit violation",
				"cve_id", match.Vulnerability.ID,
				"severity", match.Vulnerability.Severity,
				"epss_score", epssCVE.EPSS,
				"epss_risk_acceptance_score", config.Grype.EPSSRiskAcceptance.Score,
			)
		}
	}
	if len(badCVEs) > 0 {
		slog.Error("more than 0 cves with epss scores over limit",
			"over_limit_cves", len(badCVEs),
			"epss_risk_acceptance_score", config.Grype.EPSSRiskAcceptance.Score,
		)
		return false
	}
	return true
}

func validateGrype(config *Config, report *artifacts.GrypeReportMin, catalog *kev.Catalog, data *epss.Data) error {

	// 1. Deny List - Fail Matching
	if !ruleGrypeCVEDeny(config, report) {
		return errors.New("grype validation failure: CVE explicitly denied")
	}

	// 2. CVE Allowance - remove from matches
	ruleGrypeCVEAllow(config, report)

	// 3. KEV Catalog Limit - fail matching
	if !ruleGrypeKEVLimit(config, report, catalog) {
		return errors.New("grype validation failure: CVE matched to KEV Catalog")
	}

	// 4. EPSS Allowance - remove from matches
	ruleGrypeEPSSAllow(config, report, data)

	// 5. EPSS Limit - Fail Exceeding TODO: Implement
	if !ruleGrypeEPSSLimit(config, report, data) {
		return errors.New("grype validation failure: EPSS limit Exceeded")
	}

	// 6. Threshold Validation
	if !ruleGrypeLimit(config, report) {
		return errors.New("grype validation failure: Severity Limit Exceeded")
	}

	return nil
}

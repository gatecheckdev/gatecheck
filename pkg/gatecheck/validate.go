package gatecheck

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/v1"
	"github.com/gatecheckdev/gatecheck/pkg/epss/v1"
	"github.com/gatecheckdev/gatecheck/pkg/kev/v1"
)

// Validate against config thresholds
func Validate(config *Config, reportSrc io.Reader, targetfilename string, optionFuncs ...optionFunc) error {
	options := defaultOptions()
	for _, f := range optionFuncs {
		f(options)
	}

	switch {
	case strings.Contains(targetfilename, "grype"):
		slog.Debug("validate grype report", "filename", targetfilename)
		return validateGrypeReport(reportSrc, config, options)

	case strings.Contains(targetfilename, "cyclonedx"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "cyclonedx")
		return errors.New("Cyclonedx validation not supported yet.")

	case strings.Contains(targetfilename, "semgrep"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "semgrep")
		return validateSemgrepReport(reportSrc, config)

	case strings.Contains(targetfilename, "gitleaks"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "gitleaks")
		return errors.New("Gitleaks validation not supported yet.")

	case strings.Contains(targetfilename, "syft"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "syft")
		return errors.New("Syft validation not supported yet.")

	case strings.Contains(targetfilename, "bundle"):
		slog.Debug("validate", "filename", targetfilename, "filetype", "bundle")
		return errors.New("Gatecheck bundle validation not yet supported.")

	default:
		slog.Error("invalid input filetype", "filename", targetfilename)
		return errors.New("failed to validate artifact content")
	}
}

func ruleGrypeSeverityLimit(config *Config, report *artifacts.GrypeReportMin) bool {
	validationPass := true

	limits := map[string]configLimit{
		"critical": config.Grype.SeverityLimit.Critical,
		"high":     config.Grype.SeverityLimit.High,
		"medium":   config.Grype.SeverityLimit.Medium,
		"low":      config.Grype.SeverityLimit.Low,
	}

	for _, severity := range []string{"critical", "high", "medium", "low"} {

		configuredLimit := limits[severity]
		matches := report.SelectBySeverity(severity)
		matchCount := len(matches)
		if !configuredLimit.Enabled {
			slog.Debug("severity limit not enabled", "artifact", "grype", "severity", severity, "reported", matchCount)
			continue
		}
		if matchCount > int(configuredLimit.Limit) {
			slog.Error("grype severity limit exceeded", "severity", severity, "report", matchCount, "limit", configuredLimit.Limit)
			validationPass = false
			continue
		}
		slog.Info("severity limit valid", "artifact", "grype", "severity", severity, "reported", matchCount, "limit", configuredLimit.Limit)
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
	slog.Info("kev limit validated, no cves in catalog",
		"vulnerabilities", len(report.Matches), "kev_catalog_count", len(catalog.Vulnerabilities))
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
				"epss_limit_score", config.Grype.EPSSLimit.Score,
			)
		}
	}
	if len(badCVEs) > 0 {
		slog.Error("more than 0 cves with epss scores over limit",
			"over_limit_cves", len(badCVEs),
			"epss_limit_score", config.Grype.EPSSLimit.Score,
		)
		return false
	}
	return true
}

func ruleSemgrepSeverityLimit(config *Config, report *artifacts.SemgrepReportMin) bool {
	validationPass := true

	limits := map[string]configLimit{
		"error":   config.Semgrep.SeverityLimit.Error,
		"warning": config.Semgrep.SeverityLimit.Warning,
		"info":    config.Semgrep.SeverityLimit.Info,
	}

	for _, severity := range []string{"error", "warning", "info"} {

		configuredLimit := limits[severity]
		matches := report.SelectBySeverity(severity)
		matchCount := len(matches)
		if !configuredLimit.Enabled {
			slog.Debug("severity limit not enabled", "artifact", "semgrep", "severity", severity, "reported", matchCount)
			continue
		}
		if matchCount > int(configuredLimit.Limit) {
			slog.Error("severity limit exceeded", "artifact", "semgrep", "severity", severity, "report", matchCount, "limit", configuredLimit.Limit)
			validationPass = false
			continue
		}
		slog.Info("severity limit valid", "artifact", "semgrep", "severity", severity, "reported", matchCount, "limit", configuredLimit.Limit)
	}

	return validationPass
}

func ruleSemgrepImpactRiskAccept(config *Config, report *artifacts.SemgrepReportMin) {

	if !config.Semgrep.ImpactRiskAcceptance.Enabled {
		slog.Debug("impact risk acceptance not enabled", "artifact", "semgrep")
		return
	}

	results := slices.DeleteFunc(report.Results, func(result artifacts.SemgrepResults) bool {
		riskAccepted := false
		switch {
		case config.Semgrep.ImpactRiskAcceptance.High && strings.EqualFold(result.Extra.Severity, "high"):
			riskAccepted = true
		case config.Semgrep.ImpactRiskAcceptance.Medium && strings.EqualFold(result.Extra.Severity, "medium"):
			riskAccepted = true
		case config.Semgrep.ImpactRiskAcceptance.Low && strings.EqualFold(result.Extra.Severity, "low"):
			riskAccepted = true
		}

		if riskAccepted {
			slog.Info(
				"risk accepted: epss score is below risk acceptance threshold",
				"check_id", result.CheckID,
				"severity", result.Extra.Severity,
				"impact", result.Extra.Metadata.Impact,
			)
			return true
		}
		return false
	})

	report.Results = results
}

// Validate Reports

func validateGrypeReport(r io.Reader, config *Config, options *fetchOptions) error {
	var catalog *kev.Catalog
	var epssData *epss.Data

	slog.Debug("validate grype report")

	report := &artifacts.GrypeReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode grype report for validation", "error", err)
		return errors.New("Cannot run Grype validation: Report decoding failed. See log for details.")
	}

	switch {
	case !config.Grype.KEVLimitEnabled:
		break
	case options.kevFile != nil:
		catalog = kev.NewCatalog()
		if err := kev.DecodeData(options.kevFile, catalog); err != nil {
			return err
		}
	default:
		catalog = kev.NewCatalog()
		err := kev.FetchData(catalog, kev.WithClient(options.kevClient), kev.WithURL(options.kevURL))
		if err != nil {
			return err
		}
	}

	switch {
	case !config.Grype.EPSSLimit.Enabled:
		break
	case options.epssFile != nil:
		epssData = new(epss.Data)
		err := epss.ParseEPSSDataCSV(options.epssFile, epssData)
		if err != nil {
			return err
		}
	default:
		epssData = new(epss.Data)
		err := epss.FetchData(epssData, epss.WithClient(options.epssClient), epss.WithURL(options.epssURL))

		if err != nil {
			return err
		}
	}

	return validateGrypeRules(config, report, catalog, epssData)
}

func validateSemgrepReport(r io.Reader, config *Config) error {
	slog.Debug("validate semgrep report")
	report := &artifacts.SemgrepReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode semgrep report for validation", "error", err)
		return errors.New("Cannot run Semgrep report validation: Report decoding failed. See log for details.")
	}

	return validateSemgrepRules(config, report)
}

// Validate Rules

func validateGrypeRules(config *Config, report *artifacts.GrypeReportMin, catalog *kev.Catalog, data *epss.Data) error {

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

	// 6. Severity Count Limit
	if !ruleGrypeSeverityLimit(config, report) {
		return errors.New("grype validation failure: Severity Limit Exceeded")
	}

	return nil
}

func validateSemgrepRules(config *Config, report *artifacts.SemgrepReportMin) error {

	// 1. Impact Allowance - remove result
	ruleSemgrepImpactRiskAccept(config, report)

	// 2. Severity Count Limit
	if !ruleSemgrepSeverityLimit(config, report) {
		return errors.New("semgrep validation failure: Severity Limit Exceeded")
	}

	return nil
}

package gatecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/easy-up/go-coverage"
	"io"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
)

var ErrValidationFailure = errors.New("Validation Failure")

func newValidationErr(details string) error {
	return fmt.Errorf("%w: %s", ErrValidationFailure, details)
}

// Validate against config thresholds
func Validate(config *Config, reportSrc io.Reader, targetFilename string, optionFuncs ...optionFunc) error {
	options := defaultOptions()
	for _, f := range optionFuncs {
		f(options)
	}

	switch {
	case strings.Contains(targetFilename, "grype"):
		slog.Debug("validate grype report", "filename", targetFilename)
		return validateGrypeReportWithFetch(reportSrc, config, options)

	case strings.Contains(targetFilename, "cyclonedx"):
		slog.Debug("validate", "filename", targetFilename, "filetype", "cyclonedx")
		return validateCyclonedxReportWithFetch(reportSrc, config, options)

	case strings.Contains(targetFilename, "semgrep"):
		slog.Debug("validate", "filename", targetFilename, "filetype", "semgrep")
		return validateSemgrepReport(reportSrc, config)

	case strings.Contains(targetFilename, "gitleaks"):
		slog.Debug("validate", "filename", targetFilename, "filetype", "gitleaks")
		return validateGitleaksReport(reportSrc, config)

	case strings.Contains(targetFilename, "syft"):
		slog.Debug("validate", "filename", targetFilename, "filetype", "syft")
		return errors.New("syft validation not supported yet")

	case strings.Contains(targetFilename, "bundle"):
		slog.Debug("validate", "filename", targetFilename, "filetype", "bundle")
		return validateBundle(reportSrc, config, options)

	case artifacts.IsCoverageReport(targetFilename):
		slog.Debug("validate", "filename", targetFilename, "filetype", "coverage")
		return validateCoverage(reportSrc, targetFilename, config)

	default:
		slog.Error("unsupported file type, cannot be determined from filename", "filename", targetFilename)
		return errors.New("Failed to validate artifact. See log for details.")
	}
}

func removeIgnoredSeverityCVEs(config *Config, report *artifacts.GrypeReportMin, data *epss.Data) {
	hasLimits := map[string]bool{
		"critical":   config.Grype.SeverityLimit.Critical.Enabled,
		"high":       config.Grype.SeverityLimit.High.Enabled,
		"medium":     config.Grype.SeverityLimit.Medium.Enabled,
		"low":        config.Grype.SeverityLimit.Low.Enabled,
		"unknown":    false,
		"negligible": false,
	}

	for severity, hasLimit := range hasLimits {
		if hasLimit {
			continue
		}

		if config.Grype.EPSSLimit.Enabled {
			report.Matches = slices.DeleteFunc(report.Matches, func(match artifacts.GrypeMatch) bool {
				epssCVE, ok := data.CVEs[match.Vulnerability.ID]
				return strings.ToLower(match.Vulnerability.Severity) == severity && (!ok || epssCVE.EPSSValue() < config.Grype.EPSSLimit.Score)
			})
		} else {
			report.Matches = slices.DeleteFunc(report.Matches, func(match artifacts.GrypeMatch) bool {
				return strings.ToLower(match.Vulnerability.Severity) == severity
			})
		}
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
			for _, match := range matches {
				slog.Info("vulnerability detected", "id", match.Vulnerability.ID, "severity", match.Vulnerability.Severity)
			}
			validationPass = false
			continue
		}
		slog.Info("severity limit valid", "artifact", "grype", "severity", severity, "reported", matchCount, "limit", configuredLimit.Limit)
	}

	return validationPass
}

func ruleCyclonedxSeverityLimit(config *Config, report *artifacts.CyclonedxReportMin) bool {
	validationPass := true

	limits := map[string]configLimit{
		"critical": config.Cyclonedx.SeverityLimit.Critical,
		"high":     config.Cyclonedx.SeverityLimit.High,
		"medium":   config.Cyclonedx.SeverityLimit.Medium,
		"low":      config.Cyclonedx.SeverityLimit.Low,
	}

	for _, severity := range []string{"critical", "high", "medium", "low"} {

		configuredLimit := limits[severity]
		vulnerabilities := report.SelectBySeverity(severity)
		matchCount := len(vulnerabilities)
		if !configuredLimit.Enabled {
			slog.Debug("severity limit not enabled", "artifact", "cyclonedx", "severity", severity, "reported", matchCount)
			continue
		}
		if matchCount > int(configuredLimit.Limit) {
			slog.Error("severity limit exceeded", "artifact", "cyclonedx", "severity", severity, "report", matchCount, "limit", configuredLimit.Limit)
			validationPass = false
			continue
		}
		slog.Info("severity limit valid", "artifact", "cyclonedx", "severity", severity, "reported", matchCount, "limit", configuredLimit.Limit)
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
			return strings.EqualFold(match.Vulnerability.ID, cve.ID)
		})

		if contains {
			slog.Error("cve matched to Deny List", "artifact", "grype", "id", cve.ID, "metadata", fmt.Sprintf("%+v", cve))
			return false
		}
	}
	return true
}

func ruleCyclonedxCVEDeny(config *Config, report *artifacts.CyclonedxReportMin) bool {
	if !config.Cyclonedx.CVELimit.Enabled {
		slog.Debug("cve id limits not enabled", "artifact", "cyclonedx", "count_denied", len(config.Cyclonedx.CVELimit.CVEs))
		return true
	}
	for _, cve := range config.Cyclonedx.CVELimit.CVEs {
		contains := slices.ContainsFunc(report.Vulnerabilities, func(vulerability artifacts.CyclonedxVulnerability) bool {
			return strings.EqualFold(vulerability.ID, cve.ID)
		})

		if contains {
			slog.Error("cve matched to Deny List", "artifact", "cyclonedx", "id", cve.ID, "metadata", fmt.Sprintf("%+v", cve))
			return false
		}
	}
	return true
}

func ruleGrypeCVEAllow(config *Config, report *artifacts.GrypeReportMin) {
	slog.Debug("cve id risk acceptance rule", "artifact", "grype",
		"enabled", config.Grype.CVERiskAcceptance.Enabled,
		"risk_accepted_cves", len(config.Grype.CVERiskAcceptance.CVEs),
	)

	if !config.Grype.CVERiskAcceptance.Enabled {
		return
	}
	matches := slices.DeleteFunc(report.Matches, func(match artifacts.GrypeMatch) bool {
		allowed := slices.ContainsFunc(config.Grype.CVERiskAcceptance.CVEs, func(cve configCVE) bool {
			return strings.EqualFold(cve.ID, match.Vulnerability.ID)
		})
		if allowed {
			slog.Info("CVE explicitly allowed, removing from subsequent rules",
				"id", match.Vulnerability.ID, "severity", match.Vulnerability.Severity)
		}
		return allowed
	})

	report.Matches = matches
}

func ruleCyclonedxCVEAllow(config *Config, report *artifacts.CyclonedxReportMin) {
	slog.Debug(
		"cve id risk acceptance rule", "artifact", "cyclonedx",
		"enabled", config.Cyclonedx.CVERiskAcceptance.Enabled,
		"risk_accepted_cves", len(config.Cyclonedx.CVERiskAcceptance.CVEs),
	)

	if !config.Cyclonedx.CVERiskAcceptance.Enabled {
		return
	}

	vulnerabilities := slices.DeleteFunc(report.Vulnerabilities, func(vulnerability artifacts.CyclonedxVulnerability) bool {
		allowed := slices.ContainsFunc(config.Cyclonedx.CVERiskAcceptance.CVEs, func(cve configCVE) bool {
			return strings.EqualFold(cve.ID, vulnerability.ID)
		})
		if allowed {
			slog.Info("CVE explicitly allowed, removing from subsequent rules",
				"id", vulnerability.ID, "severity", vulnerability.HighestSeverity())
		}
		return allowed
	})

	report.Vulnerabilities = vulnerabilities
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
	badCVEs := make([]string, 0)
	// Check if vulnerability is in the KEV Catalog
	for _, vulnerability := range report.Matches {
		inKEVCatalog := slices.ContainsFunc(catalog.Vulnerabilities, func(kevVul kev.Vulnerability) bool {
			return kevVul.CveID == vulnerability.Vulnerability.ID
		})
		if inKEVCatalog {
			badCVEs = append(badCVEs, vulnerability.Vulnerability.ID)
			slog.Warn("cve found in kev catalog",
				"cve_id", vulnerability.Vulnerability.ID)
		}
	}
	if len(badCVEs) > 0 {
		slog.Error("cve(s) found in kev catalog",
			"vulnerabilities", len(badCVEs), "kev_catalog_count", len(catalog.Vulnerabilities))
		return false
	}
	slog.Info("kev limit validated, no cves in catalog",
		"vulnerabilities", len(report.Matches), "kev_catalog_count", len(catalog.Vulnerabilities))
	return true
}

func ruleCyclonedxKEVLimit(config *Config, report *artifacts.CyclonedxReportMin, catalog *kev.Catalog) bool {
	if !config.Cyclonedx.KEVLimitEnabled {
		slog.Debug("kev limit not enabled", "artifact", "cyclonedx")
		return true
	}
	if catalog == nil {
		slog.Error("kev limit enabled but no catalog data exists", "artifact", "cyclonedx")
		return false
	}
	badCVEs := make([]string, 0)
	// Check if vulnerability is in the KEV Catalog
	for _, vulnerability := range report.Vulnerabilities {
		inKEVCatalog := slices.ContainsFunc(catalog.Vulnerabilities, func(kevVul kev.Vulnerability) bool {
			return strings.EqualFold(kevVul.CveID, vulnerability.ID)
		})

		if inKEVCatalog {
			badCVEs = append(badCVEs, vulnerability.ID)
			slog.Warn("cve found in kev catalog",
				"cve_id", vulnerability.ID)
		}
	}
	if len(badCVEs) > 0 {
		slog.Error("cve(s) found in kev catalog",
			"vulnerabilities", len(badCVEs), "kev_catalog_count", len(catalog.Vulnerabilities))
		return false
	}
	slog.Info("kev limit validated, no cves in catalog",
		"vulnerabilities", len(report.Vulnerabilities), "kev_catalog_count", len(catalog.Vulnerabilities))
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
	slog.Debug("run epss risk acceptance filter",
		"artifact", "grype",
		"vulnerabilities", len(report.Matches),
		"epss_risk_acceptance_score", config.Cyclonedx.EPSSRiskAcceptance.Score,
	)
	matches := slices.DeleteFunc(report.Matches, func(match artifacts.GrypeMatch) bool {
		epssCVE, ok := data.CVEs[match.Vulnerability.ID]
		if !ok {
			slog.Debug("no epss score", "cve_id", match.Vulnerability.ID, "severity", match.Vulnerability.Severity)
			return false
		}
		riskAccepted := config.Grype.EPSSRiskAcceptance.Score > epssCVE.EPSSValue()
		if riskAccepted {
			slog.Info(
				"risk accepted reason: epss score",
				"cve_id", match.Vulnerability.ID,
				"severity", match.Vulnerability.Severity,
				"epss_score", epssCVE.EPSS,
			)
			return true
		}
		return false
	})

	report.Matches = matches
}

func ruleCyclonedxEPSSAllow(config *Config, report *artifacts.CyclonedxReportMin, data *epss.Data) {
	if !config.Cyclonedx.EPSSRiskAcceptance.Enabled {
		slog.Debug("epss risk acceptance not enabled", "artifact", "cyclonedx")
		return
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists", "artifact", "cyclonedx")
		return
	}
	slog.Debug("run epss risk acceptance filter",
		"artifact", "cyclonedx",
		"vulnerabilities", len(report.Vulnerabilities),
		"epss_risk_acceptance_score", config.Cyclonedx.EPSSRiskAcceptance.Score,
	)
	vulnerabilities := slices.DeleteFunc(report.Vulnerabilities, func(vulnerability artifacts.CyclonedxVulnerability) bool {
		epssCVE, ok := data.CVEs[vulnerability.ID]
		if !ok {
			slog.Debug("no epss score", "cve_id", vulnerability.ID, "severity", vulnerability.HighestSeverity())
			return false
		}
		riskAccepted := config.Cyclonedx.EPSSRiskAcceptance.Score > epssCVE.EPSSValue()
		if riskAccepted {
			slog.Info(
				"risk accepted reason: epss score",
				"cve_id", vulnerability.ID,
				"severity", vulnerability.HighestSeverity(),
				"epss_score", epssCVE.EPSS,
			)
			return true
		}
		return false
	})

	report.Vulnerabilities = vulnerabilities
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

	slog.Debug("run epss limit rule",
		"artifact", "grype",
		"vulnerabilities", len(report.Matches),
		"epss_limit_score", config.Grype.EPSSLimit.Score,
	)
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
			)
		}
	}
	if len(badCVEs) > 0 {
		slog.Error("cve(s) with epss scores over limit",
			"over_limit_cves", len(badCVEs),
			"epss_limit_score", config.Grype.EPSSLimit.Score,
		)
		return false
	}
	return true
}

func ruleCyclonedxEPSSLimit(config *Config, report *artifacts.CyclonedxReportMin, data *epss.Data) bool {
	if !config.Cyclonedx.EPSSLimit.Enabled {
		slog.Debug("epss limit not enabled", "artifact", "cyclonedx")
		return true
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists")
		return false
	}

	badCVEs := make([]epss.CVE, 0)

	slog.Debug("run epss limit rule",
		"artifact", "cyclonedx",
		"vulnerabilities", len(report.Vulnerabilities),
		"epss_limit_score", config.Cyclonedx.EPSSLimit.Score,
	)

	for _, vulnerability := range report.Vulnerabilities {
		epssCVE, ok := data.CVEs[vulnerability.ID]
		if !ok {
			continue
		}
		// add to badCVEs if the score is higher than the limit
		if epssCVE.EPSSValue() > config.Cyclonedx.EPSSLimit.Score {
			badCVEs = append(badCVEs, epssCVE)
			slog.Warn(
				"epss score limit violation",
				"cve_id", vulnerability.ID,
				"severity", vulnerability.HighestSeverity(),
				"epss_score", epssCVE.EPSS,
			)
		}
	}
	if len(badCVEs) > 0 {
		slog.Error("cve(s) with epss scores over limit",
			"over_limit_cves", len(badCVEs),
			"epss_limit_score", config.Cyclonedx.EPSSLimit.Score,
		)
		return false
	}
	return true
}

func removeIgnoredSemgrepIssues(config *Config, report *artifacts.SemgrepReportMin) {
	hasLimits := map[string]bool{
		"error":   config.Semgrep.SeverityLimit.Error.Enabled,
		"warning": config.Semgrep.SeverityLimit.Warning.Enabled,
		"info":    config.Semgrep.SeverityLimit.Info.Enabled,
	}

	for severity, hasLimit := range hasLimits {
		if hasLimit {
			continue
		}

		report.Results = slices.DeleteFunc(report.Results, func(result artifacts.SemgrepResults) bool {
			return strings.EqualFold(result.Extra.Severity, severity)
		})
	}
}

func ruleSemgrepSeverityLimit(config *Config, report *artifacts.SemgrepReportMin) bool {
	slog.Debug(
		"severity limit rule", "artifact", "semgrep",
		"error_enabled", config.Semgrep.SeverityLimit.Error.Enabled,
		"info_enabled", config.Semgrep.SeverityLimit.Info.Enabled,
		"warning_enabled", config.Semgrep.SeverityLimit.Warning.Enabled,
	)

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
			for _, match := range matches {
				slog.Info("Potential issue detected", "severity", match.Extra.Severity, "check_id", match.CheckID, "message", match.Extra.Message)
			}
			validationPass = false
			continue
		}
		slog.Info("severity limit valid", "artifact", "semgrep", "severity", severity, "reported", matchCount, "limit", configuredLimit.Limit)
	}

	return validationPass
}

func ruleSemgrepImpactRiskAccept(config *Config, report *artifacts.SemgrepReportMin) {
	slog.Debug(
		"impact risk accept rule", "artifact", "semgrep",
		"enabled", config.Semgrep.ImpactRiskAcceptance.Enabled,
		"high", config.Semgrep.ImpactRiskAcceptance.High,
		"medium", config.Semgrep.ImpactRiskAcceptance.Medium,
		"low", config.Semgrep.ImpactRiskAcceptance.Low,
	)

	if !config.Semgrep.ImpactRiskAcceptance.Enabled {
		slog.Debug("impact risk acceptance not enabled", "artifact", "semgrep")
		return
	}

	results := slices.DeleteFunc(report.Results, func(result artifacts.SemgrepResults) bool {
		riskAccepted := false
		// TODO: make the configuration for risk acceptance less dumb (what would you accept high medium impact and not accept low impact)
		switch {
		case config.Semgrep.ImpactRiskAcceptance.High && strings.EqualFold(result.Extra.Metadata.Impact, "high"):
			riskAccepted = true
		case config.Semgrep.ImpactRiskAcceptance.Medium && strings.EqualFold(result.Extra.Metadata.Impact, "medium"):
			riskAccepted = true
		case config.Semgrep.ImpactRiskAcceptance.Low && strings.EqualFold(result.Extra.Metadata.Impact, "low"):
			riskAccepted = true
		}

		if riskAccepted {
			slog.Info(
				"risk accepted: Semgrep issue impact is below acceptance threshold",
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

func ruleGitLeaksLimit(config *Config, report *artifacts.GitLeaksReportMin) bool {
	if !config.Gitleaks.LimitEnabled {
		slog.Debug("secrets limit not enabled", "artifact", "gitleaks")
		return true
	}
	detectedSecrets := report.Count()
	if detectedSecrets > 0 {
		slog.Error("committed secrets violation", "artifacts", "gitleaks", "secrets_detected", detectedSecrets)
		return false
	}
	return true
}

func loadCatalogFromFileOrAPI(catalog *kev.Catalog, options *fetchOptions) error {
	if options.kevFile != nil {
		slog.Debug("load kev catalog from file", "filename", options.kevFile)
		err := kev.DecodeData(options.kevFile, catalog)
		return err
	}

	slog.Debug("load kev catalog from API")
	err := kev.FetchData(catalog, kev.WithClient(options.kevClient), kev.WithURL(options.kevURL))
	return err
}

func loadDataFromFileOrAPI(epssData *epss.Data, options *fetchOptions) error {
	if options.epssFile != nil {
		err := epss.ParseEPSSDataCSV(options.epssFile, epssData)
		return err
	}

	slog.Debug("load epss data from API")
	err := epss.FetchData(epssData, epss.WithClient(options.epssClient), epss.WithURL(options.epssURL))

	return err
}

func LoadCatalogAndData(config *Config, catalog *kev.Catalog, epssData *epss.Data, options *fetchOptions) error {
	if config.Grype.KEVLimitEnabled || config.Cyclonedx.KEVLimitEnabled {
		if err := loadCatalogFromFileOrAPI(catalog, options); err != nil {
			return err
		}
	}

	grypeEPSSNeeded := config.Grype.EPSSLimit.Enabled || config.Grype.EPSSRiskAcceptance.Enabled
	cyclonedxEPSSNeeded := config.Cyclonedx.EPSSLimit.Enabled || config.Cyclonedx.EPSSRiskAcceptance.Enabled

	if grypeEPSSNeeded || cyclonedxEPSSNeeded {
		if err := loadDataFromFileOrAPI(epssData, options); err != nil {
			return err
		}
	}
	return nil
}

// Validate Reports

func validateGrypeReportWithFetch(r io.Reader, config *Config, options *fetchOptions) error {
	catalog := kev.NewCatalog()
	epssData := new(epss.Data)

	if err := LoadCatalogAndData(config, catalog, epssData, options); err != nil {
		slog.Error("validate grype report: load epss data from file or api", "error", err)
		return errors.New("Cannot run Grype validation: Cannot load external validation data. See log for details.")
	}

	return validateGrypeFrom(r, config, catalog, epssData)
}

func validateGrypeFrom(r io.Reader, config *Config, catalog *kev.Catalog, epssData *epss.Data) error {
	slog.Debug("validate grype report")
	report := &artifacts.GrypeReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode grype report for validation", "error", err)
		return errors.New("Cannot run Grype validation: Report decoding failed. See log for details.")
	}

	return validateGrypeRules(config, report, catalog, epssData)
}

func validateCyclonedxReportWithFetch(r io.Reader, config *Config, options *fetchOptions) error {
	slog.Debug("validate cyclonedx report")

	catalog := kev.NewCatalog()
	epssData := new(epss.Data)

	if err := LoadCatalogAndData(config, catalog, epssData, options); err != nil {
		slog.Error("validate cyclonedx report: load epss data from file or api", "error", err)
		return errors.New("Cannot run Cyclonedx validation: Cannot load external validation data. See log for details.")
	}
	return validateCyclonedxFrom(r, config, catalog, epssData)
}

func validateCyclonedxFrom(r io.Reader, config *Config, catalog *kev.Catalog, epssData *epss.Data) error {
	report := &artifacts.CyclonedxReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode cyclonedx report for validation", "error", err)
		return errors.New("Cannot run Cyclonedx validation: Report decoding failed. See log for details.")
	}

	return validateCyclonedxRules(config, report, catalog, epssData)
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

func validateGitleaksReport(r io.Reader, config *Config) error {
	slog.Debug("validate gitleaks report")
	report := &artifacts.GitLeaksReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode gitleaks report for validation", "error", err)
		return errors.New("Cannot run Semgrep report validation: Report decoding failed. See log for details.")
	}
	return validateGitleaksRules(config, report)
}

func validateCoverage(src io.Reader, targetFilename string, config *Config) error {
	coverageFormat, err := artifacts.GetCoverageMode(targetFilename)
	if err != nil {
		return err
	}

	parser := coverage.New(coverageFormat)
	report, err := parser.ParseReader(src)
	if err != nil {
		return err
	}

	lineCoverage := float32(report.CoveredLines) / float32(report.TotalLines)
	functionCoverage := float32(report.CoveredFunctions) / float32(report.TotalFunctions)
	branchCoverage := float32(report.CoveredBranches) / float32(report.TotalBranches)

	slog.Info(
		"validate coverage",
		"line_coverage", lineCoverage,
		"function_coverage", functionCoverage,
		"branch_coverage", branchCoverage,
	)

	var errs error

	if lineCoverage < config.Coverage.LineThreshold {
		slog.Error("line coverage below threshold", "line_coverage", lineCoverage, "threshold", config.Coverage.LineThreshold)
		coverageErr := newValidationErr("Coverage: Line coverage below threshold")
		errs = errors.Join(errs, coverageErr)
	}

	if functionCoverage < config.Coverage.FunctionThreshold {
		slog.Error("function coverage below threshold", "function_coverage", functionCoverage, "threshold", config.Coverage.FunctionThreshold)
		coverageErr := newValidationErr("Coverage: Function coverage below threshold")
		errs = errors.Join(errs, coverageErr)
	}

	if branchCoverage < config.Coverage.BranchThreshold {
		slog.Error("branch coverage below threshold", "branch_coverage", branchCoverage, "threshold", config.Coverage.BranchThreshold)
		coverageErr := newValidationErr("Coverage: Branch coverage below threshold")
		errs = errors.Join(errs, coverageErr)
	}

	return errs
}

func validateBundle(r io.Reader, config *Config, options *fetchOptions) error {
	slog.Debug("validate gatecheck bundle")
	bundle := archive.NewBundle()
	if err := archive.UntarGzipBundle(r, bundle); err != nil {
		slog.Error("decode gatecheck bundle")
		return errors.New("Cannot run Gatecheck Bundle validation: Bundle decoding failed. See log for details.")
	}

	catalog := kev.NewCatalog()
	epssData := new(epss.Data)

	if err := LoadCatalogAndData(config, catalog, epssData, options); err != nil {
		slog.Error("validate cyclonedx report: load epss data from file or api", "error", err)
		return errors.New("Cannot run Cyclonedx validation: Cannot load external validation data. See log for details.")
	}

	var errs error
	for fileLabel, descriptor := range bundle.Manifest().Files {
		slog.Info("gatecheck bundle validation", "file_label", fileLabel, "digest", descriptor.Digest)
		switch {
		case strings.Contains(fileLabel, "grype"):
			err := validateGrypeFrom(bytes.NewBuffer(bundle.FileBytes(fileLabel)), config, catalog, epssData)
			errs = errors.Join(errs, err)
		case strings.Contains(fileLabel, "cyclonedx"):
			err := validateCyclonedxFrom(bytes.NewBuffer(bundle.FileBytes(fileLabel)), config, catalog, epssData)
			errs = errors.Join(errs, err)
		case strings.Contains(fileLabel, "semgrep"):
			err := validateSemgrepReport(bytes.NewBuffer(bundle.FileBytes(fileLabel)), config)
			errs = errors.Join(errs, err)
		case strings.Contains(fileLabel, "gitleaks"):
			err := validateGitleaksReport(bytes.NewBuffer(bundle.FileBytes(fileLabel)), config)
			errs = errors.Join(errs, err)
		case artifacts.IsCoverageReport(fileLabel):
			err := validateCoverage(bytes.NewBuffer(bundle.FileBytes(fileLabel)), fileLabel, config)
			errs = errors.Join(errs, err)
		}
	}
	if errs != nil {
		return errors.Join(newValidationErr("Gatecheck Bundle"), errs)
	}
	return nil
}

// Validate Rules

func validateGrypeRules(config *Config, report *artifacts.GrypeReportMin, catalog *kev.Catalog, data *epss.Data) error {
	severityRank := []string{
		"critical",
		"high",
		"medium",
		"low",
		"negligible",
		"unknown",
	}
	sort.Slice(report.Matches, func(i, j int) bool {
		if report.Matches[i].Vulnerability.Severity == report.Matches[j].Vulnerability.Severity {
			epssi, oki := data.CVEs[report.Matches[i].Vulnerability.ID]
			epssj, okj := data.CVEs[report.Matches[j].Vulnerability.ID]

			// Sort EPPS from highest to lowest
			return !okj || oki && epssi.EPSSValue() > epssj.EPSSValue()
		}
		ranki := slices.Index(severityRank, strings.ToLower(report.Matches[i].Vulnerability.Severity))
		rankj := slices.Index(severityRank, strings.ToLower(report.Matches[j].Vulnerability.Severity))
		return ranki < rankj
	})
	// 1. Deny List - Fail Matching
	if !ruleGrypeCVEDeny(config, report) {
		return newValidationErr("Grype: CVE explicitly denied")
	}

	// Ignore any CVEs that don't meet the vulnerability threshold or the EPPS threshold
	removeIgnoredSeverityCVEs(config, report, data)

	// 2. CVE Allowance - remove from matches
	ruleGrypeCVEAllow(config, report)

	// 3. KEV Catalog Limit - fail matching
	if !ruleGrypeKEVLimit(config, report, catalog) {
		return newValidationErr("Grype: CVE matched to KEV Catalog")
	}

	// 4. EPSS Allowance - remove from matches
	ruleGrypeEPSSAllow(config, report, data)

	// 5. EPSS Limit - Fail Exceeding TODO: Implement
	if !ruleGrypeEPSSLimit(config, report, data) {
		return newValidationErr("Grype: EPSS Limit Exceeded")
	}

	// 6. Severity Count Limit
	if !ruleGrypeSeverityLimit(config, report) {
		return newValidationErr("Grype: Severity Limit Exceeded")
	}

	return nil
}

func validateCyclonedxRules(config *Config, report *artifacts.CyclonedxReportMin, catalog *kev.Catalog, data *epss.Data) error {
	// 1. Deny List - Fail Matching
	if !ruleCyclonedxCVEDeny(config, report) {
		return newValidationErr("CycloneDx: CVE explicitly denied")
	}

	// 2. CVE Allowance - remove from matches
	ruleCyclonedxCVEAllow(config, report)

	// 3. KEV Catalog Limit - fail matching
	if !ruleCyclonedxKEVLimit(config, report, catalog) {
		return newValidationErr("CycloneDx: CVE Matched to KEV Catalog")
	}

	// 4. EPSS Allowance - remove from matches
	ruleCyclonedxEPSSAllow(config, report, data)

	// 5. EPSS Limit - Fail Exceeding
	if !ruleCyclonedxEPSSLimit(config, report, data) {
		return newValidationErr("CycloneDx: EPSS Limit Exceeded")
	}

	// 6. Severity Count Limit
	if !ruleCyclonedxSeverityLimit(config, report) {
		return newValidationErr("CycloneDx: Severity Limit Exceeded")
	}

	return nil
}

func validateSemgrepRules(config *Config, report *artifacts.SemgrepReportMin) error {
	slog.Info("validating semgrep rules", "findings", len(report.Results))
	// Ignore issues for which there is no severity limit
	removeIgnoredSemgrepIssues(config, report)

	// 1. Impact Allowance - remove result
	ruleSemgrepImpactRiskAccept(config, report)

	// 2. Severity Count Limit
	if !ruleSemgrepSeverityLimit(config, report) {
		return newValidationErr("Semgrep: Severity Limit Exceeded")
	}

	return nil
}

func validateGitleaksRules(config *Config, report *artifacts.GitLeaksReportMin) error {
	// 1. Limit Secrets - fail
	if !ruleGitLeaksLimit(config, report) {
		return newValidationErr("Gitleaks: Secrets Detected")
	}
	return nil
}

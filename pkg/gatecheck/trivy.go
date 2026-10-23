package gatecheck

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
	"github.com/olekukonko/tablewriter"
)

func ListTrivyReport(table *tablewriter.Table, src io.Reader) error {
	findings, err := decodeTrivyFindings(src)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return emptyReport("No trivy vulnerabilities")
	}

	catLess := format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 0, catLess)
	for _, finding := range findings {
		matrix.Append([]string{titleSeverity(finding.Severity), finding.Package, finding.Version, finding.Link})
	}
	sort.Sort(matrix)

	table.Header([]string{"Trivy Severity", "Package", "Version", "Link"})
	return matrix.Table(table)
}

func listTrivyWithEPSS(table *tablewriter.Table, src io.Reader, epssData *epss.Data) error {
	findings, err := decodeTrivyFindings(src)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return emptyReport("No trivy vulnerabilities")
	}

	catLess := format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 1, catLess)
	for _, finding := range findings {
		score, prctl := "-", "-"
		if cve, ok := lookupEPSS(epssData, finding.CVE()); ok {
			score = cve.EPSS
			prctl = cve.Percentile
		}
		matrix.Append([]string{
			finding.CVE(),
			titleSeverity(finding.Severity),
			score,
			prctl,
			finding.Package,
			finding.Version,
			finding.Link,
		})
	}
	sort.Sort(matrix)

	table.Header([]string{"Trivy CVE ID", "Severity", "EPSS Score", "EPSS Prctl", "Package", "Version", "Link"})
	return matrix.Table(table)
}

func decodeTrivyFindings(src io.Reader) ([]artifacts.TrivyFinding, error) {
	report := &artifacts.TrivyReportMin{}
	slog.Debug("decode trivy report", "format", "json")
	if err := json.NewDecoder(src).Decode(report); err != nil {
		return nil, err
	}
	return report.Findings(), nil
}

func validateTrivyReportWithFetch(r io.Reader, config *Config, options *fetchOptions) error {
	catalog := kev.NewCatalog()
	epssData := new(epss.Data)
	if err := LoadCatalogAndData(config, catalog, epssData, options); err != nil {
		slog.Error("validate trivy report: load epss data from file or api", "error", err)
		return errors.New("cannot run Trivy validation: Cannot load external validation data, see log for details")
	}
	return validateTrivyFrom(r, config, catalog, epssData)
}

func validateTrivyFrom(r io.Reader, config *Config, catalog *kev.Catalog, epssData *epss.Data) error {
	slog.Debug("validate trivy report")
	report := &artifacts.TrivyReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode trivy report for validation", "error", err)
		return errors.New("cannot run Trivy validation: Report decoding failed, See log for details")
	}
	findings := report.Findings()
	return validateTrivyRules(config, findings, catalog, epssData)
}

func validateTrivyRules(config *Config, findings []artifacts.TrivyFinding, catalog *kev.Catalog, data *epss.Data) error {
	sortTrivyFindings(findings, data)
	if !ruleTrivyCVEDeny(config, findings) {
		return newValidationErr("Trivy: CVE explicitly denied")
	}
	findings = removeIgnoredTrivySeverities(config, findings, data)
	findings = ruleTrivyCVEAllow(config, findings)
	if !ruleTrivyKEVLimit(config, findings, catalog) {
		return newValidationErr("Trivy: CVE matched to KEV Catalog")
	}
	findings = ruleTrivyEPSSAllow(config, findings, data)
	if !ruleTrivyEPSSLimit(config, findings, data) {
		return newValidationErr("Trivy: EPSS Limit Exceeded")
	}
	if !ruleTrivySeverityLimit(config, findings) {
		return newValidationErr("Trivy: Severity Limit Exceeded")
	}
	return nil
}

func sortTrivyFindings(findings []artifacts.TrivyFinding, data *epss.Data) {
	severityRank := []string{"critical", "high", "medium", "low", "negligible", "unknown"}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			epssi, oki := lookupEPSS(data, findings[i].CVE())
			epssj, okj := lookupEPSS(data, findings[j].CVE())
			return !okj || oki && epssi.EPSSValue() > epssj.EPSSValue()
		}
		return slices.Index(severityRank, findings[i].Severity) < slices.Index(severityRank, findings[j].Severity)
	})
}

func removeIgnoredTrivySeverities(config *Config, findings []artifacts.TrivyFinding, data *epss.Data) []artifacts.TrivyFinding {
	hasLimits := map[string]bool{
		"critical":   config.Trivy.SeverityLimit.Critical.Enabled,
		"high":       config.Trivy.SeverityLimit.High.Enabled,
		"medium":     config.Trivy.SeverityLimit.Medium.Enabled,
		"low":        config.Trivy.SeverityLimit.Low.Enabled,
		"unknown":    false,
		"negligible": false,
	}
	return slices.DeleteFunc(findings, func(finding artifacts.TrivyFinding) bool {
		if hasLimits[finding.Severity] {
			return false
		}
		if config.Trivy.EPSSLimit.Enabled {
			cve, ok := lookupEPSS(data, finding.CVE())
			return !ok || cve.EPSSValue() < config.Trivy.EPSSLimit.Score
		}
		return true
	})
}

func ruleTrivyCVEDeny(config *Config, findings []artifacts.TrivyFinding) bool {
	if !config.Trivy.CVELimit.Enabled {
		slog.Debug("cve id limits not enabled", "artifact", "trivy", "count_denied", len(config.Trivy.CVELimit.CVEs))
		return true
	}
	for _, cve := range config.Trivy.CVELimit.CVEs {
		if slices.ContainsFunc(findings, func(finding artifacts.TrivyFinding) bool {
			return finding.MatchesID(cve.ID)
		}) {
			slog.Error("cve matched to Deny List", "artifact", "trivy", "id", cve.ID, "metadata", cve)
			return false
		}
	}
	return true
}

func ruleTrivyCVEAllow(config *Config, findings []artifacts.TrivyFinding) []artifacts.TrivyFinding {
	slog.Debug("cve id risk acceptance rule", "artifact", "trivy",
		"enabled", config.Trivy.CVERiskAcceptance.Enabled,
		"risk_accepted_cves", len(config.Trivy.CVERiskAcceptance.CVEs),
	)
	if !config.Trivy.CVERiskAcceptance.Enabled {
		return findings
	}
	return slices.DeleteFunc(findings, func(finding artifacts.TrivyFinding) bool {
		allowed := slices.ContainsFunc(config.Trivy.CVERiskAcceptance.CVEs, func(cve configCVE) bool {
			return finding.MatchesID(cve.ID)
		})
		if allowed {
			slog.Info("CVE explicitly allowed, removing from subsequent rules", "id", finding.CVE(), "severity", finding.Severity)
		}
		return allowed
	})
}

func ruleTrivyKEVLimit(config *Config, findings []artifacts.TrivyFinding, catalog *kev.Catalog) bool {
	if !config.Trivy.KEVLimitEnabled {
		slog.Debug("kev limit not enabled", "artifact", "trivy")
		return true
	}
	if catalog == nil {
		slog.Error("kev limit enabled but no catalog data exists", "artifact", "trivy")
		return false
	}
	var bad []string
	for _, finding := range findings {
		id := finding.CVE()
		inCatalog := slices.ContainsFunc(catalog.Vulnerabilities, func(item kev.Vulnerability) bool {
			return strings.EqualFold(item.CveID, id) || finding.MatchesID(item.CveID)
		})
		if inCatalog {
			bad = append(bad, id)
			slog.Warn("cve found in kev catalog", "cve_id", id)
		}
	}
	if len(bad) > 0 {
		slog.Error("cve(s) found in kev catalog", "vulnerabilities", len(bad), "kev_catalog_count", len(catalog.Vulnerabilities))
		return false
	}
	slog.Info("kev limit validated, no cves in catalog", "vulnerabilities", len(findings), "kev_catalog_count", len(catalog.Vulnerabilities))
	return true
}

func ruleTrivyEPSSAllow(config *Config, findings []artifacts.TrivyFinding, data *epss.Data) []artifacts.TrivyFinding {
	if !config.Trivy.EPSSRiskAcceptance.Enabled {
		slog.Debug("epss risk acceptance not enabled", "artifact", "trivy")
		return findings
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists", "artifact", "trivy")
		return findings
	}
	return slices.DeleteFunc(findings, func(finding artifacts.TrivyFinding) bool {
		cve, ok := lookupEPSS(data, finding.CVE())
		if !ok {
			slog.Debug("no epss score", "cve_id", finding.CVE(), "severity", finding.Severity)
			return false
		}
		if config.Trivy.EPSSRiskAcceptance.Score > cve.EPSSValue() {
			slog.Info("risk accepted reason: epss score", "cve_id", finding.CVE(), "severity", finding.Severity, "epss_score", cve.EPSS)
			return true
		}
		return false
	})
}

func ruleTrivyEPSSLimit(config *Config, findings []artifacts.TrivyFinding, data *epss.Data) bool {
	if !config.Trivy.EPSSLimit.Enabled {
		slog.Debug("epss limit not enabled", "artifact", "trivy")
		return true
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists", "artifact", "trivy")
		return false
	}
	var bad int
	for _, finding := range findings {
		cve, ok := lookupEPSS(data, finding.CVE())
		if !ok {
			continue
		}
		if cve.EPSSValue() > config.Trivy.EPSSLimit.Score {
			bad++
			slog.Warn("epss score limit violation", "cve_id", finding.CVE(), "severity", finding.Severity, "epss_score", cve.EPSS)
		}
	}
	if bad > 0 {
		slog.Error("cve(s) with epss scores over limit", "over_limit_cves", bad, "epss_limit_score", config.Trivy.EPSSLimit.Score)
		return false
	}
	return true
}

func ruleTrivySeverityLimit(config *Config, findings []artifacts.TrivyFinding) bool {
	validationPass := true
	limits := map[string]configLimit{
		"critical": config.Trivy.SeverityLimit.Critical,
		"high":     config.Trivy.SeverityLimit.High,
		"medium":   config.Trivy.SeverityLimit.Medium,
		"low":      config.Trivy.SeverityLimit.Low,
	}
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		configuredLimit := limits[severity]
		matches := trivyBySeverity(findings, severity)
		if !configuredLimit.Enabled {
			slog.Debug("severity limit not enabled", "artifact", "trivy", "severity", severity, "reported", len(matches))
			continue
		}
		if len(matches) > int(configuredLimit.Limit) {
			slog.Error("trivy severity limit exceeded", "severity", severity, "report", len(matches), "limit", configuredLimit.Limit)
			for _, match := range matches {
				slog.Info("vulnerability detected", "id", match.CVE(), "severity", match.Severity)
			}
			validationPass = false
			continue
		}
		slog.Info("severity limit valid", "artifact", "trivy", "severity", severity, "reported", len(matches), "limit", configuredLimit.Limit)
	}
	return validationPass
}

func trivyBySeverity(findings []artifacts.TrivyFinding, severity string) []artifacts.TrivyFinding {
	var out []artifacts.TrivyFinding
	for _, finding := range findings {
		if finding.Severity == severity {
			out = append(out, finding)
		}
	}
	return out
}

func lookupEPSS(data *epss.Data, id string) (epss.CVE, bool) {
	if data == nil || data.CVEs == nil || id == "" {
		return epss.CVE{}, false
	}
	if cve, ok := data.CVEs[id]; ok {
		return cve, true
	}
	cve, ok := data.CVEs[strings.ToUpper(id)]
	return cve, ok
}

func titleSeverity(severity string) string {
	switch severity {
	case "critical":
		return "Critical"
	case "high":
		return "High"
	case "medium":
		return "Medium"
	case "low":
		return "Low"
	case "negligible":
		return "Negligible"
	default:
		return "Unknown"
	}
}

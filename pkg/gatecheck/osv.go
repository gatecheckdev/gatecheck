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

func ListOSVReport(table *tablewriter.Table, src io.Reader) error {
	findings, err := decodeOSVFindings(src)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return emptyReport("No osv-scanner vulnerabilities")
	}

	catLess := format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 0, catLess)
	for _, finding := range findings {
		matrix.Append([]string{displaySeverity(finding.Severity), finding.Package, finding.Version, finding.Link})
	}
	sort.Sort(matrix)

	table.Header([]string{"OSV Severity", "Package", "Version", "Link"})
	return matrix.Table(table)
}

func listOSVWithEPSS(table *tablewriter.Table, src io.Reader, epssData *epss.Data) error {
	findings, err := decodeOSVFindings(src)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		return emptyReport("No osv-scanner vulnerabilities")
	}

	catLess := format.NewCatagoricLess([]string{"Critical", "High", "Medium", "Low", "Negligible", "Unknown"})
	matrix := format.NewSortableMatrix(make([][]string, 0), 1, catLess)
	for _, finding := range findings {
		score, prctl := "-", "-"
		if cve, ok := epssByID(epssData, finding.CVE()); ok {
			score = cve.EPSS
			prctl = cve.Percentile
		}
		matrix.Append([]string{
			finding.CVE(),
			displaySeverity(finding.Severity),
			score,
			prctl,
			finding.Package,
			finding.Version,
			finding.Link,
		})
	}
	sort.Sort(matrix)

	table.Header([]string{"OSV ID", "Severity", "EPSS Score", "EPSS Prctl", "Package", "Version", "Link"})
	return matrix.Table(table)
}

func decodeOSVFindings(src io.Reader) ([]artifacts.OSVFinding, error) {
	report := &artifacts.OSVReportMin{}
	slog.Debug("decode osv-scanner report", "format", "json")
	if err := json.NewDecoder(src).Decode(report); err != nil {
		return nil, err
	}
	return report.Findings(), nil
}

func validateOSVReportWithFetch(r io.Reader, config *Config, options *fetchOptions) error {
	catalog := kev.NewCatalog()
	epssData := new(epss.Data)
	if err := LoadCatalogAndData(config, catalog, epssData, options); err != nil {
		slog.Error("validate osv-scanner report: load epss data from file or api", "error", err)
		return errors.New("cannot run osv-scanner validation: Cannot load external validation data, see log for details")
	}
	return validateOSVFrom(r, config, catalog, epssData)
}

func validateOSVFrom(r io.Reader, config *Config, catalog *kev.Catalog, epssData *epss.Data) error {
	slog.Debug("validate osv-scanner report")
	report := &artifacts.OSVReportMin{}
	if err := json.NewDecoder(r).Decode(report); err != nil {
		slog.Error("decode osv-scanner report for validation", "error", err)
		return errors.New("cannot run osv-scanner validation: Report decoding failed, See log for details")
	}
	return validateOSVRules(config, report.Findings(), catalog, epssData)
}

func validateOSVRules(config *Config, findings []artifacts.OSVFinding, catalog *kev.Catalog, data *epss.Data) error {
	sortOSVFindings(findings, data)
	if !ruleOSVCVEDeny(config, findings) {
		return newValidationErr("osv-scanner: CVE explicitly denied")
	}
	findings = removeIgnoredOSVSeverities(config, findings, data)
	findings = ruleOSVCVEAllow(config, findings)
	if !ruleOSVKEVLimit(config, findings, catalog) {
		return newValidationErr("osv-scanner: CVE matched to KEV Catalog")
	}
	findings = ruleOSVEPSSAllow(config, findings, data)
	if !ruleOSVEPSSLimit(config, findings, data) {
		return newValidationErr("osv-scanner: EPSS Limit Exceeded")
	}
	if !ruleOSVSeverityLimit(config, findings) {
		return newValidationErr("osv-scanner: Severity Limit Exceeded")
	}
	return nil
}

func sortOSVFindings(findings []artifacts.OSVFinding, data *epss.Data) {
	severityRank := []string{"critical", "high", "medium", "low", "negligible", "unknown"}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity == findings[j].Severity {
			epssi, oki := epssByID(data, findings[i].CVE())
			epssj, okj := epssByID(data, findings[j].CVE())
			return !okj || oki && epssi.EPSSValue() > epssj.EPSSValue()
		}
		return slices.Index(severityRank, findings[i].Severity) < slices.Index(severityRank, findings[j].Severity)
	})
}

func removeIgnoredOSVSeverities(config *Config, findings []artifacts.OSVFinding, data *epss.Data) []artifacts.OSVFinding {
	hasLimits := map[string]bool{
		"critical":   config.OSVScanner.SeverityLimit.Critical.Enabled,
		"high":       config.OSVScanner.SeverityLimit.High.Enabled,
		"medium":     config.OSVScanner.SeverityLimit.Medium.Enabled,
		"low":        config.OSVScanner.SeverityLimit.Low.Enabled,
		"unknown":    false,
		"negligible": false,
	}
	return slices.DeleteFunc(findings, func(finding artifacts.OSVFinding) bool {
		if hasLimits[finding.Severity] {
			return false
		}
		if config.OSVScanner.EPSSLimit.Enabled {
			cve, ok := epssByID(data, finding.CVE())
			return !ok || cve.EPSSValue() < config.OSVScanner.EPSSLimit.Score
		}
		return true
	})
}

func ruleOSVCVEDeny(config *Config, findings []artifacts.OSVFinding) bool {
	if !config.OSVScanner.CVELimit.Enabled {
		slog.Debug("cve id limits not enabled", "artifact", "osv-scanner", "count_denied", len(config.OSVScanner.CVELimit.CVEs))
		return true
	}
	for _, cve := range config.OSVScanner.CVELimit.CVEs {
		if slices.ContainsFunc(findings, func(finding artifacts.OSVFinding) bool {
			return finding.MatchesID(cve.ID)
		}) {
			slog.Error("cve matched to Deny List", "artifact", "osv-scanner", "id", cve.ID)
			return false
		}
	}
	return true
}

func ruleOSVCVEAllow(config *Config, findings []artifacts.OSVFinding) []artifacts.OSVFinding {
	if !config.OSVScanner.CVERiskAcceptance.Enabled {
		slog.Debug("cve id risk acceptance not enabled", "artifact", "osv-scanner")
		return findings
	}
	return slices.DeleteFunc(findings, func(finding artifacts.OSVFinding) bool {
		allowed := slices.ContainsFunc(config.OSVScanner.CVERiskAcceptance.CVEs, func(cve configCVE) bool {
			return finding.MatchesID(cve.ID)
		})
		if allowed {
			slog.Info("CVE explicitly allowed, removing from subsequent rules", "id", finding.CVE(), "severity", finding.Severity)
		}
		return allowed
	})
}

func ruleOSVKEVLimit(config *Config, findings []artifacts.OSVFinding, catalog *kev.Catalog) bool {
	if !config.OSVScanner.KEVLimitEnabled {
		slog.Debug("kev limit not enabled", "artifact", "osv-scanner")
		return true
	}
	if catalog == nil {
		slog.Error("kev limit enabled but no catalog data exists", "artifact", "osv-scanner")
		return false
	}
	var bad int
	for _, finding := range findings {
		inCatalog := slices.ContainsFunc(catalog.Vulnerabilities, func(item kev.Vulnerability) bool {
			return finding.MatchesID(item.CveID)
		})
		if inCatalog {
			bad++
			slog.Warn("cve found in kev catalog", "cve_id", finding.CVE())
		}
	}
	if bad > 0 {
		slog.Error("cve(s) found in kev catalog", "vulnerabilities", bad, "kev_catalog_count", len(catalog.Vulnerabilities))
		return false
	}
	return true
}

func ruleOSVEPSSAllow(config *Config, findings []artifacts.OSVFinding, data *epss.Data) []artifacts.OSVFinding {
	if !config.OSVScanner.EPSSRiskAcceptance.Enabled {
		slog.Debug("epss risk acceptance not enabled", "artifact", "osv-scanner")
		return findings
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists", "artifact", "osv-scanner")
		return findings
	}
	return slices.DeleteFunc(findings, func(finding artifacts.OSVFinding) bool {
		cve, ok := epssByID(data, finding.CVE())
		if !ok {
			return false
		}
		if config.OSVScanner.EPSSRiskAcceptance.Score > cve.EPSSValue() {
			slog.Info("risk accepted reason: epss score", "cve_id", finding.CVE(), "severity", finding.Severity, "epss_score", cve.EPSS)
			return true
		}
		return false
	})
}

func ruleOSVEPSSLimit(config *Config, findings []artifacts.OSVFinding, data *epss.Data) bool {
	if !config.OSVScanner.EPSSLimit.Enabled {
		slog.Debug("epss limit not enabled", "artifact", "osv-scanner")
		return true
	}
	if data == nil {
		slog.Error("epss allowance enabled but no data exists", "artifact", "osv-scanner")
		return false
	}
	var bad int
	for _, finding := range findings {
		cve, ok := epssByID(data, finding.CVE())
		if !ok {
			continue
		}
		if cve.EPSSValue() > config.OSVScanner.EPSSLimit.Score {
			bad++
			slog.Warn("epss score limit violation", "cve_id", finding.CVE(), "severity", finding.Severity, "epss_score", cve.EPSS)
		}
	}
	if bad > 0 {
		slog.Error("cve(s) with epss scores over limit", "over_limit_cves", bad, "epss_limit_score", config.OSVScanner.EPSSLimit.Score)
		return false
	}
	return true
}

func ruleOSVSeverityLimit(config *Config, findings []artifacts.OSVFinding) bool {
	validationPass := true
	limits := map[string]configLimit{
		"critical": config.OSVScanner.SeverityLimit.Critical,
		"high":     config.OSVScanner.SeverityLimit.High,
		"medium":   config.OSVScanner.SeverityLimit.Medium,
		"low":      config.OSVScanner.SeverityLimit.Low,
	}
	for _, severity := range []string{"critical", "high", "medium", "low"} {
		configuredLimit := limits[severity]
		var count int
		for _, finding := range findings {
			if finding.Severity == severity {
				count++
			}
		}
		if !configuredLimit.Enabled {
			slog.Debug("severity limit not enabled", "artifact", "osv-scanner", "severity", severity, "reported", count)
			continue
		}
		if count > int(configuredLimit.Limit) {
			slog.Error("osv-scanner severity limit exceeded", "severity", severity, "report", count, "limit", configuredLimit.Limit)
			validationPass = false
			continue
		}
		slog.Info("severity limit valid", "artifact", "osv-scanner", "severity", severity, "reported", count, "limit", configuredLimit.Limit)
	}
	return validationPass
}

func epssByID(data *epss.Data, id string) (epss.CVE, bool) {
	if data == nil || data.CVEs == nil || id == "" {
		return epss.CVE{}, false
	}
	if cve, ok := data.CVEs[id]; ok {
		return cve, true
	}
	cve, ok := data.CVEs[strings.ToUpper(id)]
	return cve, ok
}

func displaySeverity(severity string) string {
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

package artifacts

import (
	"encoding/json"
	"strconv"
	"strings"
)

// OSVReportMin is the vulnerability portion of osv-scanner --format json.
type OSVReportMin struct {
	Results []OSVResult `json:"results"`
}

// OSVResult is one scanned source.
type OSVResult struct {
	Source   OSVSource    `json:"source"`
	Packages []OSVPackage `json:"packages"`
}

// OSVSource is the lockfile, SBOM, or directory that was scanned.
type OSVSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

// OSVPackage is one affected package.
type OSVPackage struct {
	Package         OSVPackageInfo     `json:"package"`
	Vulnerabilities []OSVVulnerability `json:"vulnerabilities"`
	Groups          []OSVGroup         `json:"groups"`
}

// OSVPackageInfo identifies a package.
type OSVPackageInfo struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

// OSVVulnerability is one OSV record. Only the fields used for gating are decoded.
type OSVVulnerability struct {
	ID               string          `json:"id"`
	Aliases          []string        `json:"aliases"`
	Summary          string          `json:"summary"`
	Severity         []OSVSeverity   `json:"severity"`
	DatabaseSpecific json.RawMessage `json:"database_specific"`
}

// OSVSeverity is one OSV severity entry. Score is a CVSS vector or a numeric score.
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// OSVGroup aliases that describe one vulnerability. MaxSeverity is a CVSS base score.
type OSVGroup struct {
	IDs         []string `json:"ids"`
	Aliases     []string `json:"aliases"`
	MaxSeverity string   `json:"max_severity"`
}

// OSVFinding is one grouped vulnerability.
type OSVFinding struct {
	IDs      []string
	Severity string
	Package  string
	Version  string
	Link     string
}

// Findings returns one entry per vulnerability group.
// Aliases of the same group are not counted again. License-only packages are skipped.
func (r *OSVReportMin) Findings() []OSVFinding {
	if r == nil {
		return nil
	}
	var out []OSVFinding
	for _, result := range r.Results {
		for _, pkg := range result.Packages {
			grouped := map[string]bool{}
			for _, group := range pkg.Groups {
				finding, ok := findingFromGroup(pkg, group)
				if !ok {
					continue
				}
				for _, id := range group.IDs {
					grouped[id] = true
				}
				out = append(out, finding)
			}
			for _, vuln := range pkg.Vulnerabilities {
				if vuln.ID == "" || grouped[vuln.ID] {
					continue
				}
				out = append(out, findingFromVuln(pkg, vuln))
			}
		}
	}
	return out
}

// CVE returns the first CVE id, or the first id when none start with CVE-.
func (f OSVFinding) CVE() string {
	for _, id := range f.IDs {
		if strings.HasPrefix(strings.ToUpper(id), "CVE-") {
			return id
		}
	}
	if len(f.IDs) == 0 {
		return ""
	}
	return f.IDs[0]
}

// MatchesID reports whether id equals the OSV id or any alias.
func (f OSVFinding) MatchesID(id string) bool {
	for _, got := range f.IDs {
		if strings.EqualFold(got, id) {
			return true
		}
	}
	return false
}

func findingFromGroup(pkg OSVPackage, group OSVGroup) (OSVFinding, bool) {
	ids := appendIDs(nil, group.IDs...)
	ids = appendIDs(ids, group.Aliases...)
	severity := ratingFromScore(group.MaxSeverity)
	for _, vuln := range pkg.Vulnerabilities {
		if !containsID(group.IDs, vuln.ID) && !containsID(ids, vuln.ID) {
			continue
		}
		ids = appendIDs(ids, vuln.ID)
		ids = appendIDs(ids, vuln.Aliases...)
		severity = betterSeverity(severity, vulnSeverity(vuln))
	}
	if len(ids) == 0 {
		return OSVFinding{}, false
	}
	return OSVFinding{
		IDs:      ids,
		Severity: severity,
		Package:  pkg.Package.Name,
		Version:  pkg.Package.Version,
		Link:     osvLink(ids[0]),
	}, true
}

func findingFromVuln(pkg OSVPackage, vuln OSVVulnerability) OSVFinding {
	ids := appendIDs(nil, vuln.ID)
	ids = appendIDs(ids, vuln.Aliases...)
	link := "-"
	if len(ids) > 0 {
		link = osvLink(ids[0])
	}
	return OSVFinding{
		IDs:      ids,
		Severity: vulnSeverity(vuln),
		Package:  pkg.Package.Name,
		Version:  pkg.Package.Version,
		Link:     link,
	}
}

func vulnSeverity(vuln OSVVulnerability) string {
	severity := ratingFromScore(databaseSeverity(vuln.DatabaseSpecific))
	for _, item := range vuln.Severity {
		severity = betterSeverity(severity, ratingFromScore(item.Score))
	}
	return severity
}

func databaseSeverity(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return ""
	}
	sev, _ := obj["severity"].(string)
	return sev
}

func osvLink(id string) string {
	if id == "" {
		return "-"
	}
	return "https://osv.dev/" + id
}

func appendIDs(ids []string, more ...string) []string {
	for _, id := range more {
		if id == "" || containsID(ids, id) {
			continue
		}
		ids = append(ids, id)
	}
	return ids
}

func containsID(ids []string, want string) bool {
	for _, id := range ids {
		if strings.EqualFold(id, want) {
			return true
		}
	}
	return false
}

func betterSeverity(a, b string) string {
	if severityOrder(a) <= severityOrder(b) {
		return a
	}
	return b
}

func severityOrder(severity string) int {
	switch severity {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "negligible":
		return 4
	default:
		return 5
	}
}

func ratingFromScore(raw string) string {
	raw = strings.TrimSpace(raw)
	switch strings.ToLower(raw) {
	case "critical", "high", "medium", "low", "negligible", "unknown":
		return strings.ToLower(raw)
	case "moderate":
		return "medium"
	case "", "none":
		return "unknown"
	}
	score, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return "unknown"
	}
	switch {
	case score >= 9:
		return "critical"
	case score >= 7:
		return "high"
	case score >= 4:
		return "medium"
	case score >= 0.1:
		return "low"
	default:
		return "unknown"
	}
}

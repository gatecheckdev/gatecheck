package artifacts

import "strings"

// TrivyReportMin is the vulnerability portion of a Trivy JSON report.
// Misconfigurations, secrets, and licenses are ignored.
type TrivyReportMin struct {
	SchemaVersion int           `json:"SchemaVersion"`
	ArtifactName  string        `json:"ArtifactName"`
	ArtifactType  string        `json:"ArtifactType"`
	Results       []TrivyResult `json:"Results"`
}

// TrivyResult is one target inside a Trivy report.
type TrivyResult struct {
	Target          string               `json:"Target"`
	Class           string               `json:"Class"`
	Type            string               `json:"Type"`
	Vulnerabilities []TrivyVulnerability `json:"Vulnerabilities"`
}

// TrivyVulnerability is one package vulnerability.
type TrivyVulnerability struct {
	VulnerabilityID  string   `json:"VulnerabilityID"`
	VendorIDs        []string `json:"VendorIDs"`
	PkgName          string   `json:"PkgName"`
	InstalledVersion string   `json:"InstalledVersion"`
	FixedVersion     string   `json:"FixedVersion"`
	Severity         string   `json:"Severity"`
	Title            string   `json:"Title"`
	PrimaryURL       string   `json:"PrimaryURL"`
	DataSource       *struct {
		ID   string `json:"ID"`
		Name string `json:"Name"`
		URL  string `json:"URL"`
	} `json:"DataSource"`
}

// TrivyFinding is one vulnerability flattened across results.
type TrivyFinding struct {
	IDs      []string
	Severity string
	Package  string
	Version  string
	Link     string
}

// Findings returns package vulnerabilities. Other Trivy result classes are skipped.
func (r *TrivyReportMin) Findings() []TrivyFinding {
	if r == nil {
		return nil
	}
	var out []TrivyFinding
	for _, result := range r.Results {
		for _, vuln := range result.Vulnerabilities {
			ids := make([]string, 0, 1+len(vuln.VendorIDs))
			if vuln.VulnerabilityID != "" {
				ids = append(ids, vuln.VulnerabilityID)
			}
			for _, id := range vuln.VendorIDs {
				if id == "" || containsFold(ids, id) {
					continue
				}
				ids = append(ids, id)
			}
			link := vuln.PrimaryURL
			if link == "" && vuln.DataSource != nil {
				link = vuln.DataSource.URL
			}
			if link == "" {
				link = "-"
			}
			out = append(out, TrivyFinding{
				IDs:      ids,
				Severity: normalizeSeverity(vuln.Severity),
				Package:  vuln.PkgName,
				Version:  vuln.InstalledVersion,
				Link:     link,
			})
		}
	}
	return out
}

// CVE returns the first CVE id, or the first id when none start with CVE-.
func (f TrivyFinding) CVE() string {
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

// MatchesID reports whether id equals the vulnerability id or a vendor id.
func (f TrivyFinding) MatchesID(id string) bool {
	return containsFold(f.IDs, id)
}

func containsFold(ids []string, want string) bool {
	for _, id := range ids {
		if strings.EqualFold(id, want) {
			return true
		}
	}
	return false
}

func normalizeSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "negligible":
		return "negligible"
	default:
		return "unknown"
	}
}

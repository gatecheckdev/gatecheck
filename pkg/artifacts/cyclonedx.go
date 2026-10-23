package artifacts

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// CyclonedxReportMin is a minimum representation of an Cyclonedx scan report
//
// It contains only the necessary fields for validation and listing
type CyclonedxReportMin struct {
	Components      []CyclonedxComponent     `json:"components"`
	Vulnerabilities []CyclonedxVulnerability `json:"vulnerabilities"`
}

type CyclonedxComponent struct {
	BOMRef  string `json:"bom-ref"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CyclonedxVulnerability struct {
	ID         string                     `json:"id"`
	BOMRef     string                     `json:"bom-ref"`
	Severity   string                     `json:"severity"`
	Advisories []CyclonedxAdvisory        `json:"advisories"`
	Affects    []CyclondexAffectedPackage `json:"affects"`
	Ratings    []CyclonedxRating          `json:"ratings"`
}

// Identity is the vulnerability id, or the bom-ref when the producer left id empty.
func (v CyclonedxVulnerability) Identity() string {
	if strings.TrimSpace(v.ID) != "" {
		return v.ID
	}
	return v.BOMRef
}

type CyclondexAffectedPackage struct {
	Ref string `json:"ref"`
}

type CyclonedxAdvisory struct {
	URL string `json:"url"`
}

type CyclonedxRating struct {
	Source   CyclonedxSource `json:"source"`
	Severity string          `json:"severity"`
	Score    cyclonedxScore  `json:"score"`
	Method   string          `json:"method"`
}

// cyclonedxScore accepts a JSON number or a numeric string.
// A missing score leaves Valid false so it is not treated as zero.
type cyclonedxScore struct {
	Value float64
	Valid bool
}

func (s *cyclonedxScore) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil
	}
	if data[0] == '"' {
		var text string
		if err := json.Unmarshal(data, &text); err != nil {
			return nil
		}
		parsed, err := strconv.ParseFloat(strings.TrimSpace(text), 64)
		if err != nil {
			return nil
		}
		s.Value = parsed
		s.Valid = true
		return nil
	}
	var number float64
	if err := json.Unmarshal(data, &number); err != nil {
		return nil
	}
	s.Value = number
	s.Valid = true
	return nil
}

type CyclonedxSource struct {
	Name string `json:"name"`
}

func (r *CyclonedxReportMin) SelectBySeverity(severity string) []CyclonedxVulnerability {
	vulnerabilities := []CyclonedxVulnerability{}

	for _, vulnerability := range r.Vulnerabilities {
		if strings.EqualFold(vulnerability.HighestSeverity(), severity) {
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}
	return vulnerabilities
}

func (r *CyclonedxVulnerability) HighestSeverity() string {
	best := ""
	bestRank := -1
	consider := func(severity string) {
		if severity == "" {
			return
		}
		rank := cyclonedxSeverityRank(severity)
		if rank > bestRank {
			best = severity
			bestRank = rank
		}
	}

	for _, rating := range r.Ratings {
		severity := normalizeCyclonedxSeverity(rating.Severity)
		if severity == "" && rating.Score.Valid {
			severity = severityFromCVSS(rating.Score.Value, rating.Method)
		}
		consider(severity)
	}
	if best == "" {
		consider(normalizeCyclonedxSeverity(r.Severity))
	}
	if best == "" {
		return "unknown"
	}
	return best
}

func normalizeCyclonedxSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return ""
	case "critical":
		return "critical"
	case "high", "important":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "note":
		return "info"
	case "none", "negligible":
		return "none"
	case "unknown", "unspecified":
		return "unknown"
	default:
		return strings.ToLower(strings.TrimSpace(raw))
	}
}

func cyclonedxSeverityRank(severity string) int {
	switch severity {
	case "critical":
		return 7
	case "high":
		return 6
	case "medium":
		return 5
	case "low":
		return 4
	case "info":
		return 3
	case "none":
		return 2
	case "unknown":
		return 1
	default:
		return 0
	}
}

func severityFromCVSS(score float64, method string) string {
	v2 := strings.Contains(strings.ToLower(method), "cvssv2")
	switch {
	case score <= 0:
		return "none"
	case score < 4:
		return "low"
	case score < 7:
		return "medium"
	case v2 || score < 9:
		return "high"
	default:
		return "critical"
	}
}

func (r CyclonedxReportMin) AffectedPackages(vulnerabilityIndex int) string {
	refs := []string{}

	for _, affected := range r.Vulnerabilities[vulnerabilityIndex].Affects {
		refs = append(refs, affected.Ref)
	}

	pkgs := []string{}
	// The components in the sbom are linked to affected vulnerabilities
	for _, ref := range refs {
		for _, component := range r.Components {
			if ref == component.BOMRef {
				pkgs = append(pkgs, fmt.Sprintf("%s [%s]", component.Name, component.Version))
			}
		}
	}
	if len(pkgs) == 0 {
		return strings.Join(refs, ", ")
	}

	return strings.Join(pkgs, ", ")
}

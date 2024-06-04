package artifacts

import (
	"cmp"
	"fmt"
	"slices"
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
	Advisories []CyclonedxAdvisory        `json:"advisories"`
	Affects    []CyclondexAffectedPackage `json:"affects"`
	Ratings    []CyclonedxRating          `json:"ratings"`
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
	order := map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	rating := slices.MaxFunc(r.Ratings, func(a, b CyclonedxRating) int {
		return cmp.Compare(order[a.Severity], order[b.Severity])
	})
	return rating.Severity
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

	return strings.Join(pkgs, ", ")
}

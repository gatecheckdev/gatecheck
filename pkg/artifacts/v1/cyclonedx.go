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
	Components []struct {
		BOMRef  string `json:"bom-ref"`
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"components"`
	Vulnerabilities []struct {
		ID         string `json:"id"`
		Advisories []struct {
			URL string `json:"url"`
		} `json:"advisories"`
		Affects []struct {
			Ref string `json:"ref"`
		} `json:"affects"`
		Ratings []cyclonedxRating
	} `json:"vulnerabilities"`
}

type cyclonedxRating struct {
	Source struct {
		Name string `json:"name"`
	} `json:"source"`
	Severity string `json:"severity"`
}

func (r CyclonedxReportMin) HighestSeverity(vulnerabilityIndex int) string {
	order := map[string]int{"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
	rating := slices.MaxFunc(r.Vulnerabilities[vulnerabilityIndex].Ratings, func(a, b cyclonedxRating) int {
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

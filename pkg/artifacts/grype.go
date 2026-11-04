package artifacts

import "strings"

// GrypeReportMin is a minimum representation of an Anchore Grype scan report
//
// It contains only the necessary fields for validation and listing
type GrypeReportMin struct {
	Descriptor GrypeDescriptor `json:"descriptor"`
	Matches    []GrypeMatch    `json:"matches"`
}

type GrypeMatch struct {
	Artifact               GrypeArtifact               `json:"artifact"`
	Vulnerability          GrypeVulnerability          `json:"vulnerability"`
	RelatedVulnerabilities []GrypeRelatedVulnerability `json:"relatedVulnerabilities"`
}

// GrypeRelatedVulnerability is another id for the same vulnerability, such as
// the CVE behind a GHSA.
type GrypeRelatedVulnerability struct {
	ID string `json:"id"`
}

// IDs returns the vulnerability id followed by related ids.
func (m GrypeMatch) IDs() []string {
	ids := []string{m.Vulnerability.ID}
	for _, related := range m.RelatedVulnerabilities {
		if related.ID != "" && !containsFold(ids, related.ID) {
			ids = append(ids, related.ID)
		}
	}
	return ids
}

type GrypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	PURL    string `json:"purl"`
}

type GrypeVulnerability struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	DataSource string `json:"dataSource"`
}

func (g *GrypeReportMin) SelectBySeverity(severity string) []GrypeMatch {
	matches := []GrypeMatch{}
	for _, match := range g.Matches {
		if strings.ToLower(match.Vulnerability.Severity) == severity {
			matches = append(matches, match)
		}
	}

	return matches
}

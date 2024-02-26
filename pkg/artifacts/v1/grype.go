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
	Artifact      GrypeArtifact      `json:"artifact"`
	Vulnerability GrypeVulnerability `json:"vulnerability"`
}

type GrypeDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type GrypeArtifact struct {
	Name    string `json:"name"`
	Version string `json:"version"`
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

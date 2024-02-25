package artifacts

// GrypeReportMin is a minimum representation of an Anchore Grype scan report
//
// It contains only the necessary fields for validation and listing
type GrypeReportMin struct {
	Descriptor struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"descriptor"`
	Matches []struct {
		Artifact struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"artifact"`
		Vulnerability struct {
			ID         string `json:"id"`
			Severity   string `json:"severity"`
			DataSource string `json:"dataSource"`
		} `json:"vulnerability"`
	} `json:"matches"`
}

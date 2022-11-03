package semgrep

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/fields"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"io"
	"strings"
)

type Artifact struct {
	Info       fields.Finding  `json:"info"`
	Warning    fields.Finding  `json:"warning"`
	Error      fields.Finding  `json:"error"`
	ScanReport *artifact.Asset `json:"-"`
}

// NewArtifact a zeroed artifact with proper labels
func NewArtifact() *Artifact {
	return &Artifact{
		Info:       fields.Finding{Severity: "info", Allowed: -1, Found: 0},
		Warning:    fields.Finding{Severity: "warning", Allowed: -1, Found: 0},
		Error:      fields.Finding{Severity: "error", Allowed: -1, Found: 0},
		ScanReport: new(artifact.Asset),
	}
}

// WithConfig will default to allow all findings if config is nil
func (a Artifact) WithConfig(config *Config) *Artifact {
	if config == nil {
		return a.WithConfig(NewConfig(-1))
	}
	a.Info.Severity = "info"
	a.Warning.Severity = "warning"
	a.Error.Severity = "error"

	a.Info.Allowed = config.Info
	a.Warning.Allowed = config.Warning
	a.Error.Allowed = config.Error

	return &a
}

// WithScanReport returns an Artifact with findings from a scan report
func (a Artifact) WithScanReport(r io.Reader, reportName string) (*Artifact, error) {
	// Create a new asset from the scan report
	asset, err := artifact.NewAsset(reportName, r)
	if err != nil {
		return nil, err
	}
	a.ScanReport = asset

	// Decode the report from asset content
	report := new(entity.SemgrepScanReport)

	if err := json.NewDecoder(bytes.NewBuffer(asset.Content)).Decode(report); err != nil {
		return nil, err
	}

	// Parse and update the artifact with scan report findings
	for _, result := range report.Results {
		switch result.Extra.Severity {
		case "INFO":
			a.Info.Found = a.Info.Found + 1
		case "WARNING":
			a.Warning.Found = a.Warning.Found + 1
		case "ERROR":
			a.Error.Found = a.Error.Found + 1
		}
	}
	return &a, nil
}

func (a Artifact) Validate() error {
	return fields.ValidateFindings([]fields.Finding{a.Error, a.Warning, a.Info})
}

// String human-readable formatted table
func (a Artifact) String() string {
	var out strings.Builder
	out.WriteString("Semgrep Static Code Analysis Report\n")

	if a.ScanReport != nil {
		out.WriteString(fmt.Sprintf("Report: %s\n", a.ScanReport.Label))
	}

	out.WriteString(fmt.Sprintf("%-10s | %-7s | %-7s | %-5s\n", "Severity", "Found", "Allowed", "Pass"))
	out.WriteString(strings.Repeat("-", 38) + "\n")
	out.WriteString(a.Error.String())
	out.WriteString(a.Warning.String())
	out.WriteString(a.Info.String())
	out.WriteString(strings.Repeat("-", 38) + "\n")
	// Print total as a finding
	totalFound := a.Error.Found + a.Warning.Found + a.Info.Found
	totalAllowed := 0
	// Used as quick validation to check if ALL severities pass threshold
	allPassed := "True"
	for _, finding := range []fields.Finding{a.Error, a.Warning, a.Info} {
		if finding.Test() != nil {
			allPassed = "False"
		}
		if finding.Allowed > 0 {
			totalAllowed = totalAllowed + finding.Allowed
		}
	}
	totalString := fields.Finding{Severity: "Total", Found: totalFound, Allowed: totalAllowed}.String()
	// True / False is calculated by Found findings compared to Allowed findings
	// This will replace that substring with 'if all passed' calculation
	if strings.Contains(totalString, "True") {
		totalString = strings.Replace(totalString, "True", allPassed, 1)
	} else {
		totalString = strings.Replace(totalString, "False", allPassed, 1)
	}

	out.WriteString(totalString)
	return out.String()
}

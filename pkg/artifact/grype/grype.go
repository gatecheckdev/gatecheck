package grype

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
	Critical   fields.Finding `json:"critical"`
	High       fields.Finding `json:"high"`
	Medium     fields.Finding `json:"medium"`
	Low        fields.Finding `json:"low"`
	Negligible fields.Finding `json:"negligible"`
	Unknown    fields.Finding `json:"unknown"`
	Asset      Asset
	ScanReport *artifact.Asset
}

func NewArtifact() *Artifact {
	return &Artifact{
		Critical:   fields.Finding{Severity: "Critical"},
		High:       fields.Finding{Severity: "High"},
		Medium:     fields.Finding{Severity: "Medium"},
		Low:        fields.Finding{Severity: "Low"},
		Negligible: fields.Finding{Severity: "Negligible"},
		Unknown:    fields.Finding{Severity: "Unknown"},
	}
}

// WithConfig sets the allowed values from config object
func (a Artifact) WithConfig(config *Config) *Artifact {
	a.Critical.Severity = "Critical"
	a.High.Severity = "High"
	a.Medium.Severity = "Medium"
	a.Low.Severity = "Low"
	a.Negligible.Severity = "Negligible"
	a.Unknown.Severity = "Unknown"

	a.Critical.Allowed = config.Critical
	a.High.Allowed = config.High
	a.Medium.Allowed = config.Medium
	a.Low.Allowed = config.Low
	a.Negligible.Allowed = config.Negligible
	a.Unknown.Allowed = config.Unknown

	return &a
}

// WithScanReport returns an Artifact with findings from a scan report. Builder function
func (a Artifact) WithScanReport(r io.Reader, reportName string) (*Artifact, error) {
	asset, err := artifact.NewAsset(reportName, r)
	if err != nil {
		return nil, err
	}
	a.ScanReport = asset

	// Decode the report from asset content
	report := new(entity.GrypeScanReport)

	if err := json.NewDecoder(bytes.NewBuffer(asset.Content)).Decode(report); err != nil {
		return nil, err
	}

	// Create a map of possible vulnerabilities in scan report
	vulnerabilities := map[string]int{
		"Critical":   0,
		"High":       0,
		"Medium":     0,
		"Low":        0,
		"Unknown":    0,
		"Negligible": 0,
	}

	// Loop through each match in artifact report
	for _, match := range report.Matches {
		vulnerabilities[match.Vulnerability.Severity] += 1
	}

	a.Critical.Found = vulnerabilities["Critical"]
	a.High.Found = vulnerabilities["High"]
	a.Medium.Found = vulnerabilities["Medium"]
	a.Low.Found = vulnerabilities["Low"]
	a.Unknown.Found = vulnerabilities["Unknown"]
	a.Negligible.Found = vulnerabilities["Negligible"]

	return &a, nil
}

// Deprecated: WithAsset returns an Artifact with the set found vulnerabilities. Use WithScanReport which uses io.Reader
func (a Artifact) WithAsset(asset *Asset) *Artifact {
	vulnerabilities := map[string]int{
		"Critical":   0,
		"High":       0,
		"Medium":     0,
		"Low":        0,
		"Unknown":    0,
		"Negligible": 0,
	}

	// Loop through each match in artifact report
	for _, match := range asset.scan.Matches {
		vulnerabilities[match.Vulnerability.Severity] += 1
	}

	a.Critical.Found = vulnerabilities["Critical"]
	a.High.Found = vulnerabilities["High"]
	a.Medium.Found = vulnerabilities["Medium"]
	a.Low.Found = vulnerabilities["Low"]
	a.Unknown.Found = vulnerabilities["Unknown"]
	a.Negligible.Found = vulnerabilities["Negligible"]

	a.Asset = *asset
	return &a
}

// String human-readable formatted table
func (a Artifact) String() string {
	var out strings.Builder
	out.WriteString("Grype Image Scan Report\n")
	out.WriteString(fmt.Sprintf("Scan Asset: %s\n", a.Asset.Label))
	out.WriteString(fmt.Sprintf("%-10s | %-7s | %-7s | %-5s\n", "Severity", "Found", "Allowed", "Pass"))
	out.WriteString(strings.Repeat("-", 38) + "\n")
	out.WriteString(a.Critical.String())
	out.WriteString(a.High.String())
	out.WriteString(a.Medium.String())
	out.WriteString(a.Low.String())
	out.WriteString(a.Negligible.String())
	out.WriteString(a.Unknown.String())

	return out.String()
}

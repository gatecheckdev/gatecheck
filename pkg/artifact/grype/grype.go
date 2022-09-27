package grype

import (
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/fields"
	"strings"
)

type Artifact struct {
	Critical   fields.CVE `json:"critical"`
	High       fields.CVE `json:"high"`
	Medium     fields.CVE `json:"medium"`
	Low        fields.CVE `json:"low"`
	Negligible fields.CVE `json:"negligible"`
	Unknown    fields.CVE `json:"unknown"`
	Asset      Asset
}

func NewArtifact() *Artifact {
	return &Artifact{
		Critical:   fields.CVE{Severity: "Critical"},
		High:       fields.CVE{Severity: "High"},
		Medium:     fields.CVE{Severity: "Medium"},
		Low:        fields.CVE{Severity: "Low"},
		Negligible: fields.CVE{Severity: "Negligible"},
		Unknown:    fields.CVE{Severity: "Unknown"},
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

// WithAsset returns an Artifact with the set found vulnerabilities
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

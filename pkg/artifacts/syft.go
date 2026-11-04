package artifacts

import (
	"encoding/json"
	"strings"
)

// SyftReportMin is the package list of a Syft JSON document.
type SyftReportMin struct {
	Artifacts []SyftArtifact `json:"artifacts"`
}

// SyftArtifact is one package Syft found.
type SyftArtifact struct {
	Name     string            `json:"name"`
	Version  string            `json:"version"`
	Type     string            `json:"type"`
	PURL     string            `json:"purl"`
	Licenses []json.RawMessage `json:"licenses"`
}

// LicenseNames returns each declared license. Newer Syft writes objects with
// spdxExpression and value. Older Syft writes plain strings.
func (a SyftArtifact) LicenseNames() []string {
	var out []string
	for _, raw := range a.Licenses {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			out = appendLicense(out, s)
			continue
		}
		var obj struct {
			Value          string `json:"value"`
			SPDXExpression string `json:"spdxExpression"`
		}
		if err := json.Unmarshal(raw, &obj); err != nil {
			continue
		}
		if obj.SPDXExpression != "" {
			out = appendLicense(out, obj.SPDXExpression)
		} else {
			out = appendLicense(out, obj.Value)
		}
	}
	return out
}

// CyclonedxLicenseChoice is one entry of a CycloneDX licenses array.
type CyclonedxLicenseChoice struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

// LicenseNames returns the SPDX id, name, or expression of each entry.
func (c CyclonedxComponent) LicenseNames() []string {
	var out []string
	for _, choice := range c.Licenses {
		switch {
		case choice.Expression != "":
			out = appendLicense(out, choice.Expression)
		case choice.License != nil && choice.License.ID != "":
			out = appendLicense(out, choice.License.ID)
		case choice.License != nil:
			out = appendLicense(out, choice.License.Name)
		}
	}
	return out
}

func appendLicense(out []string, license string) []string {
	license = strings.TrimSpace(license)
	if license == "" {
		return out
	}
	for _, got := range out {
		if got == license {
			return out
		}
	}
	return append(out, license)
}

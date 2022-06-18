package grype

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/fields"
	"io"
	"strings"
)

type Artifact interface {
	WithConfig(config Config) *Artifact
}

type standardArtifact struct {
	Critical   fields.CVE `json:"critical"`
	High       fields.CVE `json:"high"`
	Medium     fields.CVE `json:"medium"`
	Low        fields.CVE `json:"low"`
	Negligible fields.CVE `json:"negligible"`
	Unknown    fields.CVE `json:"unknown"`
	asset      *Asset
}

func NewArtifact() *standardArtifact {
	return &standardArtifact{
		Critical:   fields.CVE{Severity: "Critical"},
		High:       fields.CVE{Severity: "High"},
		Medium:     fields.CVE{Severity: "Medium"},
		Low:        fields.CVE{Severity: "Low"},
		Negligible: fields.CVE{Severity: "Negligible"},
		Unknown:    fields.CVE{Severity: "Unknown"},
	}
}

// WithConfig sets the allowed values from config object
func (a standardArtifact) WithConfig(config *Config) *standardArtifact {

	a.Critical.Allowed = config.Critical
	a.High.Allowed = config.High
	a.Medium.Allowed = config.Medium
	a.Low.Allowed = config.Low
	a.Negligible.Allowed = config.Negligible
	a.Unknown.Allowed = config.Unknown

	return &a
}

// WithAsset returns an Artifact with the set found vulnerabilities
func (a standardArtifact) WithAsset(asset *Asset) *standardArtifact {
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

	a.asset = asset
	return &a
}

// String human-readable formatted table
func (a standardArtifact) String() string {
	var out strings.Builder
	out.WriteString("standardGrype Image Scan Report\n")
	if a.asset != nil {
		out.WriteString(fmt.Sprintf("Scan Asset: %s\n", a.asset.Label))
	}
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

type artifactData struct {
	Critical   fields.CVE `json:"critical"`
	High       fields.CVE `json:"high"`
	Medium     fields.CVE `json:"medium"`
	Low        fields.CVE `json:"low"`
	Negligible fields.CVE `json:"negligible"`
	Unknown    fields.CVE `json:"unknown"`
	Asset      []byte
}

type ArtifactWriter struct {
	writer io.Writer
}

func (a *ArtifactWriter) Write(p []byte) (n int, err error) {
	return a.writer.Write(p)
}

func (a *ArtifactWriter) WriteArtifact(artifact *standardArtifact) error {
	buf := new(bytes.Buffer)
	_ = NewAssetWriter(buf).WriteAsset(artifact.asset)
	data := artifactData{
		Critical:   artifact.Critical,
		High:       artifact.High,
		Medium:     artifact.Medium,
		Low:        artifact.Low,
		Negligible: artifact.Negligible,
		Unknown:    artifact.Unknown,
		Asset:      buf.Bytes(),
	}
	return json.NewEncoder(a).Encode(data)
}

func NewArtifactWriter(w io.Writer) *ArtifactWriter {
	return &ArtifactWriter{writer: w}
}

type ArtifactReader struct {
	reader io.Reader
}

func (a *ArtifactReader) Read(p []byte) (n int, err error) {
	return a.reader.Read(p)
}

func (a *ArtifactReader) ReadArtifact() (*standardArtifact, error) {
	data := artifactData{}

	_ = json.NewDecoder(a).Decode(&data)

	asset, err := NewAssetReader(bytes.NewBuffer(data.Asset)).ReadAsset()

	return &standardArtifact{
		Critical:   data.Critical,
		High:       data.High,
		Medium:     data.Medium,
		Low:        data.Low,
		Negligible: data.Negligible,
		Unknown:    data.Unknown,
		asset:      asset,
	}, err
}

func NewArtifactReader(r io.Reader) *ArtifactReader {
	return &ArtifactReader{reader: r}
}

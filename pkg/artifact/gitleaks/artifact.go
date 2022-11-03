package gitleaks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"io"
	"strings"
)

type Artifact struct {
	SecretsFound   int             `json:"secretsFound"`
	SecretsAllowed bool            `json:"secretsAllowed"`
	ScanReport     *artifact.Asset `json:"-"`
}

func NewArtifact() *Artifact {
	return &Artifact{
		SecretsFound:   0,
		SecretsAllowed: false,
		ScanReport:     new(artifact.Asset),
	}
}

// WithScanReport returns an Artifact with a Gitleaks Secrets Report
func (a Artifact) WithScanReport(r io.Reader, reportName string) (*Artifact, error) {
	// Create a new asset from the scan report
	asset, err := artifact.NewAsset(reportName, r)
	if err != nil {
		return nil, err
	}
	a.ScanReport = asset

	// Decode
	report := new(entity.GitLeaksScanReport)

	if err := json.NewDecoder(bytes.NewBuffer(asset.Content)).Decode(report); err != nil {
		return nil, err
	}

	// Set the Secrets Found value
	a.SecretsFound = len(*report)
	return &a, nil
}

// WithConfig sets the secrets allowed based on a config file, if nil it will default to false
func (a Artifact) WithConfig(config *Config) *Artifact {
	if config == nil {
		a.SecretsAllowed = false
		return &a
	}
	a.SecretsAllowed = config.SecretsAllowed
	return &a
}

func (a Artifact) Validate() error {
	validationError := errors.New("gitleaks secrets validation failed")

	if a.SecretsAllowed == true {
		return nil
	}
	if a.SecretsFound != 0 {
		return fmt.Errorf("%w: %d Secrets Found", validationError, a.SecretsFound)
	}

	return nil
}

func (a Artifact) String() string {
	var out strings.Builder
	out.WriteString("Gitleaks Secrets Detection\n")

	if a.ScanReport != nil {
		out.WriteString(fmt.Sprintf("Report:          %s\n", a.ScanReport.Label))
	}

	boolString := map[bool]string{true: "True", false: "False"}

	out.WriteString(fmt.Sprintf("Secrets Found:   %d\nSecrets Allowed: %s\n",
		a.SecretsFound, boolString[a.SecretsAllowed]))

	return out.String()

}

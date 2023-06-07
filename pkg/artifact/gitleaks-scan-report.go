package artifact

import (
	"errors"
	"fmt"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
	"github.com/zricethezav/gitleaks/v8/report"
)

type GitleaksFinding report.Finding

type GitleaksScanReport []GitleaksFinding

var GitleaksValidationFailed = errors.New("gitleaks validation failed")

func (r GitleaksScanReport) String() string {
	table := new(gcStrings.Table).WithHeader("Rule", "File", "Secret", "Commit")
	for _, finding := range r {
		secret := gcStrings.ClipLeft(finding.Secret, 50)
		table = table.WithRow(finding.RuleID, finding.File, secret, finding.Commit)
	}
	return table.String()
}

type GitleaksConfig struct {
	SecretsAllowed bool `yaml:"SecretsAllowed" json:"secretsAllowed"`
}

func ValidateGitleaks(config GitleaksConfig, scanReport GitleaksScanReport) error {
	if config.SecretsAllowed {
		return nil
	}
	if len(scanReport) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %d secrets detected", GitleaksValidationFailed, len(scanReport))
}

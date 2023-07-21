package kev

import (
	"fmt"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

type VulnerabilityMatcher interface {
	MatchedVulnerabilities(r *grype.ScanReport) []models.Match
}
type Validator struct {
	service VulnerabilityMatcher
}

func NewValidator(service VulnerabilityMatcher) *Validator {
	return &Validator{service: service}
}

func (v *Validator) Validate(report *grype.ScanReport) error {
	denied := v.service.MatchedVulnerabilities(report)
	var err error

	if len(denied) > 0 {
		word := "Vulnerabilities"
		if len(denied) == 1 {
			word = "Vulnerability"
		}
		err = fmt.Errorf("%w: %d %s matched to KEV Catalog", gcv.ErrValidation, len(denied), word)
	}

	log.Infof("KEV Validation: %d matched vulnerabilities", len(denied))

	return err
}

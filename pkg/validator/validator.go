package validator

import (
	"errors"
	"fmt"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/fields"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"github.com/gatecheckdev/gatecheck/pkg/report"
	"strings"
)

var ValidationError = errors.New("report failed validation")
var GrypeValidationError = errors.New("grype artifact failed validation")

type StdValidator struct {
	r report.Report
}

func NewStdValidator(r report.Report) *StdValidator {
	return &StdValidator{r: r}
}

func (v StdValidator) Validate() error {
	err := ValidateGrype(v.r.Artifacts.Grype)
	if err != nil {
		return fmt.Errorf("%w : %s", ValidationError, err)
	}
	return nil
}

func ValidateGrype(a grype.Artifact) error {
	var sb strings.Builder
	var validationError error = nil

	testables := []fields.CVE{a.Critical, a.High, a.Medium, a.Low, a.Unknown, a.Negligible}
	for _, t := range testables {
		if err := t.Test(); err != nil {
			validationError = GrypeValidationError
			sb.WriteString(err.Error())
		}
	}
	if validationError != nil {
		return fmt.Errorf("%w \n%s", validationError, sb.String())
	}
	return nil
}

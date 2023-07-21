package epss

import (
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"golang.org/x/exp/slices"
)

type Validator struct {
	service *Service
}

func NewValidator(service *Service) *Validator {
	return &Validator{service: service}
}

func (v *Validator) Validate(matches []models.Match, configReader io.Reader) error {
	configBytes, err := io.ReadAll(configReader)

	config, err := gcv.ConfigByField[grype.Config](bytes.NewReader(configBytes), grype.ConfigFieldName)
	if err != nil {
		return err
	}
	// EPSSDenyThreshold Default value is 0 so replace that value with 1 since 1 encompasses all scores
	// This is to still allow for the possibility of denying scores over a threshold
	if config.EPSSDenyThreshold == 0 {
		config.EPSSDenyThreshold = 1
	}

	if len(matches) == 0 {
		return nil
	}

	cves, err := v.service.GetCVEs(matches)
	if err != nil {
		return err
	}

	allowedIDs := []string{}
	deniedIDs := []string{}

	for _, cve := range cves {
		if cve.Probability == 0 {
			continue
		}
		if cve.Probability <= config.EPSSAllowThreshold {
			allowedIDs = append(allowedIDs, fmt.Sprintf("%s (%s)", cve.ID, strconv.FormatFloat(cve.Probability, 'f', -1, 64)))
			continue
		}
		// check config allow list
		inAllowList := slices.ContainsFunc(config.AllowList, func(allowedCVE grype.ListItem) bool { return allowedCVE.Id == cve.ID })
		if inAllowList {
			continue
		}
		if cve.Probability >= config.EPSSDenyThreshold {
			deniedIDs = append(deniedIDs, fmt.Sprintf("%s (%s)", cve.ID, strconv.FormatFloat(cve.Probability, 'f', -1, 64)))
		}
	}

	allowedStr := ""
	if len(allowedIDs) != 0 {
		allowedStr = strings.Join(allowedIDs, ", ")
	}
	log.Infof("EPSS Validation: allowed vulnerabilities[%d]: %s", len(allowedIDs), allowedStr)

	deniedStr := ""
	if len(deniedIDs) != 0 {
		deniedStr = strings.Join(deniedIDs, ", ")
	}
	log.Infof("EPSS Validation: denied vulnerabilities[%d]: %s", len(deniedIDs), deniedStr)

	if len(deniedIDs) > 0 {
		return fmt.Errorf("%w: %d vulnerabilities have EPSS scores over deny threshold %s",
			gcv.ErrValidation, len(deniedIDs), strconv.FormatFloat(config.EPSSDenyThreshold, 'f', -1, 64))
	}
	return nil
}

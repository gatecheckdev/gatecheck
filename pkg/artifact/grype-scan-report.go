package artifact

import (
	"errors"
	"fmt"
	"strings"

	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/internal/log"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

type GrypeScanReport models.Document

var GrypeValidationFailed = errors.New("grype validation failed")

func (r GrypeScanReport) String() string {
	table := new(gcStrings.Table).WithHeader("Severity", "Package", "Version", "Link")

	for _, item := range r.Matches {
		table = table.WithRow(item.Vulnerability.Severity,
			item.Artifact.Name, item.Artifact.Version, item.Vulnerability.DataSource)
	}

	return table.String()
}

type GrypeConfig struct {
	AllowList  []GrypeListItem `yaml:"allowList,omitempty" json:"allowList,omitempty"`
	DenyList   []GrypeListItem `yaml:"denyList,omitempty" json:"denyList,omitempty"`
	Critical   int             `yaml:"critical"   json:"critical"`
	High       int             `yaml:"high"       json:"high"`
	Medium     int             `yaml:"medium"     json:"medium"`
	Low        int             `yaml:"low"        json:"low"`
	Negligible int             `yaml:"negligible" json:"negligible"`
	Unknown    int             `yaml:"unknown"    json:"unknown"`
}

type GrypeListItem struct {
	Id     string `yaml:"id"     json:"id"`
	Reason string `yaml:"reason" json:"reason"`
}

func ValidateGrype(config GrypeConfig, scanReport GrypeScanReport) error {
	found := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
	allowed := map[string]int{
		"Critical": config.Critical, "High": config.High, "Medium": config.Medium,
		"Low": config.Low, "Negligible": config.Negligible, "Unknown": config.Unknown,
	}
	foundDenied := make([]models.Match, 0)

LOOPMATCH:
	for matchIndex, match := range scanReport.Matches {

		for _, allowed := range config.AllowList {
			if strings.Compare(match.Vulnerability.ID, allowed.Id) == 0 {

				log.Infof("%s Allowed. Reason: %s", match.Vulnerability.ID, allowed.Reason)
				continue LOOPMATCH
			}
		}

		for _, denied := range config.DenyList {
			if match.Vulnerability.ID == denied.Id {
				log.Infof("%s Denied. Reason: %s", match.Vulnerability.ID, denied.Reason)
				foundDenied = append(foundDenied, scanReport.Matches[matchIndex])
			}
		}

		found[match.Vulnerability.Severity] += 1
	}

	var errStrings []string

	for severity := range found {
		// A -1 in config means all allowed
		if allowed[severity] == -1 {
			continue
		}
		if found[severity] > allowed[severity] {
			s := fmt.Sprintf("%s (%d found > %d allowed)", severity, found[severity], allowed[severity])
			errStrings = append(errStrings, s)
		}
	}

	if len(foundDenied) != 0 {
		deniedReport := &GrypeScanReport{Matches: foundDenied}
		errStrings = append(errStrings, fmt.Sprintf("Denied Vulnerabilities\n%s", deniedReport))
	}

	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", GrypeValidationFailed, strings.Join(errStrings, ", "))
}

package artifact

import (
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/presenter/models"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
	"strings"
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
	Critical   int `yaml:"critical" json:"critical"`
	High       int `yaml:"high" json:"high"`
	Medium     int `yaml:"medium" json:"medium"`
	Low        int `yaml:"low" json:"low"`
	Negligible int `yaml:"negligible" json:"negligible"`
	Unknown    int `yaml:"unknown" json:"unknown"`
}

func ValidateGrype(config GrypeConfig, scanReport GrypeScanReport) error {
	found := map[string]int{"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Negligible": 0, "Unknown": 0}
	allowed := map[string]int{"Critical": config.Critical, "High": config.High, "Medium": config.Medium,
		"Low": config.Low, "Negligible": config.Negligible, "Unknown": config.Unknown}
	for _, match := range scanReport.Matches {
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
	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", GrypeValidationFailed, strings.Join(errStrings, ", "))
}

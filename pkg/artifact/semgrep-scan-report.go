package artifact

import (
	"errors"
	"fmt"
	semgrep "github.com/BacchusJackson/go-semgrep"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
	"strings"
)

// SemgrepScanReport is a data model for a Semgrep Output scan produced by `semgrep scan --json`
type SemgrepScanReport semgrep.SemgrepOutputV1Jsonschema

var SemgrepFailedValidation = errors.New("semgrep failed validation")

func (r SemgrepScanReport) String() string {
	table := new(gcStrings.Table).WithHeader("Path", "Line", "Level", "link", "CWE Message")

	for _, item := range r.Results {
		line := fmt.Sprintf("%d", item.Start.Line)
		// Attempt type assertion on metadata since it's an interface{}
		metadata, ok := item.Extra.Metadata.(map[string]interface{})
		if ok != true {
			table = table.WithRow(item.Path, line, item.Extra.Severity, "", "")
			continue
		}

		link := fmt.Sprintf("%v", metadata["shortlink"])
		cwe := fmt.Sprintf("%v", metadata["cwe"])
		table = table.WithRow(item.Path, line, item.Extra.Severity, link, cwe)
	}

	return table.String()
}

type SemgrepConfig struct {
	Info    int `yaml:"info" json:"info"`
	Warning int `yaml:"warning" json:"warning"`
	Error   int `yaml:"error" json:"error"`
}

func ValidateSemgrep(config SemgrepConfig, scanReport SemgrepScanReport) error {
	allowed := map[string]int{"INFO": config.Info, "WARNING": config.Warning, "ERROR": config.Error}
	found := map[string]int{"INFO": 0, "WARNING": 0, "ERROR": 0}

	for _, result := range scanReport.Results {
		found[result.Extra.Severity] += 1
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

	return fmt.Errorf("%w: %s", SemgrepFailedValidation, strings.Join(errStrings, ", "))

}

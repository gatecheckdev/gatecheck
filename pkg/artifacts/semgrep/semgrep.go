package semgrep

import (
	"errors"
	"fmt"
	"sort"

	semgrep "github.com/BacchusJackson/go-semgrep"
	"github.com/gatecheckdev/gatecheck/internal/log"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
)

const ReportType = "Semgrep Scan Report"
const ConfigType = "Semgrep Config"
const ConfigFieldName = "semgrep"

// ScanReport is a data model for a Semgrep Output scan produced by `semgrep scan --json`
type ScanReport semgrep.SemgrepOutputV1Jsonschema

func (r ScanReport) String() string {
	table := format.NewTable()
	table.AppendRow("Severity", "Path", "Line", "CWE Message", "Link")

	for _, item := range r.Results {
		line := fmt.Sprintf("%d", item.Start.Line)
		path := format.Summarize(item.Path, 30, format.ClipMiddle)
		// Attempt type assertion on metadata since it's an interface{}
		metadata, ok := item.Extra.Metadata.(map[string]interface{})
		if ok != true {
			table.AppendRow(item.Extra.Severity, path, line, "", "")
			continue
		}

		link := fmt.Sprintf("%v", metadata["shortlink"])
		cwe := fmt.Sprintf("%v", metadata["cwe"])
		table.AppendRow(item.Extra.Severity, path, line, cwe, link)
	}

	table.SetSort(0, format.NewCatagoricLess([]string{"ERROR", "WARNING", "INFO"}))

	sort.Sort(table)

	return format.NewTableWriter(table).String()
}

func NewReportDecoder() *gce.JSONWriterDecoder[ScanReport] {
	return gce.NewJSONWriterDecoder[ScanReport](ReportType, checkReport)
}

func NewValidator() gcv.Validator[semgrep.CliMatch, Config] {
	return gcv.NewValidator[semgrep.CliMatch, Config]().WithValidationRules(ThresholdRule)
}

func checkReport(report *ScanReport) error {
	if report == nil {
		return gce.ErrFailedCheck
	}
	if report.Results == nil {
		return fmt.Errorf("%w: Required field 'Results' is nil", gce.ErrFailedCheck)
	}
	if report.Errors == nil {
		return fmt.Errorf("%w: Required field 'Errors' is nil", gce.ErrFailedCheck)
	}
	if report.Paths.Scanned == nil {
		return fmt.Errorf("%w: Required field 'Scanned' is nil", gce.ErrFailedCheck)
	}
	return nil
}

type Config struct {
	Error   int `yaml:"error" json:"error"`
	Warning int `yaml:"warning" json:"warning"`
	Info    int `yaml:"info" json:"info"`
}

func ThresholdRule(matches []semgrep.CliMatch, config Config) error {
	orderedKeys := []string{"ERROR", "WARNING", "INFO"}

	allowed := map[string]int{
		orderedKeys[0]: config.Error,
		orderedKeys[1]: config.Warning,
		orderedKeys[2]: config.Info,
	}

	log.Infof("Semgrep Threshold Validation Rules: %s", format.PrettyPrintMapOrdered(allowed, orderedKeys))

	found := map[string]int{
		orderedKeys[0]: 0,
		orderedKeys[1]: 0,
		orderedKeys[2]: 0,
	}

	for _, match := range matches {
		found[match.Extra.Severity] += 1
	}

	var errs error
	for severity, allowThreshold := range allowed {
		if allowThreshold == -1 {
			continue
		}
		if found[severity] > allowThreshold {
			rule := fmt.Sprintf("%s allowed %d found", severity, allowThreshold)
			errs = errors.Join(errs, gcv.NewFailedRuleError(rule, fmt.Sprint(found[severity])))
		}
	}

	log.Infof("Semgrep Threshold Validation Found: %s", format.PrettyPrintMapOrdered(found, orderedKeys))
	return errs
}

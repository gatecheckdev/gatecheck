package semgrep

import (
	"fmt"
	"sort"
	"strings"

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

func NewValidator() *gcv.Validator[ScanReport, Config] {
	return gcv.NewValidator[ScanReport, Config](ConfigFieldName, NewReportDecoder(), validateFunc)
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
	Info     int  `yaml:"info" json:"info"`
	Warning  int  `yaml:"warning" json:"warning"`
	Error    int  `yaml:"error" json:"error"`
}

func validateFunc(scanReport ScanReport, config Config) error {
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

	log.Infof("Semgrep Findings: %v", format.PrettyPrintMap(found))
	if len(errStrings) == 0 {
		return nil
	}

	return fmt.Errorf("%w: %s", gcv.ErrValidation, strings.Join(errStrings, ", "))

}

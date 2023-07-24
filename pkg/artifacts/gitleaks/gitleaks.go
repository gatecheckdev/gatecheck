package gitleaks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/internal/log"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"github.com/zricethezav/gitleaks/v8/report"
)

const ReportType = "Gitleaks Scan Report"
const ConfigType = "Gitleaks Config"
const ConfigFieldName = "gitleaks"

type Finding report.Finding

type ScanReport []Finding

func (r ScanReport) String() string {
	table := format.NewTable()
	table.AppendRow("Rule", "File", "secret", "Commit")
	for _, finding := range r {
		secret := strings.ReplaceAll(finding.Secret, "\n", "\\n")
		secret = strings.ReplaceAll(secret, "\r", "\\r")
		secret = format.Summarize(secret, 50, format.ClipLeft)
		table.AppendRow(finding.RuleID, finding.File, secret, finding.Commit)
	}
	table.SetSort(1, format.AlphabeticLess)
	sort.Sort(table)
	return format.NewTableWriter(table).String()
}

type Config struct {
	SecretsAllowed bool `yaml:"secretsAllowed" json:"secretsAllowed"`
}

func NewValidator() gcv.Validator[Finding, Config] {
	return gcv.NewValidator[Finding, Config]().WithValidationRules(NoSecretsRule)
}

func NewReportDecoder() *ReportDecoder {
	return new(ReportDecoder)
}

// Gitleaks reports are just an array of findings. No findings is '[]' literally
type ReportDecoder struct {
	bytes.Buffer
}

func (d *ReportDecoder) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}
	return d.Decode()
}

func (d *ReportDecoder) Decode() (any, error) {
	// Edge Case: report with no findings
	if d.String() == "[]" {
		return &ScanReport{}, nil
	}

	obj := ScanReport{}
	err := json.NewDecoder(d).Decode(&obj)

	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrEncoding, err)
	}

	if obj[0].RuleID == "" {
		return nil, fmt.Errorf("%w: rule id is missing", gce.ErrFailedCheck)
	}

	return &obj, nil
}

func (d *ReportDecoder) FileType() string {
	return ReportType
}

func NoSecretsRule(findings []Finding, config Config) error {
	if len(findings) == 0 {
		return nil
	}
	msg := fmt.Sprintf("Gitleaks: %d secrets detected", len(findings))
	log.Info(msg)
	if config.SecretsAllowed {
		return nil
	}
	return gcv.NewFailedRuleError("No Secrets Allowed. Found", fmt.Sprint(len(findings)))

}

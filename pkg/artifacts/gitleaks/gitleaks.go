// Package gitleaks provides data model, decoder, and validator for Gitleaks secret detection report
package gitleaks

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/format"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"github.com/zricethezav/gitleaks/v8/report"
)

// ReportType in plain text
const ReportType = "Gitleaks Scan Report"

// ConfigType in plain text
const ConfigType = "Gitleaks Config"

// ConfigFieldName field name for config map
const ConfigFieldName = "gitleaks"

// Finding data model alias
type Finding report.Finding

// ScanReport a slice of findings
type ScanReport []Finding

// String a formatted table of detected secrets
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

// Config data model
type Config struct {
	SecretsAllowed bool `json:"secretsAllowed" yaml:"secretsAllowed"`
}

// NewValidator implementation of the generic validator
func NewValidator() gcv.Validator[Finding, Config] {
	return gcv.NewValidator[Finding, Config]().WithValidationRules(NoSecretsRule)
}

// NewReportDecoder custom decoder with specific rules to handle empty findings reports
func NewReportDecoder() *ReportDecoder {
	return new(ReportDecoder)
}

// ReportDecoder reports are just an array of findings. No findings is '[]' literally
type ReportDecoder struct {
	bytes.Buffer
}

// DecodeFrom ...
func (d *ReportDecoder) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}
	return d.Decode()
}

// Decode from internal buffer
func (d *ReportDecoder) Decode() (any, error) {
	obj := ScanReport{}
	jsonDecoder := json.NewDecoder(d)
	jsonDecoder.DisallowUnknownFields()
	err := jsonDecoder.Decode(&obj)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrEncoding, err)
	}
	if len(obj) == 0 {
		slog.Debug("decoded a gitleaks report with no findings -> '[]'")
		return &obj, nil
	}

	if obj[0].RuleID == "" {
		return nil, fmt.Errorf("%w: rule id is missing", gce.ErrFailedCheck)
	}

	return &obj, nil
}

// FileType in plain text
func (d *ReportDecoder) FileType() string {
	return ReportType
}

// NoSecretsRule deny if no secrets are allowed and count of secrets > 0
func NoSecretsRule(findings []Finding, config Config) error {
	if len(findings) == 0 {
		return nil
	}
	slog.Debug("gitleaks validation", "secrets_allowed", config.SecretsAllowed, "found", len(findings))
	if config.SecretsAllowed {
		return nil
	}
	return gcv.NewFailedRuleError("No Secrets Allowed. Found", fmt.Sprint(len(findings)))
}

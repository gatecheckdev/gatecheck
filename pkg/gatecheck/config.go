package gatecheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/gatecheckdev/gatecheck/pkg/vex"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Config is used to set limits and allowances during validation
//
// The report can be encoded/decoded into json, yaml, or toml
// Metadata fields are intended for arbitrary data and shouldn't
// conflict with rule validation
type Config struct {
	Version    string               `json:"version"     toml:"version"     yaml:"version"`
	Metadata   configMetadata       `json:"metadata"    toml:"metadata"    yaml:"metadata"`
	Grype      reportWithCVEs       `json:"grype"       toml:"grype"       yaml:"grype"`
	Cyclonedx  reportWithCVEs       `json:"cyclonedx"   toml:"cyclonedx"   yaml:"cyclonedx"`
	Trivy      reportWithCVEs       `json:"trivy"       toml:"trivy"       yaml:"trivy"`
	OSVScanner reportWithCVEs       `json:"osv-scanner" toml:"osv-scanner" yaml:"osv-scanner"`
	Semgrep    configSemgrepReport  `json:"semgrep"     toml:"semgrep"     yaml:"semgrep"`
	Gitleaks   configGitleaksReport `json:"gitleaks"    toml:"gitleaks"    yaml:"gitleaks"`
	Sarif      configSarifReport    `json:"sarif"       toml:"sarif"       yaml:"sarif"`
	Coverage   configCoverageReport `json:"coverage"    toml:"coverage"    yaml:"coverage"`
	VEX        configVEX            `json:"vex"         toml:"vex"         yaml:"vex"`
	License    configLicense        `json:"license"     toml:"license"     yaml:"license"`
	Scorecard  configScorecard      `json:"scorecard"   toml:"scorecard"   yaml:"scorecard"`
	Trufflehog configTrufflehog     `json:"trufflehog"  toml:"trufflehog"  yaml:"trufflehog"`

	vexDoc *vex.Document
}

func (c *Config) String() string {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(c)
	var tree map[string]any
	_ = json.Unmarshal(buf.Bytes(), &tree)
	rows := map[string]string{}
	flattenConfig("", tree, rows)
	keys := make([]string, 0, len(rows))
	for key := range rows {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	contentBuf := new(bytes.Buffer)
	table := format.NewTable(contentBuf)
	table.Header([]string{"config key", "value"})
	for _, key := range keys {
		if err := table.Append([]string{key, rows[key]}); err != nil {
			slog.Error("append config row", "error", err)
			return contentBuf.String()
		}
	}
	if err := table.Render(); err != nil {
		slog.Error("render config table", "error", err)
	}
	return contentBuf.String()
}

func flattenConfig(prefix string, value any, out map[string]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			name := strings.ToLower(key)
			if prefix != "" {
				name = prefix + "." + name
			}
			flattenConfig(name, child, out)
		}
	default:
		out[prefix] = fmt.Sprintf("%v", v)
	}
}

type configCoverageReport struct {
	LineThreshold     float32 `json:"lineThreshold"   toml:"lineThreshold"   yaml:"lineThreshold"`
	FunctionThreshold float32 `json:"functionThreshold" toml:"functionThreshold" yaml:"functionThreshold"`
	BranchThreshold   float32 `json:"branchThreshold"  toml:"branchThreshold"  yaml:"branchThreshold"`
}

type configGitleaksReport struct {
	LimitEnabled bool `json:"limitEnabled" toml:"limitEnabled" yaml:"limitEnabled"`
}

type configSarifReport struct {
	SeverityLimit      configServerityLimit     `json:"severityLimit"      toml:"severityLimit"      yaml:"severityLimit"`
	RuleLimit          configRuleLimit          `json:"ruleLimit"          toml:"ruleLimit"          yaml:"ruleLimit"`
	RuleRiskAcceptance configRuleRiskAcceptance `json:"ruleRiskAcceptance" toml:"ruleRiskAcceptance" yaml:"ruleRiskAcceptance"`
}

type configRuleLimit struct {
	Enabled bool         `json:"enabled" toml:"enabled" yaml:"enabled"`
	Rules   []configRule `json:"rules"   toml:"rules"   yaml:"rules"`
}

type configRuleRiskAcceptance struct {
	Enabled bool         `json:"enabled" toml:"enabled" yaml:"enabled"`
	Rules   []configRule `json:"rules"   toml:"rules"   yaml:"rules"`
}

type configRule struct {
	ID       string `json:"id" toml:"id" yaml:"id"`
	Metadata struct {
		Tags []string `json:"tags" toml:"tags" yaml:"tags"`
	} `json:"metadata" toml:"metadata" yaml:"metadata"`
}

type configSemgrepReport struct {
	SeverityLimit        configSemgrepSeverityLimit        `json:"severityLimit"        toml:"severityLimit"        yaml:"severityLimit"`
	ImpactRiskAcceptance configSemgrepImpactRiskAcceptance `json:"impactRiskAcceptance" toml:"impactRiskAcceptance" yaml:"impactRiskAcceptance"`
}

type configSemgrepSeverityLimit struct {
	Error   configLimit `json:"error"   toml:"error"   yaml:"error"`
	Warning configLimit `json:"warning" toml:"warning" yaml:"warning"`
	Info    configLimit `json:"info"    toml:"info"    yaml:"info"`
}

type configSemgrepImpactRiskAcceptance struct {
	Enabled bool `json:"enabled" toml:"enabled" yaml:"enabled"`
	High    bool `json:"high"    toml:"high"    yaml:"high"`
	Medium  bool `json:"medium"  toml:"medium"  yaml:"medium"`
	Low     bool `json:"low"     toml:"low"     yaml:"low"`
}

type configMetadata struct {
	Tags []string `json:"tags" toml:"tags" yaml:"tags"`
}

type reportWithCVEs struct {
	SeverityLimit      configServerityLimit     `json:"severityLimit"      toml:"severityLimit"      yaml:"severityLimit"`
	EPSSLimit          configEPSSLimit          `json:"epssLimit"          toml:"epssLimit"          yaml:"epssLimit"`
	KEVLimitEnabled    bool                     `json:"kevLimitEnabled"    toml:"kevLimitEnabled"    yaml:"kevLimitEnabled"`
	CVELimit           configCVELimit           `json:"cveLimit"           toml:"cveLimit"           yaml:"cveLimit"`
	EPSSRiskAcceptance configEPSSRiskAcceptance `json:"epssRiskAcceptance" toml:"epssRiskAcceptance" yaml:"epssRiskAcceptance"`
	CVERiskAcceptance  configCVERiskAcceptance  `json:"cveRiskAcceptance"  toml:"cveRiskAcceptance"  yaml:"cveRiskAcceptance"`
}

type configEPSSRiskAcceptance struct {
	Enabled bool    `json:"enabled" toml:"enabled" yaml:"enabled"`
	Score   float64 `json:"score"   toml:"score"   yaml:"score"`
}
type configCVERiskAcceptance struct {
	Enabled bool        `json:"enabled" toml:"enabled" yaml:"enabled"`
	CVEs    []configCVE `json:"cves"    toml:"cves"    yaml:"cves"`
}
type configServerityLimit struct {
	Critical configLimit `json:"critical" toml:"critical" yaml:"critical"`
	High     configLimit `json:"high"     toml:"high"     yaml:"high"`
	Medium   configLimit `json:"medium"   toml:"medium"   yaml:"medium"`
	Low      configLimit `json:"low"      toml:"low"      yaml:"low"`
}

type configEPSSLimit struct {
	Enabled bool    `json:"enabled" toml:"enabled" yaml:"enabled"`
	Score   float64 `json:"score"   toml:"score"   yaml:"score"`
}

type configCVELimit struct {
	Enabled bool        `json:"enabled" toml:"enabled" yaml:"enabled"`
	CVEs    []configCVE `json:"cves"    toml:"cves"    yaml:"cves"`
}

type configCVE struct {
	ID       string `json:"id" toml:"id" yaml:"id"`
	Metadata struct {
		Tags []string `json:"tags" toml:"tags" yaml:"tags"`
	} `json:"metadata" toml:"metadata" yaml:"metadata"`
}

type configLimit struct {
	Enabled bool `json:"enabled" toml:"enabled" yaml:"enabled"`
	Limit   uint `json:"limit"   toml:"limit"   yaml:"limit"`
}

func defaultReportWithCVEs() reportWithCVEs {
	return reportWithCVEs{
		SeverityLimit: configServerityLimit{
			Critical: configLimit{Enabled: false, Limit: 0},
			High:     configLimit{Enabled: false, Limit: 0},
			Medium:   configLimit{Enabled: false, Limit: 0},
			Low:      configLimit{Enabled: false, Limit: 0},
		},
		EPSSLimit:          configEPSSLimit{Enabled: false, Score: 0},
		KEVLimitEnabled:    false,
		CVELimit:           configCVELimit{Enabled: false, CVEs: make([]configCVE, 0)},
		EPSSRiskAcceptance: configEPSSRiskAcceptance{Enabled: false, Score: 0},
		CVERiskAcceptance:  configCVERiskAcceptance{Enabled: false, CVEs: make([]configCVE, 0)},
	}
}

func NewDefaultConfig() *Config {
	return &Config{
		Version: "1",
		Metadata: configMetadata{
			Tags: []string{},
		},
		Semgrep: configSemgrepReport{
			SeverityLimit: configSemgrepSeverityLimit{
				Error: configLimit{
					Enabled: false,
					Limit:   0,
				},
				Warning: configLimit{
					Enabled: false,
					Limit:   0,
				},
				Info: configLimit{
					Enabled: false,
					Limit:   0,
				},
			},
			ImpactRiskAcceptance: configSemgrepImpactRiskAcceptance{
				Enabled: false,
				High:    false,
				Medium:  false,
				Low:     false,
			},
		},
		Grype:      defaultReportWithCVEs(),
		Cyclonedx:  defaultReportWithCVEs(),
		Trivy:      defaultReportWithCVEs(),
		OSVScanner: defaultReportWithCVEs(),
		Gitleaks: configGitleaksReport{
			LimitEnabled: false,
		},
		Sarif: configSarifReport{
			SeverityLimit: configServerityLimit{
				Critical: configLimit{
					Enabled: false,
					Limit:   0,
				},
				High: configLimit{
					Enabled: false,
					Limit:   0,
				},
				Medium: configLimit{
					Enabled: false,
					Limit:   0,
				},
				Low: configLimit{
					Enabled: false,
					Limit:   0,
				},
			},
			RuleLimit: configRuleLimit{
				Enabled: false,
				Rules:   make([]configRule, 0),
			},
			RuleRiskAcceptance: configRuleRiskAcceptance{
				Enabled: false,
				Rules:   make([]configRule, 0),
			},
		},
		Coverage: configCoverageReport{
			LineThreshold:     0,
			FunctionThreshold: 0,
			BranchThreshold:   0,
		},
		VEX:     configVEX{Files: []string{}},
		License: defaultConfigLicense(),
		Scorecard: configScorecard{
			Checks: []configScorecardCheck{},
		},
	}
}

// WriteDefaultConfig writes the default config, tagged as generated.
func WriteDefaultConfig(w io.Writer, format string) error {
	config := NewDefaultConfig()
	config.Metadata.Tags = append(config.Metadata.Tags, "auto generated from CLI")
	return EncodeConfigTo(w, config, format)
}

// ConfigFormat returns the canonical config format for a name or extension:
// "json", "yaml", or "toml". "yml" and a leading dot are accepted.
func ConfigFormat(name string) (string, error) {
	switch strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), ".")) {
	case "json":
		return "json", nil
	case "yaml", "yml":
		return "yaml", nil
	case "toml":
		return "toml", nil
	default:
		return "", fmt.Errorf("unsupported config format %q, must be json, toml, yaml, or yml", name)
	}
}

// EncodeConfigTo writes config in format (json, yaml, yml, or toml, with or
// without a leading dot). JSON and YAML are indented by two spaces.
func EncodeConfigTo(w io.Writer, config *Config, format string) error {
	canonical, err := ConfigFormat(format)
	if err != nil {
		return err
	}
	slog.Debug("encode config file", "format", canonical)
	switch canonical {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(config)
	case "yaml":
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		if err := enc.Encode(config); err != nil {
			return err
		}
		return enc.Close()
	default:
		enc := toml.NewEncoder(w)
		enc.SetIndentTables(true)
		return enc.Encode(config)
	}
}

// ConfigEncoder writes a config in the format named by a file extension.
type ConfigEncoder struct {
	writer io.Writer
	ext    string
}

// NewConfigEncoder takes ".json", ".yaml", ".yml", or ".toml". The dot is optional.
func NewConfigEncoder(w io.Writer, ext string) *ConfigEncoder {
	return &ConfigEncoder{writer: w, ext: ext}
}

func (e *ConfigEncoder) Encode(config *Config) error {
	return EncodeConfigTo(e.writer, config, e.ext)
}

// ConfigDecoder reads a config file. The extension picks the format.
type ConfigDecoder struct {
	filename string
}

func NewConfigDecoder(filename string) *ConfigDecoder {
	return &ConfigDecoder{filename: filename}
}

// ErrUnknownConfigKeys means a config file has keys gatecheck does not read.
var ErrUnknownConfigKeys = errors.New("config has unknown keys")

// Decode reads the file into config. Keys gatecheck does not know are
// skipped. When there are any, Decode fills config and then returns an error
// wrapping ErrUnknownConfigKeys, so the caller can warn and go on.
func (d *ConfigDecoder) Decode(config *Config) error {
	slog.Debug("decode config", "filename", d.filename)
	canonical, err := ConfigFormat(path.Ext(d.filename))
	if err != nil {
		return fmt.Errorf("%s: %w", d.filename, err)
	}
	content, err := os.ReadFile(d.filename)
	if err != nil {
		return err
	}
	return DecodeConfig(content, canonical, config)
}

// DecodeConfig reads content in format into config. See ConfigDecoder.Decode
// for how unknown keys are reported.
func DecodeConfig(content []byte, format string, config *Config) error {
	canonical, err := ConfigFormat(format)
	if err != nil {
		return err
	}
	var loose error
	switch canonical {
	case "json":
		loose = json.Unmarshal(content, config)
	case "yaml":
		loose = yaml.Unmarshal(content, config)
	default:
		loose = toml.Unmarshal(content, config)
	}
	if loose != nil {
		return loose
	}
	if unknown := unknownConfigKeys(content, canonical); unknown != "" {
		return fmt.Errorf("%w: %s", ErrUnknownConfigKeys, unknown)
	}
	return nil
}

// unknownConfigKeys decodes content strictly into a scratch config and returns
// the decoder's description of the unknown keys, or "".
func unknownConfigKeys(content []byte, format string) string {
	scratch := &Config{}
	var err error
	switch format {
	case "json":
		dec := json.NewDecoder(bytes.NewReader(content))
		dec.DisallowUnknownFields()
		err = dec.Decode(scratch)
	case "yaml":
		dec := yaml.NewDecoder(bytes.NewReader(content))
		dec.KnownFields(true)
		err = dec.Decode(scratch)
		if errors.Is(err, io.EOF) {
			err = nil
		}
	default:
		dec := toml.NewDecoder(bytes.NewReader(content))
		dec.DisallowUnknownFields()
		err = dec.Decode(scratch)
		var strict *toml.StrictMissingError
		if errors.As(err, &strict) {
			keys := make([]string, 0, len(strict.Errors))
			for _, e := range strict.Errors {
				keys = append(keys, strings.Join(e.Key(), "."))
			}
			return strings.Join(keys, ", ")
		}
	}
	if err == nil {
		return ""
	}
	return strings.TrimSpace(err.Error())
}

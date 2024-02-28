package gatecheck

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/gatecheckdev/gatecheck/pkg/format"
	"github.com/pelletier/go-toml/v2"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

// Config is used to set limits and allowances during validation
//
// The report can be encoded/decoded into json, yaml, or toml
// Metadata fields are intended for arbitrary data and shouldn't
// conflict with rule validation
type Config struct {
	Version  string              `json:"version" yaml:"version" toml:"version" mapstructure:"version"`
	Metadata configMetadata      `json:"metadata" yaml:"metadata" toml:"metadata"`
	Grype    reportWithCVEs      `json:"grype" yaml:"grype" toml:"grype"`
	Semgrep  configSemgrepReport `json:"semgrep" yaml:"semgrep" toml:"semgrep"`
}

func (c *Config) String() string {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(c)

	v := viper.New()
	v.SetConfigType("json")
	_ = v.ReadConfig(buf)
	table := format.NewTable()
	table.AppendRow("config key", "value")

	for _, key := range v.AllKeys() {
		table.AppendRow(key, fmt.Sprintf("%v", v.Get(key)))
	}
	fmt.Printf("%v\n", c.Grype)
	return format.NewTableWriter(table).String()
}

type configSemgrepReport struct {
	SeverityLimit        configSemgrepSeverityLimit        `json:"severityLimit" yaml:"severityLimit" toml:"severityLimit"`
	ImpactRiskAcceptance configSemgrepImpactRiskAcceptance `json:"impactRiskAcceptance" yaml:"impactRiskAcceptance" toml:"impactRiskAcceptance"`
}

type configSemgrepSeverityLimit struct {
	Enabled bool        `json:"enabled" yaml:"enabled" toml:"enabled"`
	Error   configLimit `json:"error" yaml:"error" toml:"error"`
	Warning configLimit `json:"warning" yaml:"warning" toml:"warning"`
	Info    configLimit `json:"info" yaml:"info" toml:"info"`
}

type configSemgrepImpactRiskAcceptance struct {
	Enabled bool `json:"enabled" yaml:"enabled" toml:"enabled"`
	High    bool `json:"high" yaml:"high" toml:"high"`
	Medium  bool `json:"medium" yaml:"medium" toml:"medium"`
	Low     bool `json:"low" yaml:"low" toml:"low"`
}

type configMetadata struct {
	Tags []string `json:"tags" yaml:"tags" toml:"tags"`
}

type reportWithCVEs struct {
	SeverityLimit      configServerityLimit     `json:"severityLimit" yaml:"severityLimit" toml:"severityLimit"`
	EPSSLimit          configEPSSLimit          `json:"epssLimit" yaml:"epssLimit" toml:"epssLimit"`
	KEVLimitEnabled    bool                     `json:"kevLimitEnabled" yaml:"kevLimitEnabled" toml:"kevLimitEnabled"`
	CVELimit           configCVELimit           `json:"cveLimit" yaml:"cveLimit" toml:"cveLimit"`
	EPSSRiskAcceptance configEPSSRiskAcceptance `json:"epssRiskAcceptance" yaml:"epssRiskAcceptance" toml:"epssRiskAcceptance"`
	CVERiskAcceptance  configCVERiskAcceptance  `json:"cveRiskAcceptance" yaml:"cveRiskAcceptance" toml:"cveRiskAcceptance"`
}

type configEPSSRiskAcceptance struct {
	Enabled bool    `json:"enabled" yaml:"enabled" toml:"enabled"`
	Score   float64 `json:"score" yaml:"score" toml:"score"`
}
type configCVERiskAcceptance struct {
	Enabled bool        `json:"enabled" yaml:"enabled" toml:"enabled"`
	CVEs    []configCVE `json:"cves" yaml:"cves" toml:"cves"`
}
type configServerityLimit struct {
	Critical configLimit `json:"critical" yaml:"critical" toml:"critical"`
	High     configLimit `json:"high" yaml:"high" toml:"high"`
	Medium   configLimit `json:"medium" yaml:"medium" toml:"medium"`
	Low      configLimit `json:"low" yaml:"low" toml:"low"`
}

type configEPSSLimit struct {
	Enabled bool    `json:"enabled" yaml:"enabled" toml:"enabled"`
	Score   float64 `json:"score" yaml:"score" toml:"score"`
}

type configCVELimit struct {
	Enabled bool        `json:"enabled" yaml:"enabled" toml:"enabled"`
	CVEs    []configCVE `json:"cves" yaml:"cves" toml:"cves"`
}

type configCVE struct {
	ID       string `json:"id" yaml:"id" toml:"id"`
	Metadata struct {
		Tags []string `json:"tags" yaml:"tags" toml:"tags"`
	}
}

type configLimit struct {
	Enabled bool `json:"enabled" yaml:"enabled" toml:"enabled"`
	Limit   uint `json:"limit" yaml:"limit" toml:"limit"`
}

func NewDefaultConfig() *Config {
	return &Config{
		Version: "v1",
		Metadata: configMetadata{
			Tags: []string{},
		},
		Grype: reportWithCVEs{
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
			EPSSLimit: configEPSSLimit{
				Enabled: false,
				Score:   0,
			},
			KEVLimitEnabled: false,
			CVELimit: configCVELimit{
				Enabled: false,
				CVEs:    make([]configCVE, 0),
			},
			EPSSRiskAcceptance: configEPSSRiskAcceptance{
				Enabled: false,
				Score:   0,
			},
			CVERiskAcceptance: configCVERiskAcceptance{
				Enabled: false,
				CVEs:    make([]configCVE, 0),
			},
		},
	}
}

func WriteDefaultConfig(w io.Writer, format string) error {
	config := NewDefaultConfig()
	config.Metadata.Tags = append(config.Metadata.Tags, "auto generated from CLI")
	return EncodeConfigTo(w, config, format)
}

func EncodeConfigTo(w io.Writer, config *Config, format string) error {
	var encoder interface {
		Encode(any) error
	}

	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		encoder = enc
	case "yaml", "yml":
		enc := yaml.NewEncoder(w)
		enc.SetIndent(2)
		encoder = enc
	case "toml":
		encoder = toml.NewEncoder(w)
	default:
		return fmt.Errorf("unsupported format '%s'", format)
	}

	return encoder.Encode(config)
}

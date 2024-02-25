package gatecheck

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

// Config is used to set limits and allowances during validation
//
// The report can be encoded/decoded into json, yaml, or toml
// Metadata fields are intended for arbitrary data and shouldn't
// conflict with rule validation
type Config struct {
	Version  string         `json:"version" yaml:"version" toml:"version" mapstructure:"version"`
	Metadata configMetadata `json:"metadata" yaml:"metadata" toml:"metadata"`
	Grype    reportWithCVEs `json:"grype" yaml:"grype" toml:"grype"`
}

type configMetadata struct {
	Tags []string `json:"tags" yaml:"tags" toml:"tags"`
}

type reportWithCVEs struct {
	SeverityLimit      configServerityLimit     `json:"severityLimit" yaml:"severityLimit" toml:"severityLimit"`
	EPSSLimit          configEPSSLimit          `json:"epssLimit" yaml:"epssLimit" toml:"epssLimit"`
	KEVLimitEnabled    bool                     `json:"kevLimit" yaml:"kevLimit" toml:"kevLimit"`
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
	Critical limit `json:"critical" yaml:"critical" toml:"critical"`
	High     limit `json:"high" yaml:"high" toml:"high"`
	Medium   limit `json:"medium" yaml:"medium" toml:"medium"`
	Low      limit `json:"low" yaml:"low" toml:"low"`
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

type limit struct {
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
				Critical: limit{
					Enabled: false,
					Limit:   0,
				},
				High: limit{
					Enabled: false,
					Limit:   0,
				},
				Medium: limit{
					Enabled: false,
					Limit:   0,
				},
				Low: limit{
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

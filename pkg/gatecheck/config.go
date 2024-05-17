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

	"github.com/olekukonko/tablewriter"
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
	Version   string               `json:"version"   toml:"version"   yaml:"version"`
	Metadata  configMetadata       `json:"metadata"  toml:"metadata"  yaml:"metadata"`
	Grype     reportWithCVEs       `json:"grype"     toml:"grype"     yaml:"grype"`
	Cyclonedx reportWithCVEs       `json:"cyclonedx" toml:"cyclonedx" yaml:"cyclonedx"`
	Semgrep   configSemgrepReport  `json:"semgrep"   toml:"semgrep"   yaml:"semgrep"`
	Gitleaks  configGitleaksReport `json:"gitleaks"  toml:"gitleaks"  yaml:"gitleaks"`
}

func (c *Config) String() string {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(c)

	v := viper.New()
	v.SetConfigType("json")
	_ = v.ReadConfig(buf)

	contentBuf := new(bytes.Buffer)
	table := tablewriter.NewWriter(contentBuf)
	table.SetHeader([]string{"config key", "value"})

	for _, key := range v.AllKeys() {
		table.Append([]string{key, fmt.Sprintf("%v", v.Get(key))})
	}
	return contentBuf.String()
}

type configGitleaksReport struct {
	LimitEnabled bool `json:"limitEnabled" toml:"limitEnabled" yaml:"limitEnabled"`
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
	}
}

type configLimit struct {
	Enabled bool `json:"enabled" toml:"enabled" yaml:"enabled"`
	Limit   uint `json:"limit"   toml:"limit"   yaml:"limit"`
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
		Cyclonedx: reportWithCVEs{
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
		Gitleaks: configGitleaksReport{
			LimitEnabled: false,
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

	slog.Debug("encode config file", "format", format)
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

type ConfigEncoder struct {
	writer io.Writer
	ext    string
}

func NewConfigEncoder(w io.Writer, ext string) *ConfigEncoder {
	return &ConfigEncoder{
		writer: w,
		ext:    ext,
	}
}

func (e *ConfigEncoder) Encode(config *Config) error {
	var encoder interface {
		Encode(any) error
	}

	switch e.ext {
	case ".json":
		encoder = json.NewEncoder(e.writer)
	case ".toml":
		encoder = toml.NewEncoder(e.writer)
	case ".yaml", ".yml":
		encoder = yaml.NewEncoder(e.writer)
	default:
		return errors.New("invalid file extension, only json, toml, yaml or yml supported")
	}

	return encoder.Encode(config)

}

type ConfigDecoder struct {
	filename string
}

func NewConfigDecoder(filename string) *ConfigDecoder {
	return &ConfigDecoder{
		filename: filename,
	}
}

func (d *ConfigDecoder) Decode(config *Config) error {
	ext := path.Ext(d.filename)

	slog.Debug("decode", "filename", d.filename, "extension", ext)
	f, err := os.Open(d.filename)
	if err != nil {
		return err
	}

	var decoder interface {
		Decode(any) error
	}

	switch ext {
	case ".json":
		decoder = json.NewDecoder(f)
	case ".toml":
		decoder = toml.NewDecoder(f)
	case ".yaml", ".yml":
		decoder = yaml.NewDecoder(f)
	default:
		return errors.New("invalid file extension, only json, toml, yaml or yml supported")
	}

	return decoder.Decode(config)
}

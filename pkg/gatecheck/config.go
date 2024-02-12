package gatecheck

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

func defaultConfig() map[string]any {
	return map[string]any{
		grype.ConfigFieldName: grype.Config{
			AllowList:          []grype.ListItem{{ID: "example allow id", Reason: "example reason"}},
			DenyList:           []grype.ListItem{{ID: "example deny id", Reason: "example reason"}},
			EPSSAllowThreshold: 1,
			EPSSDenyThreshold:  1,
			Critical:           -1,
			High:               -1,
			Medium:             -1,
			Low:                -1,
			Negligible:         -1,
			Unknown:            -1,
		},
		semgrep.ConfigFieldName: semgrep.Config{
			Info:    -1,
			Warning: -1,
			Error:   -1,
		},
		gitleaks.ConfigFieldName: gitleaks.Config{
			SecretsAllowed: true,
		},
		cyclonedx.ConfigFieldName: cyclonedx.Config{
			AllowList: []cyclonedx.ListItem{{ID: "example allow id", Reason: "example reason"}},
			DenyList:  []cyclonedx.ListItem{{ID: "example deny id", Reason: "example reason"}},
			Required:  false,
			Critical:  -1,
			High:      -1,
			Medium:    -1,
			Low:       -1,
			Info:      -1,
			None:      -1,
			Unknown:   -1,
		},
	}
}

func WriteDefaultConfig(w io.Writer, format string) error {
	return EncodeConfigTo(w, defaultConfig(), format)
}

func EncodeConfigTo(w io.Writer, config map[string]any, format string) error {
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

	return encoder.Encode(defaultConfig())
}

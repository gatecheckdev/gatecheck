package gatecheck

import (
	"log/slog"
	"slices"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/vex"
)

type configVEX struct {
	// Files are OpenVEX or CycloneDX VEX documents. Relative paths are read
	// from the working directory.
	Files []string `json:"files" toml:"files" yaml:"files"`
}

// WithVEXFiles adds VEX documents to the ones listed in the config.
func WithVEXFiles(filenames ...string) optionFunc {
	return func(o *fetchOptions) {
		o.vexFiles = append(o.vexFiles, filenames...)
	}
}

// loadVEX reads the config's VEX files and the ones passed as options.
func loadVEX(config *Config, options *fetchOptions) (*vex.Document, error) {
	files := append(slices.Clone(config.VEX.Files), options.vexFiles...)
	if len(files) == 0 {
		return nil, nil
	}
	doc, err := vex.Load(files...)
	if err != nil {
		return nil, err
	}
	slog.Info("loaded vex statements", "files", len(files), "statements", doc.Len())
	return doc, nil
}

// vexSuppressed logs and reports whether doc marks a finding not exploitable.
func vexSuppressed(doc *vex.Document, artifact string, f vex.Finding, severity string) bool {
	if doc == nil {
		return false
	}
	s, ok := doc.Suppressed(f)
	if !ok {
		return false
	}
	slog.Info("vex: not exploitable, removing from subsequent rules",
		"artifact", artifact,
		"id", f.IDs[0],
		"severity", severity,
		"status", s.Status,
		"justification", s.Justification,
		"source", s.Source,
	)
	return true
}

func ruleGrypeVEX(config *Config, report *artifacts.GrypeReportMin) {
	if config.vexDoc == nil {
		return
	}
	report.Matches = slices.DeleteFunc(report.Matches, func(m artifacts.GrypeMatch) bool {
		return vexSuppressed(config.vexDoc, "grype", vex.Finding{IDs: m.IDs(), PURL: m.Artifact.PURL}, m.Vulnerability.Severity)
	})
}

func ruleCyclonedxVEX(config *Config, report *artifacts.CyclonedxReportMin) {
	if config.vexDoc == nil {
		return
	}
	report.Vulnerabilities = slices.DeleteFunc(report.Vulnerabilities, func(v artifacts.CyclonedxVulnerability) bool {
		ids := []string{v.Identity()}
		for _, ref := range v.References {
			if ref.ID != "" {
				ids = append(ids, ref.ID)
			}
		}
		purls := report.AffectedPURLs(v)
		if len(purls) == 0 {
			purls = []string{""}
		}
		// The vulnerability is suppressed only when every affected package is.
		for _, purl := range purls[1:] {
			if _, ok := config.vexDoc.Suppressed(vex.Finding{IDs: ids, PURL: purl}); !ok {
				return false
			}
		}
		return vexSuppressed(config.vexDoc, "cyclonedx", vex.Finding{IDs: ids, PURL: purls[0]}, v.HighestSeverity())
	})
}

func ruleTrivyVEX(config *Config, findings []artifacts.TrivyFinding) []artifacts.TrivyFinding {
	if config.vexDoc == nil {
		return findings
	}
	return slices.DeleteFunc(findings, func(f artifacts.TrivyFinding) bool {
		return vexSuppressed(config.vexDoc, "trivy", vex.Finding{IDs: f.IDs, PURL: f.PURL}, f.Severity)
	})
}

func ruleOSVVEX(config *Config, findings []artifacts.OSVFinding) []artifacts.OSVFinding {
	if config.vexDoc == nil {
		return findings
	}
	return slices.DeleteFunc(findings, func(f artifacts.OSVFinding) bool {
		return vexSuppressed(config.vexDoc, "osv-scanner", vex.Finding{IDs: f.IDs, PURL: f.PURL}, f.Severity)
	})
}

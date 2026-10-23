package gatecheck

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
	"github.com/pelletier/go-toml/v2"
	"gopkg.in/yaml.v3"
)

func TestTrivyListAndValidate(t *testing.T) {
	report := mustRead(t, "../../test/trivy-report.json")

	t.Run("list", func(t *testing.T) {
		got := renderList(t, "trivy-report.json", report, nil)
		for _, want := range []string{"TRIVY SEVERITY", "libcrypto3", "log4j-core", "https://avd.aquasec.com/nvd/cve-2024-5535", "Critical", "High"} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q\n%s", want, got)
			}
		}
		if strings.Contains(got, "DS002") || strings.Contains(got, "Image user") {
			t.Fatalf("misconfiguration was listed\n%s", got)
		}
	})

	t.Run("list epss", func(t *testing.T) {
		got := renderList(t, "reports/trivy.json", report, []ListOptionFunc{withTestEPSS(t)})
		if !strings.Contains(got, "CVE-2023-0464") || !strings.Contains(got, "0.12345") {
			t.Fatalf("epss columns missing\n%s", got)
		}
		if !strings.Contains(got, "CVE-2021-44228") {
			t.Fatalf("vendor CVE was not used as the id\n%s", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := renderList(t, "trivy.json", []byte(`{"SchemaVersion":2,"Results":[]}`), nil)
		if got != "No trivy vulnerabilities\n" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("cyclonedx name wins", func(t *testing.T) {
		got := renderList(t, "cyclonedx-trivy-sbom.json", []byte(`{}`), nil)
		if got != "No cyclonedx vulnerabilities\n" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("content wins over filename case", func(t *testing.T) {
		got := renderList(t, "Trivy-report.json", report, nil)
		if !strings.Contains(got, "TRIVY SEVERITY") {
			t.Fatalf("contents should win over filename case\n%s", got)
		}
	})

	t.Run("severity limit", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Trivy.SeverityLimit.Critical.Enabled = true
		config.Trivy.SeverityLimit.Critical.Limit = 1
		err := Validate(config, bytes.NewReader(report), "trivy-report.json")
		if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "Trivy: Severity Limit Exceeded") {
			t.Fatalf("err %v", err)
		}

		config.Trivy.SeverityLimit.Critical.Limit = 2
		if err := Validate(config, bytes.NewReader(report), "trivy-report.json"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("deny and allow", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Trivy.CVELimit.Enabled = true
		config.Trivy.CVELimit.CVEs = []configCVE{{ID: "cve-2024-5535"}}
		err := Validate(config, bytes.NewReader(report), "scan-trivy.json")
		if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "CVE explicitly denied") {
			t.Fatalf("err %v", err)
		}

		config = NewDefaultConfig()
		config.Trivy.SeverityLimit.Critical.Enabled = true
		config.Trivy.CVERiskAcceptance.Enabled = true
		config.Trivy.CVERiskAcceptance.CVEs = []configCVE{{ID: "CVE-2023-0464"}, {ID: "GHSA-jfh8-c2jp-5v3q"}}
		if err := Validate(config, bytes.NewReader(report), "trivy-report.json"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("vendor id deny", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Trivy.CVELimit.Enabled = true
		config.Trivy.CVELimit.CVEs = []configCVE{{ID: "CVE-2021-44228"}}
		err := Validate(config, bytes.NewReader(report), "trivy-report.json")
		if !errors.Is(err, ErrValidationFailure) {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("bundle", func(t *testing.T) {
		config := NewDefaultConfig()
		config.Trivy.SeverityLimit.High.Enabled = true
		config.Trivy.SeverityLimit.High.Limit = 0
		var bundle bytes.Buffer
		if err := CreateBundle(&bundle, bytes.NewReader(report), "trivy-report.json", []string{"ci"}); err != nil {
			t.Fatal(err)
		}
		err := Validate(config, bytes.NewReader(bundle.Bytes()), "gatecheck-bundle.tar.gz")
		if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "Trivy: Severity Limit Exceeded") {
			t.Fatalf("err %v", err)
		}
	})
}

func TestTrivyEPSSAndKEV(t *testing.T) {
	findings := []artifacts.TrivyFinding{{
		IDs:      []string{"CVE-2023-0464"},
		Severity: "high",
		Package:  "libssl3",
		Version:  "3.3.2-r0",
	}}
	data := &epss.Data{CVEs: map[string]epss.CVE{
		"CVE-2023-0464": {EPSS: "0.50000", Percentile: "0.80000"},
	}}
	config := NewDefaultConfig()
	config.Trivy.EPSSLimit.Enabled = true
	config.Trivy.EPSSLimit.Score = 0.4
	err := validateTrivyRules(config, findings, nil, data)
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "EPSS Limit Exceeded") {
		t.Fatalf("err %v", err)
	}

	config.Trivy.EPSSLimit.Score = 0.5
	if err := validateTrivyRules(config, append([]artifacts.TrivyFinding(nil), findings...), nil, data); err != nil {
		t.Fatal(err)
	}

	kept := []artifacts.TrivyFinding{{
		IDs:      []string{"CVE-2023-0464"},
		Severity: "high",
		Package:  "libssl3",
		Version:  "3.3.2-r0",
	}}
	config = NewDefaultConfig()
	config.Trivy.SeverityLimit.High.Enabled = true
	config.Trivy.SeverityLimit.High.Limit = 5
	config.Trivy.KEVLimitEnabled = true
	catalog := &kev.Catalog{Vulnerabilities: []kev.Vulnerability{{CveID: "CVE-2023-0464"}}}
	err = validateTrivyRules(config, kept, catalog, nil)
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "KEV Catalog") {
		t.Fatalf("err %v", err)
	}
}

func TestTrivyConfigRoundTrip(t *testing.T) {
	config := NewDefaultConfig()
	config.Trivy.SeverityLimit.Critical.Enabled = true
	config.Trivy.SeverityLimit.Critical.Limit = 2
	config.Trivy.CVERiskAcceptance.Enabled = true
	config.Trivy.CVERiskAcceptance.CVEs = []configCVE{{ID: "CVE-2024-5535"}}

	var yamlBuf bytes.Buffer
	if err := EncodeConfigTo(&yamlBuf, config, "yaml"); err != nil {
		t.Fatal(err)
	}
	var decoded Config
	if err := yaml.Unmarshal(yamlBuf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.Trivy.SeverityLimit.Critical.Enabled || decoded.Trivy.SeverityLimit.Critical.Limit != 2 {
		t.Fatalf("yaml trivy %+v", decoded.Trivy.SeverityLimit.Critical)
	}
	if !decoded.Trivy.CVERiskAcceptance.Enabled || decoded.Trivy.CVERiskAcceptance.CVEs[0].ID != "CVE-2024-5535" {
		t.Fatalf("yaml allow %+v", decoded.Trivy.CVERiskAcceptance)
	}

	var tomlBuf bytes.Buffer
	if err := EncodeConfigTo(&tomlBuf, config, "toml"); err != nil {
		t.Fatal(err)
	}
	decoded = Config{}
	if err := toml.Unmarshal(tomlBuf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Trivy.CVERiskAcceptance.CVEs[0].ID != "CVE-2024-5535" {
		t.Fatalf("toml %+v", decoded.Trivy.CVERiskAcceptance)
	}
}

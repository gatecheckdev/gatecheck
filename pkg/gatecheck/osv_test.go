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

func TestOSVListAndValidate(t *testing.T) {
	report := mustRead(t, "../../test/osv-scanner-report.json")

	t.Run("list groups once", func(t *testing.T) {
		got := renderList(t, "osv-scanner-report.json", report, nil)
		for _, want := range []string{"OSV SEVERITY", "github.com/gogo/protobuf", "regex", "ansi_term", "https://osv.dev/GO-2021-0053", "Critical", "High", "Low"} {
			if !strings.Contains(got, want) {
				t.Fatalf("missing %q\n%s", want, got)
			}
		}
		if strings.Count(got, "github.com/gogo/protobuf") != 1 {
			t.Fatalf("grouped aliases were listed more than once\n%s", got)
		}
		if strings.Contains(got, "license") {
			t.Fatalf("license text was listed\n%s", got)
		}
	})

	t.Run("short name and stdin type", func(t *testing.T) {
		got := renderList(t, "osv.json", report, nil)
		if !strings.Contains(got, "regex") {
			t.Fatalf("osv.json was not detected\n%s", got)
		}
		got = renderList(t, "stdin:osv-scanner", report, nil)
		if !strings.Contains(got, "ansi_term") {
			t.Fatalf("input type was not detected\n%s", got)
		}
	})

	t.Run("list epss uses cve alias", func(t *testing.T) {
		got := renderList(t, "reports/osv-scanner.json", report, []ListOptionFunc{withTestEPSS(t)})
		if !strings.Contains(got, "CVE-2021-3121") || !strings.Contains(got, "CVE-2022-24713") {
			t.Fatalf("cve aliases missing\n%s", got)
		}
	})

	t.Run("empty", func(t *testing.T) {
		got := renderList(t, "osv-scanner.json", []byte(`{"results":[]}`), nil)
		if got != "No osv-scanner vulnerabilities\n" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("case sensitive filename", func(t *testing.T) {
		err := List(&bytes.Buffer{}, bytes.NewReader(report), "OSV-scanner.json")
		if err == nil {
			t.Fatal("expected an unsupported filename")
		}
	})

	t.Run("severity limit counts groups", func(t *testing.T) {
		config := NewDefaultConfig()
		config.OSVScanner.SeverityLimit.Critical.Enabled = true
		config.OSVScanner.SeverityLimit.Critical.Limit = 0
		err := Validate(config, bytes.NewReader(report), "osv-scanner-report.json")
		if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "osv-scanner: Severity Limit Exceeded") {
			t.Fatalf("err %v", err)
		}
		config.OSVScanner.SeverityLimit.Critical.Limit = 1
		if err := Validate(config, bytes.NewReader(report), "osv-scanner-report.json"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("deny and allow aliases", func(t *testing.T) {
		config := NewDefaultConfig()
		config.OSVScanner.CVELimit.Enabled = true
		config.OSVScanner.CVELimit.CVEs = []configCVE{{ID: "cve-2021-3121"}}
		err := Validate(config, bytes.NewReader(report), "osv.json")
		if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "CVE explicitly denied") {
			t.Fatalf("err %v", err)
		}

		config = NewDefaultConfig()
		config.OSVScanner.SeverityLimit.Critical.Enabled = true
		config.OSVScanner.CVERiskAcceptance.Enabled = true
		config.OSVScanner.CVERiskAcceptance.CVEs = []configCVE{{ID: "GHSA-m5pq-gvj9-9vr8"}}
		if err := Validate(config, bytes.NewReader(report), "osv-scanner-report.json"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bundle", func(t *testing.T) {
		config := NewDefaultConfig()
		config.OSVScanner.SeverityLimit.Low.Enabled = true
		config.OSVScanner.SeverityLimit.Low.Limit = 0
		var bundle bytes.Buffer
		if err := CreateBundle(&bundle, bytes.NewReader(report), "osv-scanner-report.json", []string{"ci"}); err != nil {
			t.Fatal(err)
		}
		err := Validate(config, bytes.NewReader(bundle.Bytes()), "gatecheck-bundle.tar.gz")
		if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "Severity Limit Exceeded") {
			t.Fatalf("err %v", err)
		}
	})

	t.Run("moderate word", func(t *testing.T) {
		raw := []byte(`{"results":[{"packages":[{"package":{"name":"left-pad","version":"1.0.0"},"vulnerabilities":[{"id":"GHSA-moderate","database_specific":{"severity":"MODERATE"}}],"groups":[{"ids":["GHSA-moderate"],"max_severity":""}]}]}]}`)
		config := NewDefaultConfig()
		config.OSVScanner.SeverityLimit.Medium.Enabled = true
		config.OSVScanner.SeverityLimit.Medium.Limit = 0
		err := Validate(config, bytes.NewReader(raw), "osv-scanner.json")
		if !errors.Is(err, ErrValidationFailure) {
			t.Fatalf("err %v", err)
		}
	})
}

func TestOSVEPSSAndKEV(t *testing.T) {
	findings := []artifacts.OSVFinding{{
		IDs:      []string{"GHSA-m5pq-gvj9-9vr8", "CVE-2022-24713"},
		Severity: "critical",
		Package:  "regex",
		Version:  "1.5.1",
	}}
	data := &epss.Data{CVEs: map[string]epss.CVE{
		"CVE-2022-24713": {EPSS: "0.42000", Percentile: "0.70000"},
	}}
	config := NewDefaultConfig()
	config.OSVScanner.SeverityLimit.Critical.Enabled = true
	config.OSVScanner.SeverityLimit.Critical.Limit = 5
	config.OSVScanner.EPSSLimit.Enabled = true
	config.OSVScanner.EPSSLimit.Score = 0.4
	err := validateOSVRules(config, findings, nil, data)
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "EPSS Limit Exceeded") {
		t.Fatalf("err %v", err)
	}

	config.OSVScanner.EPSSLimit.Score = 0.42
	if err := validateOSVRules(config, append([]artifacts.OSVFinding(nil), findings...), nil, data); err != nil {
		t.Fatal(err)
	}

	kept := []artifacts.OSVFinding{{
		IDs:      []string{"CVE-2022-24713"},
		Severity: "high",
		Package:  "regex",
		Version:  "1.5.1",
	}}
	config = NewDefaultConfig()
	config.OSVScanner.SeverityLimit.High.Enabled = true
	config.OSVScanner.SeverityLimit.High.Limit = 5
	config.OSVScanner.KEVLimitEnabled = true
	catalog := &kev.Catalog{Vulnerabilities: []kev.Vulnerability{{CveID: "CVE-2022-24713"}}}
	err = validateOSVRules(config, kept, catalog, nil)
	if !errors.Is(err, ErrValidationFailure) || !strings.Contains(err.Error(), "KEV Catalog") {
		t.Fatalf("err %v", err)
	}
}

func TestOSVConfigRoundTrip(t *testing.T) {
	config := NewDefaultConfig()
	config.OSVScanner.SeverityLimit.High.Enabled = true
	config.OSVScanner.SeverityLimit.High.Limit = 3
	config.OSVScanner.CVELimit.Enabled = true
	config.OSVScanner.CVELimit.CVEs = []configCVE{{ID: "CVE-2021-3121"}}

	var yamlBuf bytes.Buffer
	if err := EncodeConfigTo(&yamlBuf, config, "yaml"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(yamlBuf.String(), "osv-scanner:") {
		t.Fatalf("yaml missing key\n%s", yamlBuf.String())
	}
	var decoded Config
	if err := yaml.Unmarshal(yamlBuf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !decoded.OSVScanner.SeverityLimit.High.Enabled || decoded.OSVScanner.SeverityLimit.High.Limit != 3 {
		t.Fatalf("yaml %+v", decoded.OSVScanner.SeverityLimit.High)
	}
	if decoded.OSVScanner.CVELimit.CVEs[0].ID != "CVE-2021-3121" {
		t.Fatalf("yaml deny %+v", decoded.OSVScanner.CVELimit)
	}

	var tomlBuf bytes.Buffer
	if err := EncodeConfigTo(&tomlBuf, config, "toml"); err != nil {
		t.Fatal(err)
	}
	decoded = Config{}
	if err := toml.Unmarshal(tomlBuf.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.OSVScanner.CVELimit.CVEs[0].ID != "CVE-2021-3121" {
		t.Fatalf("toml %+v", decoded.OSVScanner.CVELimit)
	}
}

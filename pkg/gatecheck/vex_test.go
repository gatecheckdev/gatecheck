package gatecheck

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts"
	"github.com/gatecheckdev/gatecheck/pkg/vex"
)

// grypeCriticals are the critical matches in test/grype-report.json, as
// vulnerability id and package URL.
var grypeCriticals = [][2]string{
	{"GHSA-2jcg-qqmg-46q6", "pkg:npm/monorepo-symlink-test@0.0.0"},
	{"GHSA-5mrr-rgp6-x4gr", "pkg:npm/marsdb@0.6.11"},
	{"CVE-2015-9235", "pkg:npm/jsonwebtoken"},
	{"CVE-2023-37466", "pkg:npm/vm2@3.9.17"},
	{"GHSA-g644-9gfx-q4q4", "pkg:npm/vm2@3.9.17"},
	{"CVE-2019-10744", "pkg:npm/lodash@2.4.2"},
	{"CVE-2023-32314", "pkg:npm/vm2@3.9.17"},
}

func writeOpenVEX(t *testing.T, pairs [][2]string, status string) string {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString(`{"@context":"https://openvex.dev/ns/v0.2.0","statements":[`)
	for i, p := range pairs {
		if i > 0 {
			buf.WriteString(",")
		}
		buf.WriteString(`{"vulnerability":{"name":"` + p[0] + `"},"products":[{"@id":"pkg:oci/app","subcomponents":[{"@id":"` + p[1] + `"}]}],"status":"` + status + `","justification":"vulnerable_code_not_present"}`)
	}
	buf.WriteString(`]}`)
	name := filepath.Join(t.TempDir(), "app.openvex.json")
	if err := os.WriteFile(name, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func criticalLimitConfig() *Config {
	config := NewDefaultConfig()
	config.Grype.SeverityLimit.Critical = configLimit{Enabled: true, Limit: 0}
	config.Trivy.SeverityLimit.Critical = configLimit{Enabled: true, Limit: 0}
	config.OSVScanner.SeverityLimit.Critical = configLimit{Enabled: true, Limit: 0}
	config.OSVScanner.SeverityLimit.High = configLimit{Enabled: true, Limit: 0}
	config.OSVScanner.SeverityLimit.Medium = configLimit{Enabled: true, Limit: 0}
	config.OSVScanner.SeverityLimit.Low = configLimit{Enabled: true, Limit: 0}
	return config
}

func validateFile(t *testing.T, config *Config, filename string, opts ...Option) error {
	t.Helper()
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	return Validate(config, f, filename, opts...)
}

func TestValidateGrypeWithVEX(t *testing.T) {
	report := "../../test/grype-report.json"
	if err := validateFile(t, criticalLimitConfig(), report); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("without vex: %v", err)
	}

	all := writeOpenVEX(t, grypeCriticals, "not_affected")
	if err := validateFile(t, criticalLimitConfig(), report, WithVEXFiles(all)); err != nil {
		t.Fatalf("with vex flag: %v", err)
	}

	config := criticalLimitConfig()
	config.VEX.Files = []string{all}
	if err := validateFile(t, config, report); err != nil {
		t.Fatalf("with vex config: %v", err)
	}

	partial := writeOpenVEX(t, grypeCriticals[1:], "not_affected")
	if err := validateFile(t, criticalLimitConfig(), report, WithVEXFiles(partial)); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("partial vex should still fail: %v", err)
	}

	affected := writeOpenVEX(t, grypeCriticals, "affected")
	if err := validateFile(t, criticalLimitConfig(), report, WithVEXFiles(affected)); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("affected status should not suppress: %v", err)
	}

	wrongPkg := writeOpenVEX(t, [][2]string{{"CVE-2019-10744", "pkg:npm/lodash@9.9.9"}}, "not_affected")
	cfg := NewDefaultConfig()
	cfg.Grype.CVELimit = configCVELimit{Enabled: true, CVEs: []configCVE{{ID: "GHSA-jf85-cpcp-j695"}}}
	if err := validateFile(t, cfg, report, WithVEXFiles(wrongPkg)); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("deny list must still fail: %v", err)
	}

	if err := validateFile(t, criticalLimitConfig(), report, WithVEXFiles("missing.openvex.json")); err == nil || errors.Is(err, ErrValidationFailure) {
		t.Fatalf("missing vex file should be an error, got %v", err)
	}
}

func TestValidateTrivyAndOSVWithVEX(t *testing.T) {
	trivy := "../../test/trivy-report.json"
	if err := validateFile(t, criticalLimitConfig(), trivy); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("trivy without vex: %v", err)
	}
	trivyVEX := writeOpenVEX(t, [][2]string{{"CVE-2023-0464", "pkg:generic/openssl"}, {"GHSA-jfh8-c2jp-5v3q", "pkg:maven/x/y"}}, "fixed")
	if err := validateFile(t, criticalLimitConfig(), trivy, WithVEXFiles(trivyVEX)); err != nil {
		t.Fatalf("trivy with vex: %v", err)
	}

	osv := "../../test/osv-scanner-report.json"
	if err := validateFile(t, criticalLimitConfig(), osv); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("osv without vex: %v", err)
	}
	osvVEX := writeOpenVEX(t, [][2]string{
		{"GO-2021-0053", "pkg:golang/github.com/gogo/protobuf@1.3.1"},
		{"GHSA-m5pq-gvj9-9vr8", "pkg:cargo/regex"},
		{"RUSTSEC-2021-0145", "pkg:cargo/ansi_term@0.12.1"},
	}, "not_affected")
	if err := validateFile(t, criticalLimitConfig(), osv, WithVEXFiles(osvVEX)); err != nil {
		t.Fatalf("osv with vex: %v", err)
	}
	wrongEcosystem := writeOpenVEX(t, [][2]string{
		{"GO-2021-0053", "pkg:npm/github.com/gogo/protobuf"},
		{"GHSA-m5pq-gvj9-9vr8", "pkg:cargo/regex"},
		{"RUSTSEC-2021-0145", "pkg:cargo/ansi_term"},
	}, "not_affected")
	if err := validateFile(t, criticalLimitConfig(), osv, WithVEXFiles(wrongEcosystem)); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("osv vex for another ecosystem should not match: %v", err)
	}
}

func TestValidateBundleWithVEX(t *testing.T) {
	content, err := os.ReadFile("../../test/grype-report.json")
	if err != nil {
		t.Fatal(err)
	}
	bundle := archive.NewBundle()
	if err := bundle.AddFrom(bytes.NewReader(content), "grype-report.json", nil); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if _, err := archive.TarGzipBundle(&buf, bundle); err != nil {
		t.Fatal(err)
	}
	raw := buf.Bytes()
	if err := Validate(criticalLimitConfig(), bytes.NewReader(raw), "bundle.tar.gz"); !errors.Is(err, ErrValidationFailure) {
		t.Fatalf("bundle without vex: %v", err)
	}
	vexFile := writeOpenVEX(t, grypeCriticals, "not_affected")
	if err := Validate(criticalLimitConfig(), bytes.NewReader(raw), "bundle.tar.gz", WithVEXFiles(vexFile)); err != nil {
		t.Fatalf("bundle with vex: %v", err)
	}
}

func TestCyclonedxVEXNeedsEveryAffectedPackage(t *testing.T) {
	report := &artifacts.CyclonedxReportMin{
		Components: []artifacts.CyclonedxComponent{
			{BOMRef: "login", PURL: "pkg:deb/ubuntu/login@4.8.1?arch=arm64"},
			{BOMRef: "passwd", PURL: "pkg:deb/ubuntu/passwd@4.8.1?arch=arm64"},
		},
		Vulnerabilities: []artifacts.CyclonedxVulnerability{
			{ID: "CVE-2023-29383", Affects: []artifacts.CyclondexAffectedPackage{{Ref: "login"}, {Ref: "passwd"}}},
		},
	}
	run := func(pairs [][2]string) int {
		doc, err := vex.Load(writeOpenVEX(t, pairs, "not_affected"))
		if err != nil {
			t.Fatal(err)
		}
		r := *report
		r.Vulnerabilities = slices.Clone(report.Vulnerabilities)
		ruleCyclonedxVEX(&Config{vexDoc: doc}, &r)
		return len(r.Vulnerabilities)
	}
	if got := run([][2]string{{"CVE-2023-29383", "pkg:deb/ubuntu/login"}}); got != 1 {
		t.Fatalf("one of two packages covered, remaining %d", got)
	}
	if got := run([][2]string{{"CVE-2023-29383", "pkg:deb/ubuntu/login"}, {"CVE-2023-29383", "pkg:deb/ubuntu/passwd@4.8.1"}}); got != 0 {
		t.Fatalf("both packages covered, remaining %d", got)
	}
}

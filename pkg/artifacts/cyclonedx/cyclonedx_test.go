package cyclonedx

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"gopkg.in/yaml.v3"
)

const CyclonedxGrypeReport string = "../../../test/cyclonedx-grype-sbom.json"
const CyclonedxTrivyReport string = "../../../test/cyclonedx-trivy-sbom.json"
const CyclonedxSyftReport string = "../../../test/cyclonedx-syft-sbom.json"

func TestEncoding(t *testing.T) {

	testTable := []struct {
		label    string
		filename string
	}{
		{label: "grype", filename: CyclonedxGrypeReport},
		{label: "trivy", filename: CyclonedxGrypeReport},
		{label: "syft", filename: CyclonedxGrypeReport},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			obj, err := NewReportDecoder().DecodeFrom(MustOpen(CyclonedxGrypeReport, t))
			if err != nil {
				t.Fatal(err)
			}
			report, ok := obj.(*ScanReport)
			if !ok {
				t.Fatalf("want: *Report got: %T", obj)
			}
			if len(*report.Vulnerabilities) < 10 {
				t.Fatalf("want: <10 got: %d", len(*report.Vulnerabilities))
			}

			t.Log("\n" + report.String())
			if !strings.Contains(report.String(), "library") {
				t.Fatal("'library' should exist in string")
			}
			t.Log(NewReportDecoder().FileType())
		})
	}

	t.Run("bad-reader", func(t *testing.T) {
		if _, err := NewReportDecoder().DecodeFrom(&badReader{}); !errors.Is(err, gce.ErrIO) {
			t.Fatalf("want: %v got: %v", gce.ErrIO, err)
		}
	})
	t.Run("bad-json", func(t *testing.T) {
		if _, err := NewReportDecoder().DecodeFrom(strings.NewReader("{{{")); !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})
	t.Run("bad-failed-check", func(t *testing.T) {
		r, _ := NewReportDecoder().DecodeFrom(MustOpen(CyclonedxGrypeReport, t))

		buf := new(bytes.Buffer)
		report := r.(*ScanReport)
		report.BOMFormat = ""
		_ = json.NewEncoder(buf).Encode(report)
		if _, err := NewReportDecoder().DecodeFrom(buf); !errors.Is(err, gce.ErrFailedCheck) {
			t.Fatalf("want: %v got: %v", gce.ErrFailedCheck, err)
		}
	})
	t.Run("missing-components", func(t *testing.T) {
		r, _ := NewReportDecoder().DecodeFrom(MustOpen(CyclonedxGrypeReport, t))
		report := r.(*ScanReport)
		report.Components = nil
		buf := new(bytes.Buffer)
		_ = json.NewEncoder(buf).Encode(report)

		r, err := NewReportDecoder().DecodeFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("missing-vulnerabilities", func(t *testing.T) {
		r, _ := NewReportDecoder().DecodeFrom(MustOpen(CyclonedxGrypeReport, t))
		report := r.(*ScanReport)
		report.Vulnerabilities = nil
		buf := new(bytes.Buffer)
		_ = json.NewEncoder(buf).Encode(report)

		r, err := NewReportDecoder().DecodeFrom(buf)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func TestValidation(t *testing.T) {
	report := &ScanReport{
		Vulnerabilities: &[]cdx.Vulnerability{},
		Components:      &[]cdx.Component{},
	}
	addCyclonedxVul(report, "Critical", "CVE-2023-1")
	addCyclonedxVul(report, "High", "CVE-2023-2")
	addCyclonedxVul(report, "Low", "CVE-2023-3")

	t.Run("success", func(t *testing.T) {

		config := Config{Critical: -1, High: -1, Medium: -1, Low: -1, Info: -1, None: -1, Unknown: -1}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(map[string]any{ConfigFieldName: config})
		if err := NewValidator().Validate(report, configBuf); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fail", func(t *testing.T) {

		config := Config{Critical: 0, High: 0, Medium: -1, Low: -1, Info: -1, None: -1, Unknown: -1}
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(map[string]any{ConfigFieldName: config})
		if err := NewValidator().Validate(report, configBuf); !errors.Is(err, gcv.ErrValidation) {
			t.Fatalf("want: %v got: %v", gcv.ErrValidation, err)
		}
	})
}

func TestCyclonedxDenyList(t *testing.T) {
	report := &ScanReport{
		Vulnerabilities: &[]cdx.Vulnerability{},
		Components:      &[]cdx.Component{},
	}
	addCyclonedxVul(report, "Critical", "CVE-2023-1")
	addCyclonedxVul(report, "High", "CVE-2023-2")
	addCyclonedxVul(report, "Low", "CVE-2023-3")

	config := Config{Critical: -1, High: -1, Medium: -1, Low: -1, Info: -1, None: -1, Unknown: -1}
	config.DenyList = []ListItem{{Id: "CVE-2023-3", Reason: "Because..."}}

	t.Log(config.DenyList)

	t.Log(report)

	configBuf := new(bytes.Buffer)
	_ = yaml.NewEncoder(configBuf).Encode(map[string]any{ConfigFieldName: config})
	if err := NewValidator().Validate(report, configBuf); err == nil {
		t.Fatal("Expected Validation error for CVE-2023-3")
	}
}

func TestCyclonedxAllowList(t *testing.T) {
	report := &ScanReport{
		Vulnerabilities: &[]cdx.Vulnerability{},
		Components:      &[]cdx.Component{},
	}
	addCyclonedxVul(report, "Critical", "CVE-2023-1")
	addCyclonedxVul(report, "High", "CVE-2023-2")
	addCyclonedxVul(report, "Low", "CVE-2023-3")

	config := Config{Critical: 0, High: -1, Medium: -1, Low: -1, Info: -1, None: -1, Unknown: -1}
	config.AllowList = []ListItem{{Id: "CVE-2023-1", Reason: "Because..."}}

	t.Log(config.AllowList)

	t.Log(report)

	configBuf := new(bytes.Buffer)
	_ = yaml.NewEncoder(configBuf).Encode(map[string]any{ConfigFieldName: config})
	t.Log(configBuf.String())
	if err := NewValidator().Validate(report, configBuf); err != nil {
		t.Fatal(err)
	}
}

func TestCyclonedxSbomShim(t *testing.T) {
	report := &ScanReport{
		Vulnerabilities: &[]cdx.Vulnerability{},
		Components:      &[]cdx.Component{},
	}
	addCyclonedxVul(report, "Critical", "CVE-2023-1")
	addCyclonedxVul(report, "High", "CVE-2023-2")
	addCyclonedxVul(report, "Low", "CVE-2023-3")
	addCyclonedxComponent(report, "CVE-2023-4")
	addCyclonedxComponent(report, "CVE-2023-5")

	t.Log(report)

	report = report.ShimComponentsAsVulnerabilities()
	for _, vul := range *report.Vulnerabilities {
		t.Log(vul.ID)
		for _, affects := range *vul.Affects {
			t.Logf("%+v\n", affects)
		}
		if vul.ID == "" && len(*vul.Affects) != 5 {
			t.Fatal("Missing components as vulnerabilities")
		}
	}

}

func TestMissingComponentForVulnerability(t *testing.T) {
	report := &ScanReport{
		Vulnerabilities: &[]cdx.Vulnerability{
			{ID: "CVE-2023-1", Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityCritical}}, Affects: &[]cdx.Affects{{Ref: "CVE-2023-1-ref"}}},
			{ID: "CVE-2023-2", Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityCritical}}, Affects: &[]cdx.Affects{{Ref: "CVE-2023-3-ref"}}},
		},
		Components: &[]cdx.Component{
			{BOMRef: "CVE-2023-1-ref", Name: "CVE-2023-1-name", Version: "CVE-2023-1-version", Type: cdx.ComponentTypeLibrary},
		},
	}

	t.Log(report)
}

func TestHighestSeverityRating(t *testing.T) {
	ratings := []cdx.VulnerabilityRating{{Severity: "low"}, {Severity: "medium"}, {Severity: "critical"}, {Severity: "unknown"}, {Severity: "blah blah"}}
	rating := highestVulnerability(ratings)
	if rating.Severity != "critical" {
		t.Fatalf("want: %s got: %s", "critical", rating.Severity)
	}
}

func addCyclonedxVul(r *ScanReport, severity string, id string) {
	vuln := cdx.Vulnerability{
		ID:      id,
		Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityHigh}},
		Affects: &[]cdx.Affects{{Ref: id + "-ref"}},
	}
	addCyclonedxComponent(r, id)
	*r.Vulnerabilities = append(*r.Vulnerabilities, vuln)
}

func addCyclonedxComponent(r *ScanReport, id string) {
	comp := cdx.Component{BOMRef: id + "-ref", Name: id + "-name", Version: id + "-version", Type: cdx.ComponentTypeLibrary}
	*r.Components = append(*r.Components, comp)
}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatalf("test setup failure: %v", err)
	}
	return f
}

type badReader struct{}

func (r *badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("mock error: bad reader")
}

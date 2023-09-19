package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"

	gosemgrep "github.com/BacchusJackson/go-semgrep"
	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/kev"
	gcv "github.com/gatecheckdev/gatecheck/pkg/validate"
	"gopkg.in/yaml.v3"
)

func TestValidate_KEV(t *testing.T) {
	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches,
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "Critical"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Medium"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "Low"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "Critical"}}},
	)
	catalog := kev.Catalog{
		Title:          "some title",
		CatalogVersion: "some version",
		Vulnerabilities: []kev.Vulnerability{
			{CveID: "cve-1"}, {CveID: "cve-3"}, {CveID: "cve-5"}, {CveID: "cve-7"}, {CveID: "cve-9"},
		},
	}
	t.Run("success-from-file", func(t *testing.T) {

		reportFilename := writeTempAny(&grypeReport, t)
		catalogFilename := writeTempAny(&catalog, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

		cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, KEVDownloadAgent: new(bytes.Buffer), EPSSDownloadAgent: new(bytes.Buffer)}

		commandString := fmt.Sprintf("validate -k %s -c %s %s", catalogFilename, configFilename, reportFilename)
		_, err := Execute(commandString, cliconfig)

		t.Log(err)
		if !errors.Is(err, ErrorValidation) {
			t.Fatalf("want: %v got: %v", ErrorValidation, err)
		}
	})

	t.Run("success-from-downloader", func(t *testing.T) {
		catalog := kev.Catalog{
			Title:          "some title",
			CatalogVersion: "some version",
			Vulnerabilities: []kev.Vulnerability{
				{CveID: "cve-1"}, {CveID: "cve-3"}, {CveID: "cve-5"}, {CveID: "cve-7"}, {CveID: "cve-9"},
			},
		}

		reportFilename := writeTempAny(&grypeReport, t)
		catalogFilename := writeTempAny(&catalog, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

		cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, KEVDownloadAgent: MustOpen(catalogFilename, t), EPSSDownloadAgent: new(bytes.Buffer)}

		commandString := fmt.Sprintf("validate --fetch-kev -c %s %s", configFilename, reportFilename)
		_, err := Execute(commandString, cliconfig)

		t.Log(err)
		if !errors.Is(err, ErrorValidation) {
			t.Fatalf("want: %v got: %v", ErrorValidation, err)
		}
	})

	t.Run("file-encoding-error", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

		cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, KEVDownloadAgent: new(bytes.Buffer), EPSSDownloadAgent: new(bytes.Buffer)}

		commandString := fmt.Sprintf("validate -k %s -c %s %s", fileWithBadJSON(t), configFilename, reportFilename)
		_, err := Execute(commandString, cliconfig)

		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})
}

func TestValidate_EPSS(t *testing.T) {
	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches,
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-1", Severity: "Critical"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-2", Severity: "Critical"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-3", Severity: "Medium"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-4", Severity: "Low"}}},
		models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "cve-5", Severity: "Critical"}}},
	)
	var sb strings.Builder
	_, _ = sb.WriteString("#model_version:v2023.03.01,score_date:2023-07-14T00:00:00+0000\n")
	_, _ = sb.WriteString("cve,epss,percentile\n")
	_, _ = sb.WriteString("cve-1,0.12345,0.00021\n")
	_, _ = sb.WriteString("cve-2,0.22345,0.00021\n")
	_, _ = sb.WriteString("cve-3,0.32345,0.00021\n")
	_, _ = sb.WriteString("cve-4,0.42345,0.00021\n")

	t.Run("success-from-file", func(t *testing.T) {
		epssFilename := path.Join(t.TempDir(), "epss.csv")
		_, _ = strings.NewReader(sb.String()).WriteTo(MustCreate(epssFilename, t))

		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1, EPSSDenyThreshold: 0.3}}, t)

		cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, KEVDownloadAgent: new(bytes.Buffer), EPSSDownloadAgent: new(bytes.Buffer)}

		commandString := fmt.Sprintf("validate -e %s -c %s %s", epssFilename, configFilename, reportFilename)
		_, err := Execute(commandString, cliconfig)

		t.Log(err)
		if !errors.Is(err, ErrorValidation) {
			t.Fatalf("want: %v got: %v", ErrorValidation, err)
		}
	})

	t.Run("success-from-agent", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1, EPSSDenyThreshold: 0.3}}, t)

		cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, KEVDownloadAgent: new(bytes.Buffer), EPSSDownloadAgent: strings.NewReader(sb.String())}

		commandString := fmt.Sprintf("validate --fetch-epss -c %s %s", configFilename, reportFilename)
		_, err := Execute(commandString, cliconfig)

		t.Log(err)
		if !errors.Is(err, ErrorValidation) {
			t.Fatalf("want: %v got: %v", ErrorValidation, err)
		}
	})
	t.Run("error-from-agent", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1, EPSSDenyThreshold: 0.3}}, t)

		str := sb.String() + "cve-5,badvalue,0.20309"
		// str := sb.String()
		cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, KEVDownloadAgent: new(bytes.Buffer), EPSSDownloadAgent: strings.NewReader(str)}

		commandString := fmt.Sprintf("validate --fetch-epss -c %s %s", configFilename, reportFilename)
		_, err := Execute(commandString, cliconfig)

		t.Log(err)
		if err == nil {
			t.Fatal("Expected errors for validation and failed API requests")
		}
	})

	t.Run("file-encoding-error", func(t *testing.T) {
		reportFilename := writeTempAny(&grypeReport, t)
		configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

		cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder, KEVDownloadAgent: new(bytes.Buffer), EPSSDownloadAgent: new(bytes.Buffer)}

		commandString := fmt.Sprintf("validate -e %s -c %s %s", fileWithBadJSON(t), configFilename, reportFilename)
		_, err := Execute(commandString, cliconfig)

		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

}

func TestGetKEVService(t *testing.T) {
	t.Run("file-access", func(t *testing.T) {
		_, err := getKEVService(fileWithBadPermissions(t), nil)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})
}
func TestGetEPSSService(t *testing.T) {
	t.Run("file-access", func(t *testing.T) {
		_, err := getEPSSService(fileWithBadPermissions(t), nil)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})
}

func TestAuditFlag(t *testing.T) {
	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
	}})
	reportFilename := writeTempAny(&grypeReport, t)
	configFilename := writeTempConfig(map[string]any{"grype": grype.Config{Critical: 0, High: -1, Medium: -1, Low: -1, Unknown: -1}}, t)

	commandString := fmt.Sprintf("validate -c %s %s", configFilename, reportFilename)
	cliconfig := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder}
	output, err := Execute(commandString, cliconfig)
	t.Log(output)

	if !errors.Is(err, ErrorValidation) {
		t.Fatalf("want %v got %v", ErrorValidation, err)
	}

	commandString = fmt.Sprintf("validate --audit -c %s %s", configFilename, reportFilename)
	output, err = Execute(commandString, cliconfig)
	t.Log(output)

	if err != nil {
		t.Fatalf("want %v got %v", nil, err)
	}

}

func TestValidateCmd(t *testing.T) {
	fileFunc := func(input string) func(t *testing.T) string {
		return func(t *testing.T) string { return input }
	}

	grypeReport := grype.ScanReport{}
	grypeReport.Descriptor.Name = "grype"
	grypeReport.Matches = append(grypeReport.Matches, models.Match{Vulnerability: models.Vulnerability{
		VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "abc-123", Severity: "Critical"},
	}})
	grypeConfigPass := grype.Config{Critical: -1, High: -1, Low: -1, Medium: -1, Unknown: -1}
	grypeConfigFail := grype.Config{Critical: 0, High: -1, Low: -1, Medium: -1, Unknown: -1}

	semgrepReport := semgrep.ScanReport{Errors: make([]gosemgrep.CliError, 0)}
	semgrepReport.Paths.Scanned = make([]string, 0)
	semgrepReport.Results = append(semgrepReport.Results, gosemgrep.CliMatch{Extra: gosemgrep.CliMatchExtra{Severity: "ERROR", Metadata: gosemgrep.CliMatchExtra{Severity: "ERROR"}}})

	semgrepConfigPass := semgrep.Config{Info: -1, Warning: -1, Error: -1}
	semgrepConfigFail := semgrep.Config{Info: -1, Warning: -1, Error: 0}

	gitleaksReport := gitleaks.ScanReport{
		gitleaks.Finding{Description: "Some desc", Secret: "Some secret", RuleID: "abc-123"},
		gitleaks.Finding{Description: "Some desc 2", Secret: "Some secret 2", RuleID: "abc-124"},
	}

	gitleaksConfigPass := gitleaks.Config{SecretsAllowed: true}
	gitleaksConfigFail := gitleaks.Config{SecretsAllowed: false}

	o, _ := cyclonedx.NewReportDecoder().DecodeFrom(MustOpen(cyclonedxTestReport, t))
	cyclonedxReport := o.(*cyclonedx.ScanReport)
	cyclonedxReport.Vulnerabilities = &[]cdx.Vulnerability{
		{ID: "CVE-2023-1", Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityCritical}}, Affects: &[]cdx.Affects{{Ref: "CVE-2023-1-ref"}}},
		{ID: "CVE-2023-2", Ratings: &[]cdx.VulnerabilityRating{{Severity: cdx.SeverityCritical}}, Affects: &[]cdx.Affects{{Ref: "CVE-2023-3-ref"}}},
	}
	cyclonedxReport.Components = &[]cdx.Component{
		{BOMRef: "CVE-2023-1-ref", Name: "CVE-2023-1-name", Version: "CVE-2023-1-version", Type: cdx.ComponentTypeLibrary},
	}

	cyclondexConfigPass := cyclonedx.Config{Critical: -1, High: -1, Medium: -1, Low: -1, Info: -1, None: -1, Unknown: -1}
	cyclondexConfigFail := cyclonedx.Config{Critical: 0, High: 0, Medium: -1, Low: -1, Info: -1, None: -1, Unknown: -1}

	semgrepFilename := writeTempAny(&semgrepReport, t)
	grypeFilename := writeTempAny(&grypeReport, t)
	gitleaksFilename := writeTempAny(&gitleaksReport, t)
	cyclonedxFilename := writeTempAny(&cyclonedxReport, t)

	configPass := map[string]any{grype.ConfigFieldName: grypeConfigPass, semgrep.ConfigFieldName: semgrepConfigPass, gitleaks.ConfigFieldName: gitleaksConfigPass,
		cyclonedx.ConfigFieldName: cyclondexConfigPass}
	configFail := map[string]any{grype.ConfigFieldName: grypeConfigFail, semgrep.ConfigFieldName: semgrepConfigFail, gitleaks.ConfigFieldName: gitleaksConfigFail,
		cyclonedx.ConfigFieldName: cyclondexConfigFail}

	configPassFilename := writeTempConfig(configPass, t)
	configFailFilename := writeTempConfig(configFail, t)

	bundle := archive.NewBundle()
	_ = bundle.AddFrom(MustOpen(grypeFilename, t), grypeFilename, nil)
	_ = bundle.AddFrom(MustOpen(semgrepFilename, t), semgrepFilename, nil)
	_ = bundle.AddFrom(MustOpen(gitleaksFilename, t), gitleaksFilename, nil)
	_ = bundle.AddFrom(MustOpen(cyclonedxFilename, t), cyclonedxFilename, nil)
	_ = bundle.AddFrom(strings.NewReader("ABCDEF"), "file-1.txt", nil)

	var tempBundleFileFunc = func(t *testing.T) string {
		fPath := path.Join(t.TempDir(), archive.DefaultBundleFilename)
		f := MustCreate(fPath, t)
		_ = archive.NewBundleEncoder(f).Encode(bundle)
		return fPath
	}

	testTable := []struct {
		label      string
		wantErr    error
		reportFunc func(*testing.T) string
		configFunc func(*testing.T) string
	}{
		{label: "grype-pass", wantErr: nil, reportFunc: fileFunc(grypeFilename), configFunc: fileFunc(configPassFilename)},
		{label: "grype-fail", wantErr: ErrorValidation, reportFunc: fileFunc(grypeFilename), configFunc: fileFunc(configFailFilename)},

		{label: "semgrep-pass", wantErr: nil, reportFunc: fileFunc(semgrepFilename), configFunc: fileFunc(configPassFilename)},
		{label: "semgrep-fail", wantErr: ErrorValidation, reportFunc: fileFunc(semgrepFilename), configFunc: fileFunc(configFailFilename)},

		{label: "gitleaks-pass", wantErr: nil, reportFunc: fileFunc(gitleaksFilename), configFunc: fileFunc(configPassFilename)},
		{label: "gitleaks-fail", wantErr: ErrorValidation, reportFunc: fileFunc(gitleaksFilename), configFunc: fileFunc(configFailFilename)},

		{label: "cyclonedx-pass", wantErr: nil, reportFunc: fileFunc(cyclonedxFilename), configFunc: fileFunc(configPassFilename)},
		{label: "cyclonedx-fail", wantErr: ErrorValidation, reportFunc: fileFunc(cyclonedxFilename), configFunc: fileFunc(configFailFilename)},

		{label: "bundle-pass", wantErr: nil, reportFunc: tempBundleFileFunc, configFunc: fileFunc(configPassFilename)},
		{label: "bundle-fail", wantErr: ErrorValidation, reportFunc: tempBundleFileFunc, configFunc: fileFunc(configFailFilename)},

		{label: "bad-object-file", wantErr: ErrorEncoding, reportFunc: fileWithBadPermissions, configFunc: fileWithBadPermissions},
		{label: "bad-config-file", wantErr: ErrorFileAccess, reportFunc: fileFunc(grypeTestReport), configFunc: fileWithBadPermissions},
		{label: "bad-config-file-decode", wantErr: gcv.ErrConfig, reportFunc: fileFunc(grypeTestReport), configFunc: fileWithBadJSON},
		{label: "decode-error", wantErr: ErrorEncoding, reportFunc: fileWithBadJSON, configFunc: fileFunc(configPassFilename)},
	}

	for _, testCase := range testTable {
		// commandString := fmt.Sprintf("validate -c %s %s", fileWithBadPermissions(t), fileWithBadPermissions(t))
		t.Run(testCase.label, func(t *testing.T) {
			report := testCase.reportFunc(t)
			config := testCase.configFunc(t)
			commandString := fmt.Sprintf("validate -c %s %s", config, report)
			output, err := Execute(commandString, CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder})
			t.Log(output)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want %v got %v", testCase.wantErr, err)
			}

		})

	}
}

func NewAsyncDecoder() AsyncDecoder {
	return gce.NewAsyncDecoder(
		grype.NewReportDecoder(),
		semgrep.NewReportDecoder(),
		gitleaks.NewReportDecoder(),
		cyclonedx.NewReportDecoder(),
		archive.NewBundleDecoder(),
	)
}

func writeTempAny(v any, t *testing.T) string {
	filename := path.Join(t.TempDir(), "some-report.json")
	f := MustCreate(filename, t)
	_ = json.NewEncoder(f).Encode(v)
	_ = f.Close()
	return filename
}

func writeTempConfig(configMap map[string]any, t *testing.T) string {
	filename := path.Join(t.TempDir(), "config-pass.yaml")
	configFile := MustCreate(filename, t)
	_ = yaml.NewEncoder(configFile).Encode(configMap)
	_ = configFile.Close()
	return filename
}

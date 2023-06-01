package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/gatecheckdev/gatecheck/pkg/artifact"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"gopkg.in/yaml.v3"
	"math/rand"
	"os"
	"path"
	"testing"
	"time"
)

func TestNewValidateCmd(t *testing.T) {
	t.Run("bad-config", func(t *testing.T) {
		commandString := fmt.Sprintf("validate -c %s %s", fileWithBadPermissions(t), fileWithBadPermissions(t))
		output, err := Execute(commandString, CLIConfig{})

		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("bad-config-decode", func(t *testing.T) {
		commandString := fmt.Sprintf("validate -c %s %s", fileWithBadJSON(t), fileWithBadPermissions(t))
		output, err := Execute(commandString, CLIConfig{})

		if errors.Is(err, ErrorEncoding) != true {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("bad-target", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
		commandString := fmt.Sprintf("validate -c %s %s", configFile, fileWithBadPermissions(t))
		output, err := Execute(commandString, CLIConfig{})

		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("validation-error", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
		commandString := fmt.Sprintf("validate -c %s %s", configFile, gitleaksTestReport)
		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

		if errors.Is(err, ErrorValidation) != true {
			t.Fatal(err)
		}

		t.Run("audit", func(t *testing.T) {
			commandString := fmt.Sprintf("validate --audit -c %s %s", configFile, gitleaksTestReport)
			_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

			if err != nil {
				t.Fatal(err)
			}
		})
	})

	t.Run("success-with-kev", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		config := artifact.NewConfig()
		config.Grype.Critical = 0
		_ = yaml.NewEncoder(f).Encode(config)
		commandString := fmt.Sprintf("validate -k %s -c %s %s",
			kevTestFile, configFile, grypeTestReport)
		output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

		if errors.Is(err, ErrorValidation) != true {
			t.Log(output)
			t.Fatal(err)
		}
	})

	t.Run("with-kev-audit", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		config := artifact.NewConfig()
		config.Grype.Critical = 0
		_ = yaml.NewEncoder(f).Encode(config)
		commandString := fmt.Sprintf("validate --audit -k %s -c %s %s",
			kevTestFile, configFile, grypeTestReport)
		output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

		if err != nil {
			t.Log(output)
			t.Fatal(err)
		}
	})

	t.Run("with-kev-found-vulnerability", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		config := artifact.NewConfig()
		config.Grype.Critical = 0
		_ = yaml.NewEncoder(f).Encode(config)

		var grypeScan artifact.GrypeScanReport
		_ = json.NewDecoder(MustOpen(grypeTestReport, t.Fatal)).Decode(&grypeScan)
		grypeScan.Matches = append(grypeScan.Matches,
			models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}})
		tempGrypeScanFile := path.Join(t.TempDir(), "new-grype-scan.json")
		f, _ = os.Create(tempGrypeScanFile)
		_ = json.NewEncoder(f).Encode(grypeScan)

		kev := artifact.KEVCatalog{Vulnerabilities: []artifact.KEVCatalogVulnerability{
			{CveID: "A"},
		}}
		tempKEVScanFile := path.Join(t.TempDir(), "new-kev.json")
		f, _ = os.Create(tempKEVScanFile)
		_ = json.NewEncoder(f).Encode(kev)

		commandString := fmt.Sprintf("validate -k %s -c %s %s",
			tempKEVScanFile, configFile, tempGrypeScanFile)
		output, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

		if errors.Is(err, ErrorValidation) != true {
			t.Log(output)
			t.Fatal(err)
		}
	})

	t.Run("kev-file-access", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
		commandString := fmt.Sprintf("validate -k %s -c %s %s",
			fileWithBadPermissions(t), configFile, gitleaksTestReport)
		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
	})

	t.Run("kev-bad-decode", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
		commandString := fmt.Sprintf("validate -k %s -c %s %s", fileWithBadJSON(t), configFile, gitleaksTestReport)
		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

		if errors.Is(err, ErrorEncoding) != true {
			t.Fatal(err)
		}
	})

	t.Run("kev-unsupported", func(t *testing.T) {
		configFile := path.Join(t.TempDir(), "gatecheck.yaml")
		f, _ := os.Create(configFile)
		_ = yaml.NewEncoder(f).Encode(artifact.NewConfig())
		commandString := fmt.Sprintf("validate -k %s -c %s %s", kevTestFile, configFile, gitleaksTestReport)
		_, err := Execute(commandString, CLIConfig{AutoDecoderTimeout: time.Second * 3})

		if errors.Is(err, ErrorEncoding) != true {
			t.Fatal(err)
		}
	})
}

func TestNewEPSSCmd(t *testing.T) {
  t.Run("success-from-datastore", func(t *testing.T) {
    
    epssCSV := "../test/epss.csv"

		commandString := fmt.Sprintf("epss %s -f %s", grypeTestReport, epssCSV)

		config := CLIConfig{}

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
  })

	t.Run("success", func(t *testing.T) {
		var grypeScan artifact.GrypeScanReport
		_ = json.NewDecoder(MustOpen(grypeTestReport, t.Fatal)).Decode(&grypeScan)
		grypeScan.Matches = append(grypeScan.Matches,
			models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}})
		tempGrypeScanFile := path.Join(t.TempDir(), "new-grype-scan.json")
		f, _ := os.Create(tempGrypeScanFile)
		_ = json.NewEncoder(f).Encode(grypeScan)

		commandString := fmt.Sprintf("epss %s", tempGrypeScanFile)
		config := CLIConfig{EPSSService: mockEPSSService{returnError: nil, returnData: []epss.Data{
			{CVE: "A", EPSS: "B", Percentile: "32", Date: "may 3, 2023", Severity: "Critical", URL: "github.com"},
		}}}

		output, err := Execute(commandString, config)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(output)
	})

	t.Run("bad-file", func(t *testing.T) {
		commandString := fmt.Sprintf("epss %s", fileWithBadPermissions(t))
		output, err := Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-file-decode", func(t *testing.T) {
		commandString := fmt.Sprintf("epss %s", fileWithBadJSON(t))
		output, err := Execute(commandString, CLIConfig{EPSSService: mockEPSSService{}})
		if errors.Is(err, ErrorEncoding) != true {
			t.Fatal(err)
		}
		t.Log(output)
	})

	t.Run("bad-file-decode", func(t *testing.T) {
		var grypeScan artifact.GrypeScanReport
		_ = json.NewDecoder(MustOpen(grypeTestReport, t.Fatal)).Decode(&grypeScan)
		grypeScan.Matches = append(grypeScan.Matches,
			models.Match{Vulnerability: models.Vulnerability{VulnerabilityMetadata: models.VulnerabilityMetadata{ID: "A"}}})
		tempGrypeScanFile := path.Join(t.TempDir(), "new-grype-scan.json")
		f, _ := os.Create(tempGrypeScanFile)
		_ = json.NewEncoder(f).Encode(grypeScan)

		commandString := fmt.Sprintf("epss %s", tempGrypeScanFile)
		config := CLIConfig{EPSSService: mockEPSSService{returnError: errors.New("mock error")}}
		output, err := Execute(commandString, config)

		if errors.Is(err, ErrorAPI) != true {
			t.Fatal(err)
		}

		t.Log(output)
	})

}

func TestParseAndValidate(t *testing.T) {
	const timeout = time.Second * 3
	t.Run("timeout", func(t *testing.T) {
		b := make([]byte, 10_000)
		rand.Read(b)
		err := ParseAndValidate(bytes.NewBuffer(b), *artifact.NewConfig(), time.Nanosecond)
		if errors.Is(err, context.Canceled) != true {
			t.Fatal(err)
		}
	})
	t.Run("semgrep", func(t *testing.T) {
		config := artifact.NewConfig()
		config.Semgrep = nil
		err := ParseAndValidate(MustOpen(semgrepTestReport, t.Fatal), *config, timeout)
		if err == nil {
			t.Fatal("Expected error for missing configuration")
		}
		config.Semgrep = artifact.NewConfig().Semgrep
		err = ParseAndValidate(MustOpen(semgrepTestReport, t.Fatal), *config, timeout)
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("grype", func(t *testing.T) {
		config := artifact.NewConfig()
		config.Grype = nil
		err := ParseAndValidate(MustOpen(grypeTestReport, t.Fatal), *config, timeout)
		if err == nil {
			t.Fatal("Expected error for missing configuration")
		}
		config.Grype = artifact.NewConfig().Grype
		err = ParseAndValidate(MustOpen(grypeTestReport, t.Fatal), *config, timeout)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("gitleaks", func(t *testing.T) {
		config := artifact.NewConfig()
		config.Gitleaks = nil
		err := ParseAndValidate(MustOpen(gitleaksTestReport, t.Fatal), *config, timeout)
		if err == nil {
			t.Fatal("Expected error for missing configuration")
		}

		config.Gitleaks = artifact.NewConfig().Gitleaks
		config.Gitleaks.SecretsAllowed = true
		err = ParseAndValidate(MustOpen(gitleaksTestReport, t.Fatal), *config, timeout)
		if err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		b := make([]byte, 10_000)
		rand.Read(b)
		err := ParseAndValidate(bytes.NewBuffer(b), *artifact.NewConfig(), timeout)
		if err == nil {
			t.Fatal("Expected error for missing configuration")
		}
	})

}

func TestParseAndValidate_bundle(t *testing.T) {

	grypeArtifact, _ := artifact.NewArtifact("grype", MustOpen(grypeTestReport, t.Fatal))
	semgrepArtifact, _ := artifact.NewArtifact("semgrep", MustOpen(semgrepTestReport, t.Fatal))
	gitleaksArtifact, _ := artifact.NewArtifact("gitleaks", MustOpen(gitleaksTestReport, t.Fatal))

	bundle := artifact.NewBundle()
	_ = bundle.Add(grypeArtifact, semgrepArtifact, gitleaksArtifact)

	t.Run("fail-validation", func(t *testing.T) {

		config := artifact.NewConfig()
		config.Grype.Critical = 0
		config.Semgrep.Error = 0
		config.Gitleaks.SecretsAllowed = false

		buf := new(bytes.Buffer)
		_ = artifact.NewBundleEncoder(buf).Encode(bundle)
		err := ParseAndValidate(buf, *config, time.Second*3)

		if err == nil {
			t.Fatal("expected error for failed validation")
		}

		t.Log(err)
	})

	t.Run("pass-validation", func(t *testing.T) {

		config := artifact.NewConfig()
		config.Gitleaks.SecretsAllowed = true

		buf := new(bytes.Buffer)
		_ = artifact.NewBundleEncoder(buf).Encode(bundle)
		err := ParseAndValidate(buf, *config, time.Second*3)

		if err != nil {
			t.Fatal(err)
		}

		t.Log(err)
	})

}

type mockEPSSService struct {
	returnError error
	returnData  []epss.Data
}

func (m mockEPSSService) Get(_ []epss.CVE) ([]epss.Data, error) {
	return m.returnData, m.returnError
}

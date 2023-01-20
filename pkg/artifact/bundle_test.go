package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"gopkg.in/yaml.v3"
	"math/rand"
	"strings"
	"testing"
)

func TestNewBundle(t *testing.T) {
	bun := FullBundle()

	testables := []Artifact{bun.GrypeScan, bun.SemgrepScan, bun.GitleaksScan, bun.Generic["random.file"]}
	for _, v := range testables {
		if len(v.DigestString()) != 64 {
			t.Log(bun)
			t.Fatal(v)
		}
	}

	t.Run("Fail", func(t *testing.T) {
		bun := NewBundle()

		if err := bun.Add(Artifact{}); err == nil {
			t.Fatal("Expected error for missing label")
		}
	})

	t.Run("String", func(t *testing.T) {
		t.Log(bun.String())
		if strings.Contains(bun.String(), "grype-report.json") == false {
			t.Fatal("Expected grype-report.json in ", bun.String())
		}
		if strings.Contains(bun.String(), "semgrep-sast-report.json") == false {
			t.Fatal("Expected semgrep-sast-report.json in ", bun.String())
		}
		if strings.Contains(bun.String(), "gitleaks-report.json") == false {
			t.Fatal("Expected gitleaks-report.json in ", bun.String())
		}
		if strings.Contains(bun.String(), "random.file") == false {
			t.Fatal("Expected random.file in ", bun.String())
		}
	})

	t.Run("Validation", func(t *testing.T) {
		t.Parallel()
		t.Run("grype", func(t *testing.T) {
			if err := bun.ValidateGrype(&GrypeConfig{Critical: 0}); errors.Is(err, GrypeValidationFailed) != true {
				t.Fatal("Expected validation to fail")
			}
			if err := bun.ValidateGrype(NewConfig().Grype); err != nil {
				t.Fatal("Expected validation to pass")
			}

			// No configuration passed
			if err := bun.ValidateGrype(nil); err != nil {
				t.FailNow()
			}
			// No grype scan content
			if err := NewBundle().ValidateGrype(&GrypeConfig{Critical: 0}); err != nil {
				t.FailNow()
			}
			badBundle := NewBundle()
			badBundle.GrypeScan.Content = []byte("{{{")
			if err := badBundle.ValidateGrype(&GrypeConfig{Critical: 0}); err == nil {
				t.Fatal("Expected error for bad unmarshal")
			}
		})
		t.Run("semgrep", func(t *testing.T) {
			if err := bun.ValidateSemgrep(&SemgrepConfig{Error: 0}); errors.Is(err, SemgrepFailedValidation) != true {
				t.Fatal("Expected validation to fail")
			}
			if err := bun.ValidateSemgrep(NewConfig().Semgrep); err != nil {
				t.Fatal("Expected validation to pass")
			}
			// No configuration passed
			if err := bun.ValidateSemgrep(nil); err != nil {
				t.FailNow()
			}
			// No grype scan content
			if err := NewBundle().ValidateSemgrep(&SemgrepConfig{Error: 0}); err != nil {
				t.FailNow()
			}
			badBundle := NewBundle()
			badBundle.SemgrepScan.Content = []byte("{{{")
			if err := badBundle.ValidateSemgrep(&SemgrepConfig{Error: 0}); err == nil {
				t.Fatal("Expected error for bad unmarshal")
			}
		})
		t.Run("gitleaks", func(t *testing.T) {
			if err := bun.ValidateGitleaks(&GitleaksConfig{SecretsAllowed: false}); errors.Is(err, GitleaksValidationFailed) != true {
				t.Fatal("Expected validation to fail")
			}
			if err := bun.ValidateGitleaks(&GitleaksConfig{SecretsAllowed: true}); err != nil {
				t.Fatal("Expected validation to pass")
			}
			// No configuration passed
			if err := bun.ValidateGitleaks(nil); err != nil {
				t.FailNow()
			}
			// No grype scan content
			if err := NewBundle().ValidateGitleaks(&GitleaksConfig{SecretsAllowed: false}); err != nil {
				t.FailNow()
			}
			badBundle := NewBundle()
			badBundle.GitleaksScan.Content = []byte("{{{")
			if err := badBundle.ValidateGitleaks(&GitleaksConfig{SecretsAllowed: false}); err == nil {
				t.Fatal("Expected error for bad unmarshal")
			}
		})

	})
}

func TestBundleEncoding(t *testing.T) {
	bundle1 := FullBundle()
	bundle1.PipelineID = "ABC-123"
	bundle1.PipelineURL = "http://gatecheck.dev/pipeline-url"
	bundle1.ProjectName = "Test Project"

	buf := new(bytes.Buffer)
	if err := NewBundleEncoder(buf).Encode(bundle1); err != nil {
		t.Fatal(err)
	}

	bundle2 := NewBundle()

	if err := NewBundleDecoder(buf).Decode(bundle2); err != nil {
		t.Fatal(err)
	}

	if bundle2.ProjectName != bundle1.ProjectName {
		t.Log(bundle2)
		t.Fatal("Project Names don't match")
	}

	if bundle2.PipelineID != bundle1.PipelineID {
		t.Log(bundle2)
		t.Fatal("Pipeline IDs don't match")
	}

	if bundle2.PipelineURL != bundle1.PipelineURL {
		t.Log(bundle2)
		t.Fatal("Pipeline URLs don't match")
	}

	if bundle1.GrypeScan.DigestString() != bundle2.GrypeScan.DigestString() {
		t.Fatal("Grype Scan Digests don't match")
	}

	if bundle1.SemgrepScan.DigestString() != bundle2.SemgrepScan.DigestString() {
		t.Fatal("Semgrep Scan Digests don't match")
	}

	if bundle1.GitleaksScan.DigestString() != bundle2.GitleaksScan.DigestString() {
		t.Fatal("Gitleaks Scan Digests don't match")
	}

	if bundle1.Generic["random.file"].DigestString() != bundle2.Generic["random.file"].DigestString() {
		t.Fatal("Random File, generic Digests don't match")
	}

	t.Run("bad-io", func(t *testing.T) {
		if err := NewBundleDecoder(&badReadWriter{}).Decode(bundle1); err == nil {
			t.Fatal("Expected decoding error")
		}
		if err := NewBundleDecoder(bytes.NewBufferString("{{")).Decode(&Bundle{}); err == nil {
			t.Fatal("Expected decoding error during io copy")
		}
		if err := NewBundleEncoder(&badReadWriter{}).Encode(bundle1); err == nil {
			t.Fatal("Expected encoding error")
		}
		if err := NewBundleEncoder(new(bytes.Buffer)).Encode(nil); err == nil {
			t.Fatal("Expected encoding error")
		}
	})
}

func TestArtifact_String(t *testing.T) {
	b := make([]byte, 1_000_000)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	art, err := NewArtifact("some file", bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(art.String(), "1.0 MB") == false {
		t.Log("Expected 1.0 MB in string")
		t.Fatal(art.String())
	}
}

func TestDecoding(t *testing.T) {
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(&sample{FieldOne: "sample"})
	if DecodeJSON[sample](buf).FieldOne != "sample" {
		t.Fatal("JSON Decoding failed")
	}
	buf = new(bytes.Buffer)
	_ = yaml.NewEncoder(buf).Encode(&sample{FieldOne: "sample"})
	t.Log(buf.String())
	if DecodeYAML[sample](buf).FieldOne != "sample" {
		t.Fatal("YAML Decoding failed")
	}
	buf = new(bytes.Buffer)
	bundle := NewBundle()
	bundle.PipelineID = "ABC-123"
	_ = NewBundleEncoder(buf).Encode(bundle)
	if DecodeBundle(buf).PipelineID != "ABC-123" {
		t.Fatal("bundle decoding failed")
	}
}

// Test Resources
type sample struct {
	FieldOne string `json:"field_one" yaml:"field_one"`
}

func FullBundle() *Bundle {
	var panicFunc = func(args ...any) {
		panic(args)
	}

	grypeBytes := MustReadFile("../../test/grype-report.json", panicFunc)
	semgrepBytes := MustReadFile("../../test/semgrep-sast-report.json", panicFunc)
	gitleaksBytes := MustReadFile("../../test/gitleaks-report.json", panicFunc)
	b := make([]byte, 1_000_000)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	grypeArtifact, _ := NewArtifact("grype-report.json", bytes.NewBuffer(grypeBytes))
	semgrepArtifact, _ := NewArtifact("semgrep-sast-report.json", bytes.NewBuffer(semgrepBytes))
	gitleaksArtifact, _ := NewArtifact("gitleaks-report.json", bytes.NewBuffer(gitleaksBytes))
	randomArtifact, _ := NewArtifact("random.file", bytes.NewBuffer(b))

	bundle1 := NewBundle()
	if err := bundle1.Add(grypeArtifact, semgrepArtifact, gitleaksArtifact, randomArtifact); err != nil {
		panic(err)
	}

	return bundle1
}

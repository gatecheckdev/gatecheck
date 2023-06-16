package validate

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"gopkg.in/yaml.v3"
)

func TestValidate(t *testing.T) {

	validator := NewValidator[MockReport, MockConfig]("report",
		gce.NewJSONWriterDecoder[MockReport]("Mock Report", func(mr *MockReport) error { return nil }),
		mockReportValidateFunc)

	report := &MockReport{ValueA: 10}

	t.Run("success-fail-validation", func(t *testing.T) {
		config := &MockConfig{ValueALimit: 5}

		configReader := bytes.NewBuffer(MarshalConfig("report", config, t))

		err := validator.Validate(report, configReader)
		if !errors.Is(err, ErrValidation) {
			t.Fatalf("want: %v got: %v", ErrValidation, err)
		}
	})
	t.Run("success-pass-validation", func(t *testing.T) {
		config := &MockConfig{ValueALimit: 15}

		configReader := bytes.NewBuffer(MarshalConfig("report", config, t))

		err := validator.Validate(report, configReader)
		if !errors.Is(err, nil) {
			t.Fatalf("want: %v got: %v", ErrValidation, err)
		}
	})

	t.Run("validate-from", func(t *testing.T) {
		config := &MockConfig{ValueALimit: 15}

		configReader := bytes.NewBuffer(MarshalConfig("report", config, t))
		reportReader := bytes.NewBuffer(MustMarshalJSON(report, t))

		err := validator.ValidateFrom(reportReader, configReader)
		if !errors.Is(err, nil) {
			t.Fatalf("want: %v got: %v", ErrValidation, err)
		}
	})

	t.Run("bad-decode-obj", func(t *testing.T) {
		err := validator.ValidateFrom(strings.NewReader("{{{"), strings.NewReader("{{["))
		if !errors.Is(err, ErrInput) {
			t.Fatalf("want: %v got: %v", ErrInput, err)
		}
	})

	t.Run("bad-decode-config", func(t *testing.T) {
		err := validator.Validate(report, strings.NewReader("{{["))
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("want: %v got: %v", ErrConfig, err)
		}
	})

	t.Run("missing-config", func(t *testing.T) {
		config := &MockConfig{ValueALimit: 15}
		configReader := bytes.NewBuffer(MarshalConfig("another-field-not-report", config, t))
		err := validator.Validate(report, configReader)
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("want: %v got: %v", ErrConfig, err)
		}
	})

	t.Run("invalid-config-obj", func(t *testing.T) {

		badObj := make(map[string]bool)
		badObj["value"] = true
		objectReader := bytes.NewBuffer(MarshalConfig("report", badObj, t))

		config := &MockConfig{ValueALimit: 15}
		configReader := bytes.NewBuffer(MarshalConfig("report", config, t))

		err := validator.Validate(objectReader, configReader)
		if !errors.Is(err, ErrInput) {
			t.Fatalf("want: %v got: %v", ErrInput, err)
		}

	})

}

type MockReport struct {
	ValueA int
}

type MockConfig struct {
	ValueALimit int `yaml:"valueALimit"`
}

func mockReportValidateFunc(r MockReport, c MockConfig) error {
	if r.ValueA > c.ValueALimit {
		return ErrValidation
	}
	return nil
}

func MustMarshalJSON(v any, t *testing.T) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func MarshalConfig(fieldname string, v any, t *testing.T) []byte {
	configMap := make(map[string]any)
	configMap[fieldname] = v

	b, err := yaml.Marshal(configMap)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

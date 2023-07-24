package validate

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestValidateFunc(t *testing.T) {
	sample := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	err := ValidateFunc(sample, func(value int) error {
		isEven := value%2 == 0
		if isEven {
			return nil
		}
		return NewFailedRuleError("must be even", fmt.Sprint(value))
	})
	t.Log(err)
	if !errors.Is(err, ErrFailedRule) {
		t.Fatalf("want: %v got: %v", ErrFailedRule, err)
	}
}

type mockConfig struct {
	Enabled bool `yaml:"enabled"`
}

func isEven(values []int, config mockConfig) error {
	if !config.Enabled {
		return nil
	}
	return ValidateFunc(values, func(value int) error {
		if value%2 == 0 {
			return nil
		}
		return NewFailedRuleError("must be even", fmt.Sprint(value))
	})
}

func underFive(values []int, config mockConfig) error {
	if !config.Enabled {
		return nil
	}
	return ValidateFunc(values, func(value int) error {
		if value < 5 {
			return nil
		}
		return NewFailedRuleError("must be less than 5", fmt.Sprint(value))
	})
}

func TestValidator(t *testing.T) {
	sample := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	validator := NewValidator[int, mockConfig]()
	validator = validator.WithValidationRules(isEven, underFive)
	validator = validator.WithAllowRules(func(i int, _ mockConfig) bool { return i == 5 })

	t.Run("success", func(t *testing.T) {
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(map[string]any{"config": mockConfig{Enabled: true}})
		err := validator.ReadConfigAndValidate(sample, configBuf, "config")
		t.Log(err)
	})
	t.Run("bad-config", func(t *testing.T) {
		configBuf := new(bytes.Buffer)
		_ = yaml.NewEncoder(configBuf).Encode(map[string]any{"config": mockConfig{Enabled: true}})
		err := validator.ReadConfigAndValidate(sample, configBuf, "someotherfield")
		t.Log(err)
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("want: %v got: %v", ErrConfig, err)
		}
	})
	t.Run("bad-config-encoding", func(t *testing.T) {
		configBuf := strings.NewReader("{{{")
		err := validator.ReadConfigAndValidate(sample, configBuf, "someotherfield")
		t.Log(err)
		if !errors.Is(err, ErrConfig) {
			t.Fatalf("want: %v got: %v", ErrConfig, err)
		}
	})
}

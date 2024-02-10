// Package validate provides a generic implementation for any object type using validation rules
package validate

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"gopkg.in/yaml.v3"
)

// ErrFailedRule return this error if an object fails a validation rule
var ErrFailedRule = errors.New("Failed Rule")

// ErrConfig return this error if the configuration file is invalid
var ErrConfig = errors.New("cannot validate, invalid configuration")

// NewFailedRuleError convenience function for error wrapping
func NewFailedRuleError(rule string, id string) error {
	return fmt.Errorf("%w: %v: %s", ErrFailedRule, rule, id)
}

// DenyFunc generic execution of a check function over a slice of objects
func DenyFunc[S ~[]E, E any](target S, check func(E) error) error {
	var errs error
	for _, element := range target {
		errs = errors.Join(errs, check(element))
	}
	return errs
}

// Validator generic validation runner
type Validator[ObjectT any, ConfigT any] struct {
	validationRules []func([]ObjectT, ConfigT) error
	allowListRules  []func(ObjectT, ConfigT) bool
}

// WithValidationRules define the fail validation rules, all must pass
func (v Validator[ObjectT, ConfigT]) WithValidationRules(rules ...func([]ObjectT, ConfigT) error) Validator[ObjectT, ConfigT] {
	v.validationRules = append(v.validationRules, rules...)
	return v
}

// WithAllowRules define the allow rules which will skip validation
func (v Validator[ObjectT, ConfigT]) WithAllowRules(rules ...func(ObjectT, ConfigT) bool) Validator[ObjectT, ConfigT] {
	v.allowListRules = append(v.allowListRules, rules...)
	return v
}

// NewValidator used to create specific implementations of a validator
func NewValidator[ObjectT any, ConfigT any]() Validator[ObjectT, ConfigT] {
	return Validator[ObjectT, ConfigT]{}
}

// Validate run validation rules on a slice of objects
func (v Validator[ObjectT, ConfigT]) Validate(objects []ObjectT, config ConfigT) error {
	var errs error
	filteredObjects := slices.DeleteFunc(objects, func(obj ObjectT) bool {
		for _, allow := range v.allowListRules {
			if allow(obj, config) {
				return true
			}
		}
		return false
	})

	oCount := len(objects) - len(filteredObjects)
	filteredCount := len(filteredObjects)
	slog.Debug("validation", "object_count", oCount, "allowed_count", filteredCount)
	for _, validate := range v.validationRules {
		errs = errors.Join(errs, validate(filteredObjects, config))
	}

	return errs
}

// ReadConfigAndValidate validate after decoding the configuration object
func (v Validator[ObjectT, ConfigT]) ReadConfigAndValidate(objects []ObjectT, configReader io.Reader, field string) error {
	config, err := ConfigByField[ConfigT](configReader, field)
	if err != nil {
		return err
	}
	return v.Validate(objects, config)
}

// ConfigByField get the config field name after decoding
func ConfigByField[T any](configReader io.Reader, fieldname string) (T, error) {
	configMap := make(map[string]T)
	nilObj := *new(T)

	if err := yaml.NewDecoder(configReader).Decode(configMap); err != nil {
		return nilObj, fmt.Errorf("%w: %v", ErrConfig, err)
	}

	c, ok := configMap[fieldname]
	if !ok {
		return nilObj, fmt.Errorf("%w: No configuration provided for field '%s'", ErrConfig, fieldname)
	}
	return c, nil
}

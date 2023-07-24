package validate

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"
)

var ErrFailedRule = errors.New("Failed Rule")

func NewFailedRuleError(rule string, id string) error {
	return fmt.Errorf("%w: %v: %s", ErrFailedRule, rule, id)
}

func ValidateFunc[S ~[]E, E any](target S, check func(E) error) error {
	var errs error
	for _, element := range target {
		errs = errors.Join(errs, check(element))
	}
	return errs
}

var ErrConfig = errors.New("cannot validate, invalid configuration")

type Validator[ObjectT any, ConfigT any] struct {
	validationRules []func([]ObjectT, ConfigT) error
	allowListRules  []func(ObjectT, ConfigT) bool
}

func (v Validator[ObjectT, ConfigT]) WithValidationRules(rules ...func([]ObjectT, ConfigT) error) Validator[ObjectT, ConfigT] {
	v.validationRules = append(v.validationRules, rules...)
	return v
}

func (v Validator[ObjectT, ConfigT]) WithAllowRules(rules ...func(ObjectT, ConfigT) bool) Validator[ObjectT, ConfigT] {
	v.allowListRules = append(v.allowListRules, rules...)
	return v
}

func NewValidator[ObjectT any, ConfigT any]() Validator[ObjectT, ConfigT] {
	return Validator[ObjectT, ConfigT]{}
}

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

	for _, validate := range v.validationRules {
		errs = errors.Join(errs, validate(filteredObjects, config))
	}

	return errs
}

func (v Validator[ObjectT, ConfigT]) ReadConfigAndValidate(objects []ObjectT, configReader io.Reader, field string) error {
	config, err := ConfigByField[ConfigT](configReader, field)
	if err != nil {
		return err
	}
	return v.Validate(objects, config)
}

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

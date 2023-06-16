package validate

import (
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

var ErrValidation = errors.New("Violation")
var ErrInput = errors.New("cannot validate, invalid object to be validatated")
var ErrConfig = errors.New("cannot validate, invalid configuration")

type WriterDecoder interface {
	io.Writer
	Decode() (any, error)
	DecodeFrom(io.Reader) (any, error)
}

type Validator[ObjectT any, ConfigT any] struct {
	objDecoder       WriterDecoder
	configFieldName  string
	validateFunction func(ObjectT, ConfigT) error
}

func NewValidator[ObjectT any, ConfigT any](configFieldName string, objectDecoder WriterDecoder, validateFunc func(ObjectT, ConfigT) error) *Validator[ObjectT, ConfigT] {
	return &Validator[ObjectT, ConfigT]{
		configFieldName:  configFieldName,
		objDecoder:       objectDecoder,
		validateFunction: validateFunc,
	}
}

func (v *Validator[ObjectT, ConfigT]) Validate(objPtr any, configReader io.Reader) error {
	c, err := ConfigByField[ConfigT](configReader, v.configFieldName)
	if err != nil {
		return err
	}
	o, ok := objPtr.(*ObjectT)
	if !ok {
		return fmt.Errorf("%w: Invalid object type '%T'", ErrInput, objPtr)
	}
	return v.validateFunction(*o, c)
}

func (v *Validator[ObjectT, ConfigT]) ValidateFrom(objReader io.Reader, configReader io.Reader) error {
	o, err := v.objDecoder.DecodeFrom(objReader)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInput, err)
	}

	return v.Validate(o, configReader)
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

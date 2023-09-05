package encoding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"
)

// ErrEncoding any errors decoding/encoding
var ErrEncoding = errors.New("encoding error")

// ErrIO any errors from reading/writing
var ErrIO = errors.New("input/output error")

// ErrFailedCheck use for simple validation to differentiate field values for formatting
var ErrFailedCheck = errors.New("object field check failed")

// JSONWriterDecoder decodes JSON and runs a provided check function
type JSONWriterDecoder[T any] struct {
	bytes.Buffer
	checkFunc func(*T) error
	fileType  string
}

// NewJSONWriterDecoder generic implementation, use to create a specific implementation
func NewJSONWriterDecoder[T any](fileType string, check func(*T) error) *JSONWriterDecoder[T] {
	return &JSONWriterDecoder[T]{
		checkFunc: check,
		fileType:  fileType,
	}
}

// Decode run the decoding and check function
func (d *JSONWriterDecoder[T]) Decode() (any, error) {
	obj := new(T)
	err := json.NewDecoder(d).Decode(obj)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return obj, d.checkFunc(obj)
}

// DecodeFrom see Decode
func (d *JSONWriterDecoder[T]) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIO, err)
	}
	return d.Decode()
}

// FileType plain text file type
func (d *JSONWriterDecoder[T]) FileType() string {
	return d.fileType
}

// YAMLWriterDecoder see JSONWriterDecoder, this implementation is the same but for YAML
type YAMLWriterDecoder[T any] struct {
	bytes.Buffer
	checkFunc func(*T) error
	fileType  string
}

// NewYAMLWriterDecoder use to create a yaml decoder
func NewYAMLWriterDecoder[T any](fileType string, check func(*T) error) *YAMLWriterDecoder[T] {
	return &YAMLWriterDecoder[T]{
		checkFunc: check,
		fileType:  fileType,
	}
}

// Decode run the decoding and check function
func (d *YAMLWriterDecoder[T]) Decode() (any, error) {
	obj := new(T)
	err := yaml.NewDecoder(d).Decode(obj)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEncoding, err)
	}
	return obj, d.checkFunc(obj)
}

// DecodeFrom see Decode
func (d *YAMLWriterDecoder[T]) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIO, err)
	}
	return d.Decode()
}

// FileType plain text provided file type after decoding
func (d *YAMLWriterDecoder[T]) FileType() string {
	return d.fileType
}

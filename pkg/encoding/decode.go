package encoding

import (
	"encoding/json"
	"io"
)

// DecodeJSON if the type is known and decode error is unexpected. Intended to be paired with Inspect
func DecodeJSON[T any](r io.Reader) T {
	v := new(T)
	_ = json.NewDecoder(r).Decode(v)
	return *v
}

// DecodeYAML if the type is known and decode error is unexpected. Intended to be paired with Inspect
func DecodeYAML[T any](r io.Reader) T {
	v := new(T)
	_ = json.NewDecoder(r).Decode(v)
	return *v
}

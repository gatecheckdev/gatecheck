package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"gopkg.in/yaml.v3"
	"io"
	"sync"
)

type Type string

const (
	Gitleaks        Type = "Gitleaks"
	Grype           Type = "Grype"
	Semgrep         Type = "Semgrep"
	GatecheckBundle Type = "Gatecheck Bundle"
	GatecheckConfig Type = "Gatecheck Config"
	Unsupported     Type = "Unsupported"
)

// Inspect will attempt to decode into all report types and return the one that worked.
// Warning: this function is prone to hanging if a bad reader is supplied, use InspectWithContext unless
// reader can be guaranteed not to hang. Very small performance bump over InspectWithContext
func Inspect(r io.Reader) (Type, error) {
	// Errors caught in detectBytes
	inputBytes, _ := io.ReadAll(r)
	return detectBytes(inputBytes)
}

// InspectWithContext calls Inspect with the ability to cancel which prevents hanging when running go routines
func InspectWithContext(ctx context.Context, r io.Reader) (Type, error) {
	// based on benchmarking, the async solution is twice as fast when there are at least 3 decoder functions
	var reportType Type
	var err error
	c := make(chan struct{}, 1)

	go func() {
		// Errors caught in detectBytes
		inputBytes, _ := io.ReadAll(r)
		reportType, err = detectBytes(inputBytes)
		c <- struct{}{}
	}()

	select {
	case <-c: // function ran successfully
		return reportType, err
	case <-ctx.Done(): // Context was canceled before go routine could finish
		return Unsupported, context.Canceled
	}
}

// Read bytes from a reader and inspect the report type. Use ReadWithContext for the option to timeout
func Read(r io.Reader) (Type, []byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return Unsupported, data, err
	}
	rType, err := detectBytes(data)
	return rType, data, err
}

// ReadWithContext same as Read but enables the ability to cancel early via Context to prevent hanging
func ReadWithContext(ctx context.Context, r io.Reader) (Type, []byte, error) {
	var target []byte
	var err error
	var entityType = Unsupported

	c := make(chan struct{}, 1)

	go func() {
		target, err = io.ReadAll(r)
		if err != nil {
			c <- struct{}{}
			return
		}
		entityType, err = detectBytes(target)
		c <- struct{}{}
	}()

	select {
	case <-c: // goroutine is done
		return entityType, target, err
	case <-ctx.Done(): // Context was canceled before go routine could finish
		return Unsupported, nil, context.Canceled
	}
}

// DecodeJSON if the type is known and decode error is unexpected. Intended to be paired with Inspect
func DecodeJSON[T any](r io.Reader) T {
	v := new(T)
	_ = json.NewDecoder(r).Decode(v)
	return *v
}

// DecodeYAML if the type is known and decode error is unexpected. Intended to be paired with Inspect
func DecodeYAML[T any](r io.Reader) T {
	v := new(T)
	_ = yaml.NewDecoder(r).Decode(v)
	return *v
}

// DecodeBundle without checking for a decode error. Intended to be paired with Inspect
func DecodeBundle(r io.Reader) Bundle {
	bun := NewBundle()
	_ = NewBundleDecoder(r).Decode(bun)
	return *bun
}

func detectBytes(inputBytes []byte) (Type, error) {
	var wg sync.WaitGroup
	resChan := make(chan Type, 1)

	decodeFuncs := []func([]byte) Type{detectGitleaksBytes, detectSemgrepBytes, detectGrypeBytes,
		detectBundleBytes, detectConfigBytes}

	// Try each decoder at the same time
	for _, v := range decodeFuncs {
		wg.Add(1)
		go func(decodeFunc func([]byte) Type) {
			defer wg.Done()
			reportType := decodeFunc(inputBytes)
			if reportType != Unsupported {
				resChan <- reportType
			}
		}(v)
	}

	// Wait for all decoders to run, this catches the case that none of them worked
	go func() {
		wg.Wait()
		resChan <- Unsupported
	}()

	// Wait for a response from either one of the decoders or for all of them to run and fail
	response := <-resChan

	return response, nil
}

func detectGitleaksBytes(b []byte) Type {
	var gitleaksScan GitleaksScanReport

	// Gitleaks with no findings will be '[]'
	if string(b) == "[]" {
		return Gitleaks
	}

	if err := json.Unmarshal(b, &gitleaksScan); err != nil {
		return Unsupported
	}

	return Gitleaks
}

func detectSemgrepBytes(b []byte) Type {
	var semgrepScan SemgrepScanReport

	if err := json.Unmarshal(b, &semgrepScan); err != nil {
		return Unsupported
	}

	if semgrepScan.Version == nil {
		return Unsupported
	}

	return Semgrep
}

func detectGrypeBytes(b []byte) Type {
	var grypeScan GrypeScanReport

	if err := json.Unmarshal(b, &grypeScan); err != nil {
		return Unsupported
	}

	if grypeScan.Source == nil {
		return Unsupported
	}

	return Grype
}

func detectBundleBytes(b []byte) Type {
	var bun Bundle
	if err := NewBundleDecoder(bytes.NewBuffer(b)).Decode(&bun); err != nil {
		return Unsupported
	}

	// No need for verification since it uses a custom decoder
	return GatecheckBundle
}

func detectConfigBytes(b []byte) Type {
	var config Config
	if err := yaml.Unmarshal(b, &config); err != nil {
		return Unsupported
	}

	if config.Grype != nil || config.Semgrep != nil || config.Gitleaks != nil {
		return GatecheckConfig
	}

	return Unsupported
}

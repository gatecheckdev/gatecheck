package encoding

import (
	"context"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"io"
	"sync"
)

// Read bytes from a reader and inspect the report type. Use ReadWithContext for the option to timeout
func Read(r io.Reader) (EntityType, []byte, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return Unsupported, data, err
	}
	rType, err := detectBytes(data)
	return rType, data, err
}

// ReadWithContext same as Read but enables the ability to cancel early via Context to prevent hanging
func ReadWithContext(ctx context.Context, r io.Reader) (EntityType, []byte, error) {
	var target []byte
	var err error
	var reportType = Unsupported

	c := make(chan struct{}, 1)

	go func() {
		target, err = io.ReadAll(r)
		if err != nil {
			c <- struct{}{}
			return
		}
		reportType, err = detectBytes(target)
		c <- struct{}{}
	}()

	select {
	case <-c: // goroutine is done
		return reportType, target, err
	case <-ctx.Done(): // Context was canceled before go routine could finish
		return Unsupported, nil, context.Canceled
	}
}

func detectBytes(inputBytes []byte) (EntityType, error) {
	var wg sync.WaitGroup
	resChan := make(chan EntityType, 1)

	decodeFuncs := []func([]byte) EntityType{detectGitleaksBytes, detectSemgrepBytes, detectGrypeBytes}

	// Try each decoder at the same time
	for _, v := range decodeFuncs {
		wg.Add(1)
		go func(decodeFunc func([]byte) EntityType) {
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

func detectGitleaksBytes(b []byte) EntityType {
	var gitleaksScan entity.GitLeaksScanReport

	// Gitleaks with no findings will be '[]'
	if string(b) == "[]" {
		return Gitleaks
	}

	if err := json.Unmarshal(b, &gitleaksScan); err != nil {
		return Unsupported
	}

	if len(gitleaksScan) <= 1 {
		return Unsupported
	}

	return Gitleaks
}

func detectSemgrepBytes(b []byte) EntityType {
	var semgrepScan entity.SemgrepScanReport

	if err := json.Unmarshal(b, &semgrepScan); err != nil {
		return Unsupported
	}

	if semgrepScan.Version == "" {
		return Unsupported
	}

	return Semgrep
}

func detectGrypeBytes(b []byte) EntityType {
	var grypeScan entity.GrypeScanReport

	if err := json.Unmarshal(b, &grypeScan); err != nil {
		return Unsupported
	}

	if grypeScan.Source == nil {
		return Unsupported
	}

	return Grype
}

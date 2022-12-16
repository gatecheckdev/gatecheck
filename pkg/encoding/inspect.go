package encoding

import (
	"context"
	"io"
)

type EntityType string

const (
	Gitleaks    EntityType = "Gitleaks"
	Grype       EntityType = "Grype"
	Semgrep     EntityType = "Semgrep"
	Unsupported EntityType = "Unsupported"
)

// Inspect will attempt to decode into all report types and return the one that worked.
// Warning: this function is prone to hanging if a bad reader is supplied, use InspectWithContext unless
// reader can be guaranteed not to hang. Very small performance bump over InspectWithContext
func Inspect(r io.Reader) (EntityType, error) {
	// Errors caught in detectBytes
	inputBytes, _ := io.ReadAll(r)
	return detectBytes(inputBytes)
}

// InspectWithContext calls Inspect with the ability to cancel which prevents hanging when running go routines
func InspectWithContext(ctx context.Context, r io.Reader) (EntityType, error) {
	// based on benchmarking, the async solution is twice as fast when there are at least 3 decoder functions
	var reportType EntityType
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

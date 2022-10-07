package fields

import (
	"errors"
	"fmt"
	"strings"
)

// Finding abstracts the CVEs from any generic scan report
type Finding struct {
	Severity string `json:"severity"`
	Found    int    `json:"found"`
	Allowed  int    `json:"allowed"`
}

// Test compares the thresholds to the number of findings
func (f Finding) Test() error {
	if f.Allowed < 0 {
		return nil
	}
	if f.Allowed >= f.Found {
		return nil
	}

	return errors.New(fmt.Sprintf("%s - Allowed: %d, Found: %d\n", f.Severity, f.Allowed, f.Found))
}

// String output for human eyes
func (f Finding) String() string {
	pass := "False"
	if err := f.Test(); err == nil {
		pass = "True"
	}
	return fmt.Sprintf("%-10s | %-7d | %-7d | %-5s\n", f.Severity, f.Found, f.Allowed, pass)
}

func ValidateFindings(findings []Finding) error {
	var sb strings.Builder
	var validationError error = nil

	for _, t := range findings {
		if err := t.Test(); err != nil {
			validationError = errors.New("validation failed")
			sb.WriteString(err.Error())
		}
	}
	if validationError != nil {
		return fmt.Errorf("%w \n%s", validationError, sb.String())
	}
	return nil
}

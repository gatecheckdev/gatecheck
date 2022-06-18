package fields

import (
	"errors"
	"fmt"
)

// CVE abstracts the CVEs from any generic scan report
type CVE struct {
	Severity string `json:"severity"`
	Found    int    `json:"found"`
	Allowed  int    `json:"allowed"`
}

// Test compares the thresholds to the number of findings
func (c CVE) Test() error {
	if c.Allowed < 0 {
		return nil
	}
	if c.Allowed >= c.Found {
		return nil
	}

	return errors.New(fmt.Sprintf("%s - Allowed: %d, Found: %d\n", c.Severity, c.Allowed, c.Found))
}

// String output for human eyes
func (c CVE) String() string {
	pass := "False"
	if err := c.Test(); err == nil {
		pass = "True"
	}
	return fmt.Sprintf("%-10s | %-7d | %-7d | %-5s\n", c.Severity, c.Found, c.Allowed, pass)
}

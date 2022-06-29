package validator_test

import (
	"github.com/gatecheckdev/gatecheck/internal"
	"github.com/gatecheckdev/gatecheck/internal/testutil"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"github.com/gatecheckdev/gatecheck/pkg/validator"
	"testing"
)

func TestStdValidator_Validate(t *testing.T) {
	reportFilename := testutil.ReportTestCopy(t)

	r, err := internal.ReportFromFile(reportFilename)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("All Vulnerabilities allowed", func(t *testing.T) {
		// All vulnerabilities should be allowed
		c := config.NewConfig("Test Project")
		r.WithConfig(c)
		if err := validator.NewStdValidator(*r).Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Some Allowed", func(t *testing.T) {
		c := config.NewConfig("Test Project")
		c.Grype.Critical = 0
		c.Grype.High = 1
		c.Grype.Medium = 2
		c.Grype.Low = 50
		c.Grype.Unknown = 0
		c.Grype.Negligible = 0
		r = r.WithConfig(c)

		err := validator.NewStdValidator(*r).Validate()
		t.Log(err)

		if err == nil {
			t.Fatal("Expected error for thresholds set to 0")
		}
	})

	t.Run("No vulnerabilities allowed", func(t *testing.T) {
		c := config.NewConfig("Test Project")
		c.Grype.Critical = 0
		c.Grype.High = 0
		c.Grype.Medium = 0
		c.Grype.Low = 0
		c.Grype.Unknown = 0
		c.Grype.Negligible = 0
		r = r.WithConfig(c)

		err := validator.NewStdValidator(*r).Validate()
		t.Log(err)

		if err == nil {
			t.Fatal("Expected error for thresholds set to 0")
		}
	})

}

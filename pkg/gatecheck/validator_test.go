package gatecheck

import (
	"testing"
)

func TestStdValidator_Validate(t *testing.T) {
	r := NewReport("Test Report")
	r.Artifacts.Grype.Critical.Found = 20
	r.Artifacts.Grype.High.Found = 22
	r.Artifacts.Grype.Medium.Found = 113

	r.Artifacts.Semgrep.Error.Found = 12
	r.Artifacts.Semgrep.Warning.Found = 14
	r.Artifacts.Semgrep.Info.Found = 130

	t.Run("All Vulnerabilities allowed", func(t *testing.T) {
		// All vulnerabilities should be allowed
		c := NewConfig("Test Project")

		r = r.WithConfig(c)
		if err := NewStdValidator(*r).Validate(); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("Some Allowed", func(t *testing.T) {
		c := NewConfig("Test Project")
		c.Grype.Critical = 0
		c.Grype.High = 1
		c.Grype.Medium = 2
		c.Grype.Low = 50
		c.Grype.Unknown = 0
		c.Grype.Negligible = 0

		c.Semgrep.Error = 0
		c.Semgrep.Warning = 20
		c.Semgrep.Info = -1
		r = r.WithConfig(c)

		err := NewStdValidator(*r).Validate()
		t.Log(err)

		if err == nil {
			t.Fatal("Expected error for thresholds set to 0")
		}
	})

	t.Run("No vulnerabilities allowed", func(t *testing.T) {
		c := NewConfig("Test Project")
		c.Grype.Critical = 0
		c.Grype.High = 0
		c.Grype.Medium = 0
		c.Grype.Low = 0
		c.Grype.Unknown = 0
		c.Grype.Negligible = 0

		c.Semgrep.Error = 0
		c.Semgrep.Warning = 0
		c.Semgrep.Info = 0
		r = r.WithConfig(c)

		err := NewStdValidator(*r).Validate()
		t.Log(err)

		if err == nil {
			t.Fatal("Expected error for thresholds set to 0")
		}
	})

}

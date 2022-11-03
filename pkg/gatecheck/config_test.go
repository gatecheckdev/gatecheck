package gatecheck

import (
	"bytes"
	"gopkg.in/yaml.v3"
	"testing"
)

var configString = `ProjectName: Test Project
grype:
  critical: 1
  high: 2
  medium: 3
  low: 4
  negligible: 5
  unknown: 6
semgrep:
	error: 1
	warning: 2
	info: 3
`

func TestNewConfig(t *testing.T) {
	c := NewConfig("Test Project")
	c.Grype.Critical = 1
	c.Grype.High = 2
	c.Grype.Medium = 3
	c.Grype.Low = 4
	c.Grype.Negligible = 5
	c.Grype.Unknown = 6

	c.Semgrep.Error = 1
	c.Semgrep.Warning = 2
	c.Semgrep.Info = 3

	buf := new(bytes.Buffer)
	if err := yaml.NewEncoder(buf).Encode(c); err != nil {
		t.Fatal(err)
	}

	c2 := new(Config)
	if err := yaml.NewDecoder(buf).Decode(c2); err != nil {
		t.Fatal(err)
	}

	if c.ProjectName != c2.ProjectName {
		t.Fatal("Encoded config does not match decoded config")
	}

	cTestTable := []int{c.Grype.Critical, c.Grype.High, c.Grype.Medium,
		c.Grype.Low, c.Grype.Negligible, c.Grype.Unknown, c.Semgrep.Error, c.Semgrep.Info, c.Semgrep.Warning}
	c2TestTable := []int{c2.Grype.Critical, c2.Grype.High, c2.Grype.Medium,
		c2.Grype.Low, c2.Grype.Negligible, c2.Grype.Unknown, c.Semgrep.Error, c.Semgrep.Info, c.Semgrep.Warning}

	for i, _ := range cTestTable {
		if cTestTable[i] != c2TestTable[i] {
			t.Errorf("%+v\n", c)
			t.Errorf("%+v\n", c2)
			t.Fatalf("%d != %d as expected", cTestTable[i], c2TestTable[i])
		}
	}
}

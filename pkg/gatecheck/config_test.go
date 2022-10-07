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
`

func TestNewConfig(t *testing.T) {
	c := NewConfig("Test Project")
	c.Grype.Critical = 1
	c.Grype.High = 2
	c.Grype.Medium = 3
	c.Grype.Low = 4
	c.Grype.Negligible = 5
	c.Grype.Unknown = 6

	buf := new(bytes.Buffer)
	if err := yaml.NewEncoder(buf).Encode(c); err != nil {
		t.Fatal(err)
	}

	c2 := new(Config)
	if err := yaml.NewDecoder(buf).Decode(c2); err != nil {
		t.Fatal(err)
	}

	if *c != *c2 {
		t.Logf("%+v\n", *c)
		t.Logf("%+v\n", *c2)
		t.Fatal("Decoded Config does not match Encoded config")
	}

}

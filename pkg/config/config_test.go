package config_test

import (
	"bytes"
	"github.com/gatecheckdev/gatecheck/pkg/config"
	"strings"
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

func TestWriter(t *testing.T) {
	someConfig := config.NewConfig("Test Project")
	someConfig.Grype.Critical = 1
	someConfig.Grype.High = 2
	someConfig.Grype.Medium = 3
	someConfig.Grype.Low = 4
	someConfig.Grype.Negligible = 5
	someConfig.Grype.Unknown = 6
	buf := new(bytes.Buffer)
	if err := config.NewWriter(buf).WriteConfig(someConfig); err != nil {
		t.Fatal(err)
	}

	if strings.Compare(buf.String(), configString) != 0 {
		t.Fatalf("Expected -> '%v' Got -> '%v'", configString, buf.String())
	}
}

func TestReader(t *testing.T) {
	testConfig, err := config.NewReader(bytes.NewBufferString(configString)).ReadConfig()

	if err != nil {
		t.Fatal(err)
	}

	expectedConfig := config.NewConfig("Test Project")
	expectedConfig.Grype.Critical = 1
	expectedConfig.Grype.High = 2
	expectedConfig.Grype.Medium = 3
	expectedConfig.Grype.Low = 4
	expectedConfig.Grype.Negligible = 5
	expectedConfig.Grype.Unknown = 6

	if *testConfig != *expectedConfig {
		t.Fatalf("Expected -> '%v' Got -> '%v'", *expectedConfig, *testConfig)
	}
}

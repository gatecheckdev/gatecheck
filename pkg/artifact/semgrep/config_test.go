package semgrep

import (
	"bytes"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestNewConfig(t *testing.T) {

	// Test Encoding from object
	config := NewConfig(1)
	outputBuf := new(bytes.Buffer)
	if err := yaml.NewEncoder(outputBuf).Encode(config); err != nil {
		t.Fatal(err)
	}

	// Test Decoding from encoded object
	configDecodedFromObject := new(Config)
	if err := yaml.NewDecoder(outputBuf).Decode(configDecodedFromObject); err != nil {
		t.Fatal(err)
	}

	// Test Encoding from string
	stringConfig := "info: 1\nwarning: 1\nerror: 1\n"
	configDecodedFromString := new(Config)
	if err := yaml.NewDecoder(bytes.NewBufferString(stringConfig)).Decode(configDecodedFromString); err != nil {
		t.Fatal(err)
	}

	// Test Equality
	if *configDecodedFromObject != *config {
		t.Logf("%+v\n", config)
		t.Logf("%+v\n", configDecodedFromObject)
		t.Fatal("Decoding from object failed")
	}

	if *configDecodedFromString != *config {
		t.Logf("%+v\n", config)
		t.Logf("%+v\n", configDecodedFromString)
		t.Fatal("Decoding from string failed")
	}
}

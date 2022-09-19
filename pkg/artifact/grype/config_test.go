package grype_test

import (
	"bytes"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"io"
	"strings"
	"testing"
)

func TestNewConfigWriter(t *testing.T) {
	config := grype.NewConfig(3)
	outputBuf := new(bytes.Buffer)

	if err := grype.NewConfigWriter(outputBuf).WriteConfig(config); err != nil {
		t.Fatal(err)
	}

	expectedConfig := "critical: 3\nhigh: 3\nmedium: 3\nlow: 3\nnegligible: 3\nunknown: 3\n"

	if strings.Compare(expectedConfig, outputBuf.String()) != 0 {
		t.Fatalf("expected -> '%s', got -> '%s'\n", expectedConfig, outputBuf.String())
	}

}

func TestNewConfigReader(t *testing.T) {
	testConfig := "critical: 1\nhigh: 2\nmedium: 3\nlow: 4\nnegligible: 5\nunknown: 6\n"

	config, err := grype.NewConfigReader(bytes.NewBufferString(testConfig)).ReadConfig()

	if err != nil {
		t.Fatal(err)
	}

	expectedConfig := grype.Config{
		Critical:   1,
		High:       2,
		Medium:     3,
		Low:        4,
		Negligible: 5,
		Unknown:    6,
	}

	if config != expectedConfig {
		t.Fatalf("Expected -> %v, got -> %v", expectedConfig, config)
	}

	b, err := io.ReadAll(grype.NewConfigReader(bytes.NewBufferString(testConfig)))

	if err != nil {
		t.Fatal(err)
	}
	if len(b) < 50 {
		t.Fatalf("Returned byte size is too small. Got -> %v\n", b)
	}
}

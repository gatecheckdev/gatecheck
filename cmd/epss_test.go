package cmd

import (
	"bytes"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/epss"
	"os"
	"testing"
)

func TestNewEPSSCmd(t *testing.T) {
	actual := new(bytes.Buffer)
	command := NewRootCmd(mockExporter{}, mockService{})
	command.SetOut(actual)
	command.SetErr(actual)

	tempFile, err := os.Open("../test/grype-report.json")
	if err != nil {
		t.Fatal(err)
	}

	command.SetArgs([]string{"epss", tempFile.Name()})

	if err := command.Execute(); err != nil {
		t.Fatal(err)
	}
	t.Log(actual.Len())

	// Something went wrong if the file size is small since the grype-report is from Juice Shop
	if actual.Len() < 30000 {
		t.Log(actual)
		t.FailNow()
	}

	t.Run("non-existing-file", func(t *testing.T) {
		command.SetArgs([]string{"epss", t.TempDir() + "/somefile.txt"})

		if err := command.Execute(); err == nil {
			t.FailNow()
		}
	})

	t.Run("service-error", func(t *testing.T) {
		service := mockService{getError: errors.New("")}
		command := NewRootCmd(mockExporter{}, service)
		command.SetArgs([]string{"epss", tempFile.Name()})

		if err := command.Execute(); err == nil {
			t.FailNow()
		}
	})

}

type mockService struct {
	getError error
}

func (m mockService) Get(CVEs []epss.CVE) ([]epss.Data, error) {
	if m.getError != nil {
		return nil, m.getError
	}
	data := make([]epss.Data, len(CVEs))
	for i, value := range CVEs {
		data[i] = epss.Data{
			CVE:        value.ID,
			EPSS:       ".11",
			Percentile: "0.9",
			Date:       "2022-11-17",
			Severity:   value.Severity,
			URL:        value.Link,
		}
	}
	return data, nil
}

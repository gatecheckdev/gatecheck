package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
	"time"

	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
)

func TestNewExport_DDCmd(t *testing.T) {
	t.Run("defectdojo-bad-file", func(t *testing.T) {
		commandString := fmt.Sprintf("export dd %s", fileWithBadPermissions(t))
		out, err := Execute(commandString, CLIConfig{})

		if errors.Is(err, ErrorFileAccess) != true {
			t.Log(out)
			t.Fatal(err)
		}
	})

	t.Run("defectdojo-timeout", func(t *testing.T) {
		b := make([]byte, 1000)
		tempFile := path.Join(t.TempDir(), "random.file")
		if err := os.WriteFile(tempFile, b, 0664); err != nil {
			t.Fatal(err)
		}

		commandString := fmt.Sprintf("export dd %s", tempFile)
		config := CLIConfig{DDExportTimeout: time.Nanosecond}

		out, err := Execute(commandString, config)

		if errors.Is(err, ErrorEncoding) != true {
			t.Log(out)
			t.Fatal(err)
		}
	})

	t.Run("defectdojo-unsupported", func(t *testing.T) {
		b := make([]byte, 1000)
		tempFile := path.Join(t.TempDir(), "random.file")
		if err := os.WriteFile(tempFile, b, 0664); err != nil {
			t.Fatal(err)
		}

		commandString := fmt.Sprintf("export dd %s", tempFile)

		out, err := Execute(commandString, CLIConfig{DDExportTimeout: time.Second * 3})

		if errors.Is(err, ErrorEncoding) != true {
			t.Log(out)
			t.Fatal(err)
		}
		t.Log(out)
	})

	t.Run("defectdojo-success", func(t *testing.T) {
		files := []*os.File{
			MustOpen(grypeTestReport, t.Fatal),
			MustOpen(semgrepTestReport, t.Fatal),
			MustOpen(gitleaksTestReport, t.Fatal),
		}

		for _, v := range files {

			commandString := fmt.Sprintf("export dd %s", v.Name())

			out, err := Execute(commandString, CLIConfig{
				DDExportService: mockDDExportService{exportResponse: nil},
				DDExportTimeout: time.Second * 3,
			})
			if err != nil {
				t.Log(out)
				t.Fatal(err)
			}
		}
	})

}

func TestExportS3Cmd(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		f := MustOpen(grypeTestReport, t.Fatal)

		commandString := fmt.Sprintf("export s3 %s", f.Name())

		_, err := Execute(commandString, CLIConfig{
			AWSExportService: mockAWSExportService{exportResponse: nil},
			AWSExportTimeout: time.Second * 3,
		})
		if err != nil {
			t.Fatal(err)
		}
	})

	t.Run("bad-permissions", func(t *testing.T) {

		commandString := fmt.Sprintf("export s3 %s --key a/b/c", fileWithBadPermissions(t))
		out, err := Execute(commandString, CLIConfig{})

		if errors.Is(err, ErrorFileAccess) != true {
			t.Log(out)
			t.Fatal(err)
		}
	})
}

type mockDDExportService struct {
	exportResponse error
}

func (m mockDDExportService) Export(_ context.Context, _ io.Reader, _ defectdojo.EngagementQuery, _ defectdojo.ScanType) error {
	return m.exportResponse
}

type mockAWSExportService struct {
	exportResponse error
}

func (m mockAWSExportService) Export(_ context.Context, _ io.Reader, _ string) error {
	return m.exportResponse
}

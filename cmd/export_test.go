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

	"github.com/gatecheckdev/gatecheck/pkg/archive"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/cyclonedx"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/gitleaks"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/grype"
	"github.com/gatecheckdev/gatecheck/pkg/artifacts/semgrep"
	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
	"github.com/gatecheckdev/gatecheck/pkg/export/defectdojo"
)

func TestNewExport_DDCmd(t *testing.T) {
	t.Run("defectdojo-success", func(t *testing.T) {
		files := []*os.File{
			MustOpen(grypeTestReport, t),
			MustOpen(semgrepTestReport, t),
			MustOpen(gitleaksTestReport, t),
			MustOpen(cyclonedxTestReport, t),
		}

		for _, v := range files {

			commandString := fmt.Sprintf("export dd %s", v.Name())

			out, err := Execute(commandString, CLIConfig{
				DDExportService:     mockDDExportService{exportResponse: nil},
				NewAsyncDecoderFunc: AsyncDecoderFunc,
				DDExportTimeout:     time.Second * 3,
			})
			if err != nil {
				t.Log(out)
				t.Fatal(err)
			}
		}
	})

	t.Run("defectdojo-full-bom", func(t *testing.T) {

		config := CLIConfig{DDExportService: mockDDExportService{exportResponse: nil},
			NewAsyncDecoderFunc: AsyncDecoderFunc, DDExportTimeout: time.Second * 3}

		commandString := fmt.Sprintf("export dd --full-bom %s", MustOpen(cyclonedxTestReport, t).Name())
		out, err := Execute(commandString, config)
		if err != nil {
			t.Log(out)
			t.Fatal(err)
		}
		t.Run("invalid", func(t *testing.T) {

			commandString := fmt.Sprintf("export dd --full-bom %s", MustOpen(grypeTestReport, t).Name())
			out, err := Execute(commandString, config)
			if !errors.Is(err, ErrorUserInput) {
				t.Log(out)
				t.Fatalf("want: %v got: %v", ErrorUserInput, err)
			}
		})

	})

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
		config := CLIConfig{DDExportTimeout: time.Nanosecond, NewAsyncDecoderFunc: AsyncDecoderFunc}

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

		out, err := Execute(commandString, CLIConfig{DDExportTimeout: time.Second * 3, NewAsyncDecoderFunc: AsyncDecoderFunc})

		if errors.Is(err, ErrorEncoding) != true {
			t.Log(out)
			t.Fatal(err)
		}
		t.Log(out)
	})

}

func TestExportS3Cmd(t *testing.T) {
	config := CLIConfig{
		AWSExportService: mockAWSExportService{exportResponse: nil},
		AWSExportTimeout: time.Second * 3,
	}

	commandString := fmt.Sprintf("export s3 %s --key a/b/c", grypeTestReport)

	_, err := Execute(commandString, config)
	if err != nil {
		t.Fatal(err)
	}
}

func AsyncDecoderFunc() AsyncDecoder {
	decoder := new(gce.AsyncDecoder).WithDecoders(
		grype.NewReportDecoder(),
		semgrep.NewReportDecoder(),
		gitleaks.NewReportDecoder(),
		cyclonedx.NewReportDecoder(),
		archive.NewBundleDecoder(),
	)

	return decoder
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

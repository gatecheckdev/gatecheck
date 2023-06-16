package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"path"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
)

func TestNewBundleCmd(t *testing.T) {
	config := CLIConfig{NewAsyncDecoderFunc: NewAsyncDecoder}
	mockObj := map[string]string{"key": "value"}
	tempFile := func(p string) string { return path.Join(t.TempDir(), p) }

	testTable := []struct {
		label     string
		cmdString string
		wantErr   error
	}{
		{label: "bundle-error", cmdString: fmt.Sprintf("bundle -o %s %s", fileWithBadPermissions(t), fileWithBadJSON(t)), wantErr: ErrorFileAccess},
		{label: "existing-bundle-error", cmdString: fmt.Sprintf("bundle -o %s %s", writeTempAny(mockObj, t), fileWithBadJSON(t)), wantErr: ErrorEncoding},
		{label: "arugment-file-error", cmdString: fmt.Sprintf("bundle -o %s %s", tempFile("bundle-1.tar.gz"), fileWithBadPermissions(t)), wantErr: ErrorFileAccess},
		{label: "missing-file", cmdString: fmt.Sprintf("bundle -mo %s %s %s", tempFile("bundle-2.tar.gz"), writeTempAny(mockObj, t), "nonexistingfile.txt"), wantErr: nil},
		{label: "ls-file-error", cmdString: "bundle ls", wantErr: ErrorFileAccess},
		{label: "ls-file-encoding-error", cmdString: fmt.Sprintf("bundle ls %s", writeTempAny(mockObj, t)), wantErr: ErrorEncoding},
	}

	for _, testCase := range testTable {
		t.Run(testCase.label, func(t *testing.T) {
			out, err := Execute(testCase.cmdString, config)
			t.Log(out)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("want: %v got: %v", testCase.wantErr, err)
			}
		})
	}

	t.Run("existing-bundle", func(t *testing.T) {
		bundle := archive.NewBundle()
		_ = bundle.AddFrom(MustOpen(grypeTestReport, t), "grype-report.json", nil)
		_ = bundle.AddFrom(MustOpen(semgrepTestReport, t), "semgrep-report.json", nil)
		bundleFilename := path.Join(t.TempDir(), "bundle.tar.gz")
		_ = archive.NewBundleEncoder(MustCreate(bundleFilename, t)).Encode(bundle)

		tempFilename := path.Join(t.TempDir(), "file-1.txt")
		_, _ = strings.NewReader("ABCDEF").WriteTo(MustCreate(tempFilename, t))

		cmdString := fmt.Sprintf("bundle -o %s %s", bundleFilename, tempFilename)
		if _, err := Execute(cmdString, config); err != nil {
			t.Fatalf("want: %v got: %v", nil, err)
		}

		obj, err := archive.NewBundleDecoder().DecodeFrom(MustOpen(bundleFilename, t))
		if err != nil {
			t.Fatal(err)
		}
		buf := new(bytes.Buffer)
		decodedBundle := obj.(*archive.Bundle)
		_, err = decodedBundle.WriteFileTo(buf, "file-1.txt")
		t.Log(buf.String())
		if err != nil {
			t.Fatal(err)
		}
		if buf.String() != "ABCDEF" {
			t.Fatalf("want: %s got: %s", "ABCDEF", buf.String())
		}
		cmdString = fmt.Sprintf("bundle ls %s", bundleFilename)
		out, err := Execute(cmdString, config)
		if err != nil {
			t.Fatalf("want: %v got: %v", nil, err)
		}
		t.Log(out)
	})
}

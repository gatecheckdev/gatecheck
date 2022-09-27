package grype_test

import (
	"bytes"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"os"
	"testing"
)

var TestGrypeReport = "../../../test/grype-report.json"

func TestScanReportReader(t *testing.T) {
	scanFile, err := os.Open(TestGrypeReport)
	if err != nil {
		t.Fatal(err)
	}

	scan := new(grype.ScanReport)
	if err = json.NewDecoder(scanFile).Decode(scan); err != nil {
		t.Fatal(err)
	}

	if len(scan.Matches) < 100 {
		t.Fatal("Check scan, not enough matches returned")
	}
}

func TestAssetReader(t *testing.T) {
	scanFile, err := os.Open(TestGrypeReport)
	if err != nil {
		t.Fatal(err)
	}

	scan := new(grype.ScanReport)
	if err := json.NewDecoder(scanFile).Decode(scan); err != nil {
		t.Fatal(err)
	}

	asset := grype.NewAsset("grype-scan").WithScan(scan)

	buf := new(bytes.Buffer)

	_ = json.NewEncoder(buf).Encode(asset)

	if buf.Len() < 50 {
		t.Fatal("Asset size after writing bytes is too small")
	}
}

func TestAssetWriter(t *testing.T) {
	scanFile, err := os.Open(TestGrypeReport)
	if err != nil {
		t.Fatal(err)
	}
	scan := new(grype.ScanReport)
	if err := json.NewDecoder(scanFile).Decode(scan); err != nil {
		t.Fatal(err)
	}

	asset := grype.NewAsset("grype-scan").WithScan(scan)

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(asset); err != nil {
		t.Fatal(err)
	}

	if buf.Len() < 50 {
		t.Fatal("not enough expected written asset bytes")
	}

	t.Run("Read from Writer", func(t *testing.T) {
		newAsset := new(grype.Asset)
		if err := json.NewDecoder(buf).Decode(newAsset); err != nil {
			t.Fatal(err)
		}

		if newAsset.Label != "grype-scan" {
			t.Log(newAsset)
			t.Fatal("expected label name")
		}
	})
}

func TestScanReportWriter_WriteScan(t *testing.T) {
	scanFile, _ := os.Open(TestGrypeReport)
	scan := new(grype.ScanReport)
	if err := json.NewDecoder(scanFile).Decode(scan); err != nil {
		t.Fatal(err)
	}

	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(scan); err != nil {
		t.Fatal(err)
	}

	if buf.Len() < 600000 {
		t.Fatal("Scan report too small")
	}
}

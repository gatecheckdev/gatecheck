package grype_test

import (
	"bytes"
	"github.com/gatecheckdev/gatecheck/pkg/artifact/grype"
	"io/ioutil"
	"os"
	"testing"
)

var TestGrypeReport = "../../../test/grype-report.json"

func TestScanReportReader(t *testing.T) {
	scanFile, err := os.Open("../../../test/grype-report.json")
	if err != nil {
		t.Fatal(err)
	}

	scan, err := grype.NewScanReportReader(scanFile).ReadScan()

	if err != nil {
		t.Fatal(err)
	}

	if len(scan.Matches) < 100 {
		t.Fatal("Check scan, not enough matches returned")
	}
}

func TestAssetReader(t *testing.T) {
	scanFile, _ := os.Open(TestGrypeReport)
	scan, _ := grype.NewScanReportReader(scanFile).ReadScan()

	asset := grype.NewAsset("grype-scan").WithScan(*scan)

	buf := new(bytes.Buffer)

	_ = grype.NewAssetWriter(buf).WriteAsset(asset)

	if buf.Len() < 1000 {
		t.Fatal("Asset size after writing bytes is too small")
	}
}

func TestAssetWriter(t *testing.T) {
	scanFile, _ := os.Open(TestGrypeReport)
	scan, _ := grype.NewScanReportReader(scanFile).ReadScan()

	asset := grype.NewAsset("grype-scan").WithScan(*scan)

	buf := new(bytes.Buffer)
	if err := grype.NewAssetWriter(buf).WriteAsset(asset); err != nil {
		t.Fatal(err)
	}

	if buf.Len() < 1000 {
		t.Fatal("not enough expected written asset bytes")
	}

	t.Run("Read from Writer", func(t *testing.T) {
		assetBytes, err := ioutil.ReadAll(grype.NewAssetReader(buf))

		if err != nil {
			t.Fatal(err)
		}

		if len(assetBytes) < 1000 {
			t.Log(string(assetBytes))
			t.Fatal("Asset size is too small,")
		}

		newAsset, err := grype.NewAssetReader(bytes.NewBuffer(assetBytes)).ReadAsset()
		if err != nil {
			t.Fatal(err)
		}

		t.Log(newAsset)
	})
}

func TestAssetReader_badJson(t *testing.T) {
	buf := new(bytes.Buffer)

	if _, err := grype.NewAssetReader(buf).ReadAsset(); err == nil {
		t.Fatal("expected error for bad json decoding")
	}
}

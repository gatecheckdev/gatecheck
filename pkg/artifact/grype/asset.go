package grype

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
)

type Asset struct {
	Label            string `json:"label"`
	ScanReportDigest []byte `json:"scanReportDigest"`
	scan             ScanReport
}

func NewAsset(label string) *Asset {
	return &Asset{
		Label: label,
	}
}

func (a Asset) WithScan(s *ScanReport) *Asset {
	// Save the scan
	a.scan = *s
	// Encode scan as JSON
	scanBuffer := new(bytes.Buffer)
	_ = json.NewEncoder(scanBuffer).Encode(s)

	// Hash the scan report JSON bytes
	hashWriter := sha256.New()
	hashWriter.Write(scanBuffer.Bytes())
	a.ScanReportDigest = hashWriter.Sum(nil)

	return &a
}

type ScanReport = entity.GrypeScanReport

package grype

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"io"
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

type AssetReader struct {
	reader io.Reader
}

func (r *AssetReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *AssetReader) ReadAsset() (*Asset, error) {
	asset := Asset{}
	err := json.NewDecoder(r).Decode(&asset)
	return &asset, err
}

func NewAssetReader(r io.Reader) *AssetReader {
	return &AssetReader{reader: r}
}

type AssetWriter struct {
	writer io.Writer
}

func (w *AssetWriter) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

func (w *AssetWriter) WriteAsset(a *Asset) error {
	return json.NewEncoder(w).Encode(a)
}

func NewAssetWriter(w io.Writer) *AssetWriter {
	return &AssetWriter{writer: w}
}

type ScanReportReader struct {
	reader io.Reader
}

func (r *ScanReportReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

func (r *ScanReportReader) ReadScan() (*ScanReport, error) {
	scan := &ScanReport{}
	err := json.NewDecoder(r).Decode(scan)

	return scan, err
}

func NewScanReportReader(r io.Reader) *ScanReportReader {
	return &ScanReportReader{reader: r}
}

type ScanReportWriter struct {
	writer io.Writer
}

func NewScanReportWriter(w io.Writer) *ScanReportWriter {
	return &ScanReportWriter{writer: w}
}

func (w *ScanReportWriter) Write(p []byte) (int, error) {
	return w.writer.Write(p)
}

func (w *ScanReportWriter) WriteScan(scan *ScanReport) error {
	return json.NewEncoder(w).Encode(scan)
}

type ScanReport = entity.GrypeScanReport

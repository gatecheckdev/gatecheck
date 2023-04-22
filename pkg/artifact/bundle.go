package artifact

import (
	"bytes"
	"compress/gzip"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/dustin/go-humanize"
	gcStrings "github.com/gatecheckdev/gatecheck/pkg/strings"
)

type Bundle struct {
	GrypeScan    Artifact
	SemgrepScan  Artifact
	GitleaksScan Artifact
	Generic      map[string]Artifact
	PipelineID   string
	PipelineURL  string
	ProjectName  string
}

func NewBundle() *Bundle {
	return &Bundle{Generic: map[string]Artifact{}}
}

func (b *Bundle) Add(artifacts ...Artifact) error {
	for _, v := range artifacts {
		if err := b.add(v); err != nil {
			return err
		}
	}
	return nil
}

func (b *Bundle) add(artifact Artifact) error {
	if strings.Trim(artifact.Label, " ") == "" {
		return errors.New("artifact is missing a label")
	}
	// Directly taking bytes, no possibility of error
	rType, _ := Inspect(bytes.NewBuffer(artifact.ContentBytes()))

	// No need to check decode errors since it's decoded in the DetectReportType Function
	switch rType {
	case Semgrep:
		b.SemgrepScan = artifact
	case Grype:
		b.GrypeScan = artifact
	case Gitleaks:
		b.GitleaksScan = artifact
	case Unsupported:
		b.Generic[artifact.Label] = artifact
	}

	return nil
}

func (b *Bundle) String() string {
	table := new(gcStrings.Table).WithHeader("Type", "Label", "Digest", "Size")

	items := []Artifact{b.GrypeScan, b.SemgrepScan, b.GitleaksScan}
	types := []string{"Grype", "Semgrep", "Gitleaks"}
	for _, v := range b.Generic {
		items = append(items, v)
		types = append(types, "Generic File")
	}

	totalSize := uint64(0)
	for i, v := range items {
		totalSize += uint64(len(v.ContentBytes()))
		table = table.WithRow(types[i], v.Label, v.DigestString(), humanize.Bytes(uint64(len(v.ContentBytes()))))
	}
	horizontalLength := len(strings.Split(table.String(), "\n")[0])
	var sb strings.Builder
	sb.WriteString(table.String() + "\n")

	summary := "Total Size: " + humanize.Bytes(totalSize)
	// Left pad with spaces
	sb.WriteString(strings.Repeat(" ", horizontalLength-len(summary)) + summary)
	return sb.String()
}

func (b *Bundle) ValidateGrype(config *GrypeConfig) error {
	var grypeScan GrypeScanReport
	// No config
	if config == nil {
		return nil
	}
	// No scan in bundle to validate
	if len(b.GrypeScan.Content) == 0 {
		return nil
	}

	// Problem parsing the artifact
	if err := json.Unmarshal(b.GrypeScan.ContentBytes(), &grypeScan); err != nil {
		return fmt.Errorf("%w: %v", GrypeValidationFailed, err)
	}

	return ValidateGrype(*config, grypeScan)
}

func (b *Bundle) ValidateSemgrep(config *SemgrepConfig) error {
	var semgrepScan SemgrepScanReport
	// No config
	if config == nil {
		return nil
	}
	// No scan in bundle to validate
	if len(b.SemgrepScan.ContentBytes()) == 0 {
		return nil
	}

	// Problem parsing the artifact
	if err := json.Unmarshal(b.SemgrepScan.ContentBytes(), &semgrepScan); err != nil {
		return fmt.Errorf("%w: %v", SemgrepFailedValidation, err)
	}

	return ValidateSemgrep(*config, semgrepScan)
}

func (b *Bundle) ValidateGitleaks(config *GitleaksConfig) error {
	var gitleaksScan GitleaksScanReport
	// No config
	if config == nil {
		return nil
	}
	// No scan in bundle to validate
	if len(b.GitleaksScan.ContentBytes()) == 0 {
		return nil
	}

	// Problem parsing the artifact
	if err := json.Unmarshal(b.GitleaksScan.ContentBytes(), &gitleaksScan); err != nil {
		return fmt.Errorf("%w: %v", GitleaksValidationFailed, err)
	}

	return ValidateGitleaks(*config, gitleaksScan)
}

type Encoder struct {
	w io.Writer
}

func (e Encoder) Encode(bundle *Bundle) error {
	// TODO: Add encryption
	buf := new(bytes.Buffer)
	if bundle == nil {
		return errors.New("no bundle to encode")
	}
	_ = gob.NewEncoder(buf).Encode(bundle)

	zw := gzip.NewWriter(e.w)

	if _, err := io.Copy(zw, buf); err != nil {
		return err
	}

	_ = zw.Close()
	return nil
}

func NewBundleEncoder(w io.Writer) *Encoder {
	return &Encoder{w: w}
}

type BundleDecoder struct {
	r io.Reader
}

func (d BundleDecoder) Decode(bundle *Bundle) error {
	// TODO: Add decryption

	zr, err := gzip.NewReader(d.r)
	if err != nil {
		return err
	}

	buf := new(bytes.Buffer)
	// Errors captured during gzip.NewReader or during decoding
	_, _ = io.Copy(buf, zr)

	return gob.NewDecoder(buf).Decode(bundle)
}

func NewBundleDecoder(r io.Reader) *BundleDecoder {
	return &BundleDecoder{r: r}
}

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

const FileType = "Gatecheck Bundle"
const BundleVersion = "1"
const ManifestFilename = "gatecheck-manifest.json"
const DefaultBundleFilename = "gatecheck-bundle.tar.gz"

type Bundle struct {
	content  map[string][]byte
	manifest bundleManifest
}

func NewBundle() *Bundle {
	return &Bundle{
		content:  make(map[string][]byte),
		manifest: bundleManifest{Created: time.Now(), Version: BundleVersion, Files: make(map[string]fileDescriptor)},
	}
}

func (b *Bundle) Manifest() bundleManifest {
	return b.manifest
}

func (b *Bundle) WriteFileTo(w io.Writer, fileLabel string) (int64, error) {
	fileBytes, ok := b.content[fileLabel]
	if !ok {
		return 0, fmt.Errorf("%w: Label '%s' not found in bundle", gce.ErrIO, fileLabel)
	}
	return bytes.NewReader(fileBytes).WriteTo(w)
}

func (b *Bundle) FileSize(fileLabel string) int {
	fileBytes, ok := b.content[fileLabel]
	if !ok {
		return 0
	}
	return len(fileBytes)
}

func (b *Bundle) AddFrom(r io.Reader, label string, properties map[string]string) error {
	hasher := sha256.New()
	p, err := io.ReadAll(r)
	_, _ = bytes.NewReader(p).WriteTo(hasher)
	if err != nil {
		return fmt.Errorf("%w: %v", gce.ErrIO, err)
	}
	digest := fmt.Sprintf("%x", hasher.Sum(nil))

	b.manifest.Files[label] = fileDescriptor{Added: time.Now(), Properties: properties, Digest: digest}

	b.content[label] = p
	return nil
}

func (b *Bundle) Delete(label string) {
	delete(b.content, label)
	delete(b.manifest.Files, label)
}

type bundleManifest struct {
	Created time.Time                 `json:"createdAt"`
	Version string                    `json:"version"`
	Files   map[string]fileDescriptor `json:"files"`
}

type fileDescriptor struct {
	Added      time.Time         `json:"addedAt"`
	Properties map[string]string `json:"properties"`
	Digest     string            `json:"digest"`
}

type BundleEncoder struct {
	w io.Writer
}

func NewBundleEncoder(w io.Writer) *BundleEncoder {
	return &BundleEncoder{w: w}
}

func (b *BundleEncoder) Encode(bundle *Bundle) error {
	if bundle == nil {
		return fmt.Errorf("%w: bundle is nil", gce.ErrEncoding)
	}
	tarballBuffer := new(bytes.Buffer)
	tarWriter := tar.NewWriter(tarballBuffer)
	manifestBytes, _ := json.Marshal(bundle.manifest)
	_ = bundle.AddFrom(bytes.NewReader(manifestBytes), "gatecheck-manifest.json", nil)

	for label, data := range bundle.content {
		// Using bytes.Buffer so IO errors are unlikely
		_ = tarWriter.WriteHeader(&tar.Header{Name: label, Size: int64(len(data)), Mode: int64(os.FileMode(0666))})
		_, _ = bytes.NewReader(data).WriteTo(tarWriter)
	}
	tarWriter.Close()

	bundle.Delete(ManifestFilename)
	gzipWriter := gzip.NewWriter(b.w)
	_, _ = tarballBuffer.WriteTo(gzipWriter)
	gzipWriter.Close()

	return nil
}

type BundleDecoder struct {
	bytes.Buffer
}

func NewBundleDecoder() *BundleDecoder {
	return new(BundleDecoder)
}

func (d *BundleDecoder) DecodeFrom(r io.Reader) (any, error) {
	_, err := d.ReadFrom(r)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", gce.ErrIO, err)
	}

	return d.Decode()
}

func (d *BundleDecoder) Decode() (any, error) {
	gzipReader, err := gzip.NewReader(d)
	if err != nil {
		return nil, fmt.Errorf("%w: gzip decode: %v", gce.ErrEncoding, err)
	}
	tarReader := tar.NewReader(gzipReader)

	bundle := new(Bundle)
	bundle.content = make(map[string][]byte)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("%w: tar decode: %v", gce.ErrEncoding, err)
		}

		if header.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("%w: Gatecheck Bundle only supports regular files in a flat directory structure", gce.ErrEncoding)
		}
		fileBytes, _ := io.ReadAll(tarReader)
		bundle.content[header.Name] = fileBytes
	}
	manifest := new(bundleManifest)
	manifestBytes, ok := bundle.content[ManifestFilename]
	if !ok {
		return nil, fmt.Errorf("%w: Gatecheck Bundle manifest not found", gce.ErrEncoding)
	}
	if err := json.Unmarshal(manifestBytes, manifest); err != nil {
		return nil, fmt.Errorf("%w: gatecheck manifest decoding: %v", gce.ErrEncoding, err)
	}
	bundle.manifest = *manifest
	bundle.Delete(ManifestFilename)

	return bundle, nil
}

func (d *BundleDecoder) FileType() string {
	return FileType
}

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path"
	"strings"
	"testing"

	gce "github.com/gatecheckdev/gatecheck/pkg/encoding"
)

func TestEncoding(t *testing.T) {
	bundle := NewBundle()

	_ = bundle.AddFrom(strings.NewReader("ABCDEF"), "file-1.txt", nil)
	_ = bundle.AddFrom(strings.NewReader("GHIJKL"), "file-2.txt", nil)
	_ = bundle.AddFrom(strings.NewReader("MNOPQR"), "file-3.txt", nil)

	filename := path.Join(t.TempDir(), DefaultBundleFilename)
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewBundleEncoder(f).Encode(bundle); err != nil {
		t.Fatal(err)
	}

	t.Run("successful-decode", func(t *testing.T) {
		obj, err := NewBundleDecoder().DecodeFrom(MustOpen(filename, t))
		if err != nil {
			t.Fatal(err)
		}
		decodedBundle, ok := obj.(*Bundle)
		if !ok {
			t.Fatalf("want: *Bundle got: %T", obj)
		}

		for key := range decodedBundle.content {
			if bytes.Compare(decodedBundle.content[key], bundle.content[key]) != 0 {
				t.Fatalf("for key: %s %s != %s", key, decodedBundle.content[key], bundle.content[key])
			}
		}

		for key := range decodedBundle.manifest.Files {
			if decodedBundle.manifest.Files[key].Digest != bundle.manifest.Files[key].Digest {
				t.Fatalf("for key: %s %s != %s", key, decodedBundle.manifest.Files[key].Digest, bundle.manifest.Files[key].Digest)
			}
		}
		t.Log(NewBundleDecoder().FileType())
		t.Log(bundle.Manifest())
	})

	t.Run("failed-io-addFrom", func(t *testing.T) {
		err := NewBundle().AddFrom(&badReader{}, "b", nil)
		if !errors.Is(err, gce.ErrIO) {
			t.Fatalf("want: %v got: %v", gce.ErrIO, err)
		}
	})

	t.Run("nil-bundle-encoding", func(t *testing.T) {
		err := NewBundleEncoder(new(bytes.Buffer)).Encode(nil)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

	t.Run("failed-io-decoding", func(t *testing.T) {
		_, err := NewBundleDecoder().DecodeFrom(&badReader{})
		if !errors.Is(err, gce.ErrIO) {
			t.Fatalf("want: %v got: %v", gce.ErrIO, err)
		}
	})

	t.Run("failed-gzip-bad-format", func(t *testing.T) {

		_, err := NewBundleDecoder().DecodeFrom(strings.NewReader("ABCDEF"))
		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

	t.Run("failed-tar-reading-decoding", func(t *testing.T) {
		outputBuf := new(bytes.Buffer)
		gw := gzip.NewWriter(outputBuf)
		contentBuf := strings.NewReader("ABCDEF")
		_, _ = io.Copy(gw, contentBuf)
		gw.Close()
		// Don't close writer to provoke an error

		_, err := NewBundleDecoder().DecodeFrom(outputBuf)
		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})
	t.Run("failed-tar-decoding-invalid-type", func(t *testing.T) {

		contentBuf := strings.NewReader("ABCDEF")
		hdr := &tar.Header{Name: "foo", Size: int64(contentBuf.Len()), Mode: 0666, Typeflag: tar.TypeDir}

		_, err := NewBundleDecoder().DecodeFrom(zippedTarballReader(contentBuf, hdr))
		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

	t.Run("failed-tar-decoding-missing-manifest", func(t *testing.T) {
		contentBuf := strings.NewReader("ABCDEF")
		hdr := &tar.Header{Name: "foo", Size: int64(contentBuf.Len()), Mode: 0666, Typeflag: tar.TypeReg}

		_, err := NewBundleDecoder().DecodeFrom(zippedTarballReader(contentBuf, hdr))
		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})

	t.Run("failed-tar-decoding-bad-manifest", func(t *testing.T) {
		contentBuf := strings.NewReader("{{{")
		hdr := &tar.Header{Name: ManifestFilename, Size: int64(contentBuf.Len()), Mode: 0666, Typeflag: tar.TypeReg}

		_, err := NewBundleDecoder().DecodeFrom(zippedTarballReader(contentBuf, hdr))
		t.Log(err)
		if !errors.Is(err, gce.ErrEncoding) {
			t.Fatalf("want: %v got: %v", gce.ErrEncoding, err)
		}
	})
}

func TestBundle_WriteFileTo(t *testing.T) {
	bundle := NewBundle()
	_ = bundle.AddFrom(strings.NewReader("ABCDEF"), "file-1.txt", nil)
	_ = bundle.AddFrom(strings.NewReader("GHIJKL"), "file-2.txt", nil)
	_ = bundle.AddFrom(strings.NewReader("MNOPQR"), "file-3.txt", nil)
	outputBuf := new(bytes.Buffer)
	_, err := bundle.WriteFileTo(outputBuf, "file-1.txt")
	if err != nil {
		t.Fatal(err)
	}
	if outputBuf.String() != "ABCDEF" {
		t.Fatalf("want: 'ABCDEF' got: '%s'", outputBuf.String())
	}
	if bundle.FileSize("file-1.txt") != outputBuf.Len() {
		t.Fatalf("%d is not equal to %d", bundle.FileSize("file-1.txt"), outputBuf.Len())
	}

	t.Run("not-found", func(t *testing.T) {
		_, err := bundle.WriteFileTo(outputBuf, "file-999.txt")
		t.Log(err)
		if !errors.Is(err, gce.ErrIO) {
			t.Fatalf("want: %v got: %v", gce.ErrIO, err)
		}
		if bundle.FileSize("file-999.txt") != 0 {
			t.Fatal()
		}
	})

	t.Run("bad-writer", func(t *testing.T) {
		_, err := bundle.WriteFileTo(&badWriter{}, "file-1.txt")
		if err == nil {
			t.Fatal("want: badreader error got: nil")
		}
	})
}

func zippedTarballReader(r io.Reader, tarHeader *tar.Header) *bytes.Buffer {
	outputBuf := new(bytes.Buffer)
	gw := gzip.NewWriter(outputBuf)
	tw := tar.NewWriter(gw)
	tw.WriteHeader(tarHeader)

	_, _ = io.Copy(tw, r)
	tw.Close()
	gw.Close()
	return outputBuf
}

type badReader struct{}

func (r *badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("mock reader error")
}

type badWriter struct{}

func (r *badWriter) Write(_ []byte) (int, error) {
	return 0, errors.New("mock reader error")
}

func MustOpen(filename string, t *testing.T) *os.File {
	f, err := os.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

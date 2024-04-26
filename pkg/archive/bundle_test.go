package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)


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
		if err == nil {
			t.Fatal("want error got nil")
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
	_ = tw.WriteHeader(tarHeader)

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

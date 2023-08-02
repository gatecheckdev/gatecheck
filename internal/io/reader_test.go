package io

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path"
	"testing"
)

func TestLazyReader(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		tempFile := path.Join(t.TempDir(), "file.txt")
		_ = os.WriteFile(tempFile, []byte("content"), 0664)
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(NewLazyReader(tempFile))
		if err != nil {
			t.Fatal(err)
		}
		if buf.String() != "content" {
			t.Fatalf("want: 'content' got: '%s'", buf.String())
		}
	})

	t.Run("bad-permissions", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(NewLazyReader(fileWithBadPermissions(t)))
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("want: %v got: %v", os.ErrPermission, err)
		}
	})
	t.Run("nil-file", func(t *testing.T) {
		buf := new(bytes.Buffer)
		_, err := buf.ReadFrom(&LazyReader{})
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("want: %v got: %v", os.ErrNotExist, err)
		}
	})
}

func TestCloseEOF(t *testing.T) {
	if err := closeEOF(mockCloser{returnErr: nil}); !errors.Is(err, io.EOF) {
		t.Fatalf("want: %v got: %v", io.EOF, err)
	}
	if err := closeEOF(mockCloser{returnErr: errors.New("mock close error")}); err == nil {
		t.Fatalf("want: error got: %v", err)
	}
}

type mockCloser struct {
	returnErr error
}

func (c mockCloser) Close() error {
	return c.returnErr
}

func fileWithBadPermissions(t *testing.T) (filename string) {
	n := path.Join(t.TempDir(), "bad-file")
	f, err := os.Create(n)
	if err != nil {
		t.Fatal(err)
	}

	if err := f.Chmod(0000); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()

	return n
}

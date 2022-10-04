package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
)

func TestOpenAll(t *testing.T) {
	filename1 := path.Join(t.TempDir(), "file1.txt")
	filename2 := path.Join(t.TempDir(), "file2.txt")
	filename3 := path.Join(t.TempDir(), "file3.txt")

	for i, filename := range []string{filename1, filename2, filename3} {
		f, _ := os.Create(filename)
		_, _ = f.WriteString(fmt.Sprintf("File %d", i+1))
	}

	files, err := OpenAll(filename1, filename2, filename3)

	if err != nil {
		t.Fatal(err)
	}

	for i, file := range files {
		content, err := io.ReadAll(file)
		if err != nil {
			t.Fatal(err)
		}
		if string(content) != fmt.Sprintf("File %d", i+1) {
			t.Log(string(content))
			t.Fatal("Unmatched file content")
		}
	}

	t.Run("bad-file", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "bad-file.txt")
		_, _ = os.Create(fPath)
		_ = os.Chmod(fPath, 0000)
		t.Log(fPath)

		if _, err := OpenAll(fPath); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected error for bad permissions, got %v", err)
		}

	})

}

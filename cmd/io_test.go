package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"testing"
)

func TestOpenOrCreate(t *testing.T) {

	t.Run("non-existing-file", func(t *testing.T) {
		filename := path.Join(t.TempDir(), "file1.txt")
		// File doesn't exist so it should be created
		f, err := OpenOrCreate(filename)
		if err != nil {
			t.Fatal(err)
		}
		CheckReadWrite(t, f, filename)
	})

	t.Run("file-access", func(t *testing.T) {
		if _, err := OpenOrCreate(CreateMockFile(t, NoPermissions)); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}
		if _, err := OpenOrCreate(CreateMockFile(t, BadDescriptor)); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}
	})
}

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

	t.Run("file-access", func(t *testing.T) {

		if _, err := OpenAll(CreateMockFile(t, NoPermissions)); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected error for bad permissions, got %v", err)
		}

		if _, err := OpenAll(""); errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected error for blank file, got %v", err)
		}
	})

}

func TestOpenAndDecode(t *testing.T) {

	t.Run("encode-decode-json", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "temp-file.json")
		if err := OpenAndEncode(fPath, JSON, &testObj{FirstName: "Tony", LastName: "Stark"}); err != nil {
			t.Fatal(err)
		}
		decodedObj, err := OpenAndDecode[testObj](fPath, JSON)
		if err != nil {
			t.Fatal(err)
		}
		if decodedObj.FirstName != "Tony" && decodedObj.LastName != "Stark" {
			t.Fatal("Decoded object doesn't match encoded object")
		}
	})

	t.Run("encode-decode-yaml", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "bad-file.yaml")
		if err := OpenAndEncode(fPath, YAML, &testObj{FirstName: "Tony", LastName: "Stark"}); err != nil {
			t.Fatal(err)
		}
		decodedObj, err := OpenAndDecode[testObj](fPath, YAML)
		if err != nil {
			t.Fatal(err)
		}
		if decodedObj.FirstName != "Tony" && decodedObj.LastName != "Stark" {
			t.Fatal("Decoded object doesn't match encoded object")
		}
	})

	t.Run("non-existing-file", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "bad-file.json")
		if _, err := OpenAndDecode[badMarshaller](fPath, JSON); errors.Is(err, ErrorFileNotExists) != true {
			t.Fatalf("Expected error for file not existing, got %v", err)
		}
	})

	t.Run("bad-decode", func(t *testing.T) {
		_, err := OpenAndDecode[badMarshaller](CreateMockFile(t, BadDecode), JSON)
		if errors.Is(err, ErrorDecode) != true {
			t.Fatalf("Expected error for file not existing, got %v", err)
		}
	})

	t.Run("file-access", func(t *testing.T) {
		_, err := OpenAndDecode[badMarshaller](CreateMockFile(t, NoPermissions), JSON)
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}
	})
}

func TestOpenAndDecodeOrCreate(t *testing.T) {
	fPath := path.Join(t.TempDir(), "test.json")
	obj := testObj{FirstName: "Tony", LastName: "Stark"}
	if err := OpenAndEncode(fPath, JSON, obj); err != nil {
		t.Fatal(err)
	}

	decodedObj, err := OpenAndDecodeOrCreate[testObj](fPath, JSON)
	if err != nil {
		t.Fatal(err)
	}

	if decodedObj.FirstName != "Tony" && decodedObj.LastName != "Stark" {
		t.Fatal("Decoded object does not match encoded object")
	}

	t.Run("non-existing-file", func(t *testing.T) {
		fPath2 := path.Join(t.TempDir(), "somefile.json")
		someObj, err := OpenAndDecodeOrCreate[testObj](fPath2, JSON)
		if err != nil {
			t.Fatal(err)
		}
		if someObj == nil {
			t.Fatal("Did not receive a new object for non-existing file")
		}
	})

	t.Run("file-access-error", func(t *testing.T) {

		_, err := OpenAndDecodeOrCreate[testObj](CreateMockFile(t, NoPermissions), JSON)
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}

		_, err = OpenAndDecodeOrCreate[testObj](CreateMockFile(t, BadDescriptor), JSON)
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}
	})
}

func TestOpenAndEncode(t *testing.T) {
	t.Run("encoding", func(t *testing.T) {
		err := OpenAndEncode(CreateMockFile(t, BadDecode), YAML, new(badMarshaller))
		if errors.Is(err, ErrorEncode) != true {
			t.Fatalf("Expected encoding error, got %v", err)
		}
	})

	t.Run("file-access", func(t *testing.T) {
		err := OpenAndEncode(CreateMockFile(t, NoPermissions), YAML, new(badMarshaller))
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected File Access error, got %v", err)
		}

		err = OpenAndEncode(CreateMockFile(t, BadDescriptor), YAML, new(badMarshaller))
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected File Access error, got %v", err)
		}
	})
}

func TestOpenOrCreateInDirectory(t *testing.T) {

	t.Run("regular-non-existing-file", func(t *testing.T) {
		fPath := path.Join(t.TempDir(), "some-file.json")
		f, err := OpenOrCreateInDirectory(fPath, "")
		if err != nil {
			t.Fatal()
		}
		// Should be able to read and write to file
		CheckReadWrite(t, f, fPath)
	})

	t.Run("directory", func(t *testing.T) {
		fPath := t.TempDir()
		f, err := OpenOrCreateInDirectory(fPath, "some-new-file.json")
		if err != nil {
			t.Fatal(err)
		}
		CheckReadWrite(t, f, path.Join(fPath, "some-new-file.json"))
	})

	t.Run("file-access-error", func(t *testing.T) {
		_, err := OpenOrCreateInDirectory(CreateMockFile(t, NoPermissions), "")
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}

		_, err = OpenOrCreateInDirectory(CreateMockFile(t, BadDescriptor), "")
		if errors.Is(err, ErrorFileAccess) != true {
			t.Fatalf("Expected file access error, got %v", err)
		}
	})
}

// Helper Functions

func CheckReadWrite(t *testing.T, f io.ReadWriter, filename string) {
	// Should be able to write to file
	if _, err := io.Copy(f, bytes.NewBufferString("content")); err != nil {
		t.Fatal(err)
	}
	// Should be able to read content from that file
	b, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "content" {
		t.Fatalf("Expected '%s', got %s", "content", string(b))
	}
}

type MockFileCondition int

const (
	NoPermissions MockFileCondition = iota
	BadDescriptor
	BadDecode
)

func CreateMockFile(t *testing.T, condition MockFileCondition) string {
	fPath := path.Join(t.TempDir(), "mock-file.file")
	switch condition {
	case NoPermissions:
		if err := os.WriteFile(fPath, []byte("content"), 0000); err != nil {
			t.Fatal(err)
		}
	case BadDescriptor:
		fPath = path.Join(t.TempDir(), "\000x")
	case BadDecode:
		if err := os.WriteFile(fPath, []byte("{content"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return fPath
}

// Mock Objects

type badMarshaller struct{}

func (b badMarshaller) MarshalYAML() (interface{}, error) {
	return nil, errors.New("mock error")
}

func (b badMarshaller) MarshalJSON() ([]byte, error) {
	return nil, errors.New("mock error")
}

type testObj struct {
	FirstName string `json:"firstName" yaml:"firstName"`
	LastName  string `json:"lastName" yaml:"lastName"`
}

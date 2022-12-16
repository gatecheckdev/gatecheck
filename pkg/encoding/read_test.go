package encoding

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/gatecheckdev/gatecheck/pkg/entity"
	"io"
	"os"
	"testing"
	"time"
)

func TestDetectGitleaksBytes(t *testing.T) {
	gitleaksScanReport := entity.GitLeaksScanReport{
		entity.GitleaksFinding{Description: "Some Description 1"},
		entity.GitleaksFinding{Description: "Some Description 2"},
		entity.GitleaksFinding{Description: "Some Description 3"},
	}
	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(gitleaksScanReport)

	TestTable := []BytesTestCase{
		{Case: buf.Bytes(), Expected: Gitleaks},
		{Case: nil, Expected: Unsupported},
		{Case: []byte("[]"), Expected: Gitleaks},
		{Case: []byte("{{"), Expected: Unsupported},
	}

	for _, item := range TestTable {
		if rType := detectGitleaksBytes(item.Case); rType != item.Expected {
			t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
		}
	}
}

func TestDetectSemgrep(t *testing.T) {

	semgrepScanReport := entity.SemgrepScanReport{Version: "1.1.1"}

	buf := new(bytes.Buffer)
	_ = json.NewEncoder(buf).Encode(semgrepScanReport)

	testTable := []BytesTestCase{
		{Case: nil, Expected: Unsupported},
		{Case: buf.Bytes(), Expected: Semgrep},
	}

	for _, item := range testTable {
		if rType := detectSemgrepBytes(item.Case); rType != item.Expected {
			t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
		}
	}
}

func TestDetectGrype(t *testing.T) {
	grypeBytes := MustReadFile("../../test/grype-report.json", t.Fatal)

	testTable := []BytesTestCase{
		{Case: nil, Expected: Unsupported},
		{Case: grypeBytes, Expected: Grype},
	}

	for _, item := range testTable {
		if rType := detectGrypeBytes(item.Case); rType != item.Expected {
			t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
		}
	}
}

func TestRead(t *testing.T) {
	grypeBytes := MustReadFile("../../test/grype-report.json", t.Fatal)
	semgrepBytes := MustReadFile("../../test/semgrep-sast-report.json", t.Fatal)
	gitleaksBytes := MustReadFile("../../test/gitleaks-report.json", t.Fatal)

	var getTestTable = func() []ReaderTestCase {
		return []ReaderTestCase{
			{Case: bytes.NewBuffer(grypeBytes), Expected: Grype},
			{Case: bytes.NewBuffer(semgrepBytes), Expected: Semgrep},
			{Case: bytes.NewBuffer(gitleaksBytes), Expected: Gitleaks},
			{Case: badReader{}, Expected: Unsupported},
			{Case: bytes.NewBufferString("unsupported file content"), Expected: Unsupported},
		}
	}

	t.Run("Read", func(t *testing.T) {
		for _, item := range getTestTable() {
			if rType, _, _ := Read(item.Case); rType != item.Expected {
				t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
			}
		}
	})

	t.Run("ReadWithContext", func(t *testing.T) {
		for i, item := range getTestTable() {
			if rType, _, _ := ReadWithContext(context.Background(), item.Case); rType != item.Expected {
				t.Fatalf("Item %d: Expected %s for %+v, Got %s", i, item.Expected, item.Case, rType)
			}
		}
	})

	t.Run("ReadWithContext-timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()

		if _, _, err := ReadWithContext(ctx, bytes.NewBuffer(grypeBytes)); errors.Is(err, context.Canceled) != true {
			t.FailNow()
		}
	})

}

func BenchmarkRead(b *testing.B) {
	grypeBytes := MustReadFile("../../test/grype-report.json", b.Fatal)
	semgrepBytes := MustReadFile("../../test/semgrep-sast-report.json", b.Fatal)
	gitleaksBytes := MustReadFile("../../test/gitleaks-report.json", b.Fatal)

	b.Run("InspectWithContext", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = InspectWithContext(context.Background(), bytes.NewBuffer(grypeBytes))
			_, _ = InspectWithContext(context.Background(), bytes.NewBuffer(semgrepBytes))
			_, _ = InspectWithContext(context.Background(), bytes.NewBuffer(gitleaksBytes))
		}
	})

	b.Run("async-no-context", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			_, _ = Inspect(bytes.NewBuffer(grypeBytes))
			_, _ = Inspect(bytes.NewBuffer(semgrepBytes))
			_, _ = Inspect(bytes.NewBuffer(gitleaksBytes))
		}
	})
}

// Test Resources
func MustReadFile(filename string, fatalFunc func(args ...any)) []byte {
	fileBytes, err := os.ReadFile(filename)
	if err != nil {
		fatalFunc(err)
	}
	return fileBytes
}

type ReaderTestCase struct {
	Case     io.Reader
	Expected EntityType
}

type BytesTestCase struct {
	Case     []byte
	Expected EntityType
}

type badReader struct{}

func (b badReader) Read(_ []byte) (int, error) {
	return 0, errors.New("mock error")
}

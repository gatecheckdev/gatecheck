package encoding

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestInspect(t *testing.T) {
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

	t.Run("InspectWithContext", func(t *testing.T) {
		for _, item := range getTestTable() {
			if rType, _ := InspectWithContext(context.Background(), item.Case); rType != item.Expected {
				t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
			}
		}
	})

	t.Run("InspectWithContext-timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()

		if _, err := InspectWithContext(ctx, bytes.NewBuffer(grypeBytes)); errors.Is(err, context.Canceled) != true {
			t.FailNow()
		}
	})

	t.Run("Inspect", func(t *testing.T) {
		for _, item := range getTestTable() {
			if rType, _ := InspectWithContext(context.Background(), item.Case); rType != item.Expected {
				t.Fatalf("Expected %s for %+v, Got %s", item.Expected, item.Case, rType)
			}
		}
	})
}

func BenchmarkInspect(b *testing.B) {
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

package gatecheck

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
)

func TestListRenderedOutput(t *testing.T) {
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.DiscardHandler))
	t.Cleanup(func() { slog.SetDefault(prev) })

	grype := mustRead(t, "../../test/grype-report.json")
	semgrep := mustRead(t, "../../test/semgrep-sast-report.json")

	t.Run("grype", func(t *testing.T) {
		assertGolden(t, "grype-report.json", grype, nil, "testdata/grype.golden")
	})
	t.Run("grype epss", func(t *testing.T) {
		assertGolden(t, "grype-report.json", grype, []ListOptionFunc{withTestEPSS(t)}, "testdata/grype-epss.golden")
	})
	t.Run("semgrep", func(t *testing.T) {
		assertGolden(t, "semgrep-sast-report.json", semgrep, nil, "testdata/semgrep.golden")
	})
	t.Run("empty gitleaks", func(t *testing.T) {
		assertGolden(t, "gitleaks-report.json", []byte("[]"), nil, "testdata/gitleaks-empty.golden")
	})
}

func TestEmptyReportPrintsALine(t *testing.T) {
	cases := []struct {
		name     string
		filename string
		src      string
		markdown bool
		epss     bool
		want     string
	}{
		{name: "grype", filename: "grype.json", src: `{"matches":[]}`, want: "No grype vulnerabilities\n"},
		{name: "grype markdown", filename: "grype.json", src: `{"matches":[]}`, markdown: true, want: "No grype vulnerabilities\n"},
		{name: "grype epss", filename: "grype.json", src: `{"matches":[]}`, epss: true, want: "No grype vulnerabilities\n"},
		{name: "cyclonedx", filename: "cyclonedx.json", src: `{}`, want: "No cyclonedx vulnerabilities\n"},
		{name: "cyclonedx markdown", filename: "cyclonedx.json", src: `{}`, markdown: true, want: "No cyclonedx vulnerabilities\n"},
		{name: "semgrep", filename: "semgrep.json", src: `{"results":[]}`, want: "No semgrep findings\n"},
		{name: "semgrep markdown", filename: "semgrep.json", src: `{"results":[]}`, markdown: true, want: "No semgrep findings\n"},
		{name: "gitleaks", filename: "gitleaks.json", src: `[]`, want: "No gitleaks findings\n"},
		{name: "gitleaks markdown", filename: "gitleaks.json", src: `[]`, markdown: true, want: "No gitleaks findings\n"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []ListOptionFunc
			if tc.markdown {
				opts = append(opts, WithDisplayFormat("markdown"))
			}
			if tc.epss {
				opts = append(opts, withTestEPSS(t))
			}
			got := renderList(t, tc.filename, []byte(tc.src), opts)
			if got != tc.want {
				t.Fatalf("got %q want %q", got, tc.want)
			}
			if strings.Contains(got, "|") {
				t.Fatalf("empty report rendered a table:\n%s", got)
			}
		})
	}
}

func TestMarkdownListRendersATable(t *testing.T) {
	src := []byte(`{"matches":[{"vulnerability":{"severity":"High","dataSource":"https://example.com"},"artifact":{"name":"pkg","version":"1.2.3"}}]}`)
	got := renderList(t, "grype.json", src, []ListOptionFunc{WithDisplayFormat("markdown")})
	if !strings.Contains(got, "GRYPE SEVERITY") || !strings.Contains(got, "|") {
		t.Fatalf("markdown table missing:\n%s", got)
	}
	if strings.Contains(got, "No grype vulnerabilities") {
		t.Fatalf("non-empty report printed the empty line:\n%s", got)
	}
}

func withTestEPSS(t *testing.T) ListOptionFunc {
	t.Helper()
	raw, err := os.ReadFile("testdata/epss.csv")
	if err != nil {
		t.Fatal(err)
	}
	// Keep the parser on LF if a Windows checkout rewrites the fixture.
	raw = bytes.ReplaceAll(raw, []byte("\r"), nil)
	f, err := os.CreateTemp(t.TempDir(), "epss-*.csv")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(raw); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	opt, err := WithEPSS(f, "")
	if err != nil {
		t.Fatal(err)
	}
	return opt
}

func assertGolden(t *testing.T, filename string, src []byte, opts []ListOptionFunc, golden string) {
	t.Helper()
	got := renderList(t, filename, src, opts)
	wantBytes, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	want := string(bytes.ReplaceAll(wantBytes, []byte("\r\n"), []byte("\n")))
	if got != want {
		t.Fatalf("rendered output does not match %s:\n%s", golden, firstDiff(want, got))
	}
}

func renderList(t *testing.T, filename string, src []byte, opts []ListOptionFunc) string {
	t.Helper()
	var buf bytes.Buffer
	if err := List(&buf, bytes.NewReader(src), filename, opts...); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func firstDiff(want, got string) string {
	wb := strings.Split(want, "\n")
	gb := strings.Split(got, "\n")
	n := len(wb)
	if len(gb) > n {
		n = len(gb)
	}
	var b strings.Builder
	shown := 0
	for i := 0; i < n; i++ {
		var w, g string
		if i < len(wb) {
			w = wb[i]
		}
		if i < len(gb) {
			g = gb[i]
		}
		if w == g {
			continue
		}
		fmt.Fprintf(&b, "line %d\n- %s\n+ %s\n", i+1, w, g)
		shown++
		if shown == 8 {
			break
		}
	}
	return b.String()
}

package format

import (
	"bytes"
	"strings"
	"testing"
)

func TestHeaderAndFooterCase(t *testing.T) {
	buf := new(bytes.Buffer)
	table := NewTable(buf)
	table.Header([]string{"Owasp IDs", "EPSS Prctl"})
	if err := table.Append([]string{"A01", "0.50"}); err != nil {
		t.Fatal(err)
	}
	table.Footer([]string{"50.00%", "1.00%"})
	if err := table.Render(); err != nil {
		t.Fatal(err)
	}

	got := buf.String()
	for _, want := range []string{"OWASP IDS", "EPSS PRCTL", "50.00%", "1.00%"} {
		if !strings.Contains(got, want) {
			t.Fatalf("rendered table missing %q:\n%s", want, got)
		}
	}
	for _, banned := range []string{"OWASP I DS", "50 . 00", "1 . 00"} {
		if strings.Contains(got, banned) {
			t.Fatalf("rendered table contains %q:\n%s", banned, got)
		}
	}
}

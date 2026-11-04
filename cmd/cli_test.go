package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/archive"
)

const (
	grypeReport = "../test/grype-report.json"
	kevJSON     = "../test/known_exploited_vulnerabilities.json"
	epssCSV     = "../test/epss_scores-2023-06-01.csv"
)

type result struct {
	stdout, stderr string
	code           int
}

// run executes a fresh command tree, the same way main does.
func run(t *testing.T, stdin string, args ...string) result {
	t.Helper()
	var out, errb bytes.Buffer
	root := NewGatecheckCommand()
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(args)
	err := root.Execute()
	return result{stdout: out.String(), stderr: errb.String(), code: ExitCode(err)}
}

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func clearEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"GATECHECK_CONFIG_FILENAME", "GATECHECK_AUDIT", "GATECHECK_VERBOSE", "GATECHECK_SILENT",
		"GATECHECK_LOG_LEVEL", "GATECHECK_LOG_FORMAT", "GATECHECK_EPSS_FILENAME", "GATECHECK_KEV_FILENAME",
		"GATECHECK_EPSS_URL", "GATECHECK_KEV_URL", "GATECHECK_VEX", "GATECHECK_BUNDLE_TAG",
	} {
		t.Setenv(key, "")
	}
}

const criticalLimit = "version: \"1\"\ngrype:\n  severityLimit:\n    critical:\n      enabled: true\n      limit: 0\n"

func TestFreshCommandTreePerCall(t *testing.T) {
	a, b := NewGatecheckCommand(), NewGatecheckCommand()
	if a == b {
		t.Fatal("same root returned twice")
	}
	findA, _, _ := a.Find([]string{"validate"})
	findB, _, _ := b.Find([]string{"validate"})
	if findA == findB {
		t.Fatal("validate command is shared between trees")
	}
	if err := findA.Flags().Set("audit", "true"); err != nil {
		t.Fatal(err)
	}
	if findB.Flags().Lookup("audit").Value.String() != "false" {
		t.Fatal("flag value leaked between trees")
	}
}

func TestValidateExitCodes(t *testing.T) {
	clearEnv(t)
	config := writeFile(t, "gatecheck.yaml", criticalLimit)

	if r := run(t, "", "validate", "-f", config, grypeReport); r.code != ExitValidation {
		t.Fatalf("threshold failure: %+v", r)
	}
	if r := run(t, "", "validate", "--audit", "-f", config, grypeReport); r.code != ExitOK || !strings.Contains(r.stderr, "validation failure") {
		t.Fatalf("audit should exit 0 and print the failure: %+v", r)
	}
	if r := run(t, "", "validate", "--audit", "-f", config, "missing.json"); r.code != ExitUsage {
		t.Fatalf("audit must not hide a missing file: %+v", r)
	}
	if r := run(t, "", "validate", "--audit", "-f", "missing.yaml", grypeReport); r.code != ExitUsage {
		t.Fatalf("missing config: %+v", r)
	}
	if r := run(t, "", "validate", "--bogus"); r.code != ExitUsage {
		t.Fatalf("bad flag: %+v", r)
	}
	if r := run(t, "", "validate"); r.code != ExitUsage {
		t.Fatalf("no file: %+v", r)
	}
	unsupported := writeFile(t, "notes.txt", "hello")
	if r := run(t, "", "validate", "--audit", unsupported); r.code != ExitUsage {
		t.Fatalf("audit must not hide an unsupported report: %+v", r)
	}

	kev := writeFile(t, "gatecheck.yaml", "version: \"1\"\ngrype:\n  kevLimitEnabled: true\n")
	if r := run(t, "", "validate", "-f", kev, "--kev-url", "http://127.0.0.1:1/kev.json", grypeReport); r.code != ExitFetch {
		t.Fatalf("kev fetch failure: %+v", r)
	}
	if r := run(t, "", "validate", "--audit", "-f", kev, "--kev-url", "http://127.0.0.1:1/kev.json", grypeReport); r.code != ExitFetch {
		t.Fatalf("audit must not hide a fetch failure: %+v", r)
	}
	if r := run(t, "", "validate", "-f", kev, "--kev-filename", kevJSON, grypeReport); r.code == ExitFetch || r.code == ExitUsage {
		t.Fatalf("local kev file: %+v", r)
	}
}

func TestEnvironmentSettings(t *testing.T) {
	clearEnv(t)
	config := writeFile(t, "gatecheck.yaml", criticalLimit)

	t.Setenv("GATECHECK_CONFIG_FILENAME", config)
	if r := run(t, "", "validate", grypeReport); r.code != ExitValidation {
		t.Fatalf("config from env: %+v", r)
	}
	t.Setenv("GATECHECK_AUDIT", "true")
	if r := run(t, "", "validate", grypeReport); r.code != ExitOK {
		t.Fatalf("audit from env: %+v", r)
	}
	if r := run(t, "", "validate", "--audit=false", grypeReport); r.code != ExitValidation {
		t.Fatalf("--audit=false must beat GATECHECK_AUDIT=true: %+v", r)
	}
	t.Setenv("GATECHECK_AUDIT", "")

	for _, key := range []string{"GATECHECK_VERBOSE", "GATECHECK_SILENT", "GATECHECK_AUDIT"} {
		t.Setenv(key, "true")
		r := run(t, "", "validate", grypeReport)
		if r.code == ExitUsage {
			t.Fatalf("%s=true: %+v", key, r)
		}
		t.Setenv(key, "maybe")
		r = run(t, "", "validate", grypeReport)
		if r.code != ExitUsage || !strings.Contains(r.stderr, key) {
			t.Fatalf("%s=maybe should be a usage error: %+v", key, r)
		}
		t.Setenv(key, "")
	}

	// GATECHECK_KEV_FILENAME is its own setting, not the EPSS one.
	t.Setenv("GATECHECK_CONFIG_FILENAME", writeFile(t, "kev.yaml", "version: \"1\"\ngrype:\n  kevLimitEnabled: true\n"))
	t.Setenv("GATECHECK_KEV_URL", "http://127.0.0.1:1/kev.json")
	t.Setenv("GATECHECK_EPSS_FILENAME", epssCSV)
	if r := run(t, "", "validate", grypeReport); r.code != ExitFetch {
		t.Fatalf("EPSS file must not be read as KEV: %+v", r)
	}
	t.Setenv("GATECHECK_KEV_FILENAME", kevJSON)
	if r := run(t, "", "validate", grypeReport); r.code == ExitFetch || r.code == ExitUsage {
		t.Fatalf("GATECHECK_KEV_FILENAME: %+v", r)
	}
}

func TestLogging(t *testing.T) {
	clearEnv(t)
	r := run(t, "", "validate", grypeReport)
	if !strings.Contains(r.stderr, "no config file") {
		t.Fatalf("missing no-config warning: %q", r.stderr)
	}
	r = run(t, "", "--silent", "validate", grypeReport)
	if !strings.Contains(r.stderr, "no config file") || strings.Contains(r.stderr, "INF") {
		t.Fatalf("--silent should keep warnings and drop info: %q", r.stderr)
	}
	r = run(t, "", "--log-level", "error", "validate", grypeReport)
	if strings.Contains(r.stderr, "no config file") {
		t.Fatalf("--log-level error should drop warnings: %q", r.stderr)
	}
	r = run(t, "", "--log-format", "json", "validate", grypeReport)
	lines := strings.Split(strings.TrimSpace(r.stderr), "\n")
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil || entry["level"] == nil {
		t.Fatalf("json log line %q: %v", lines[0], err)
	}
	if r := run(t, "", "--log-format", "xml", "version"); r.code != ExitUsage {
		t.Fatalf("bad log format: %+v", r)
	}
	if r := run(t, "", "-v", "--silent", "version"); r.code != ExitUsage {
		t.Fatalf("verbose and silent together: %+v", r)
	}
	t.Setenv("GATECHECK_LOG_LEVEL", "debug")
	if r := run(t, "", "validate", grypeReport); !strings.Contains(r.stderr, "DBG") {
		t.Fatalf("GATECHECK_LOG_LEVEL=debug: %q", r.stderr)
	}
}

func TestValidateConfigWarningsAndFormat(t *testing.T) {
	clearEnv(t)
	typo := writeFile(t, "gatecheck.yaml", criticalLimit+"grpye:\n  kevLimitEnabled: true\n")
	r := run(t, "", "validate", "-f", typo, "--format", "json", grypeReport)
	if r.code != ExitValidation || !strings.Contains(r.stderr, "grpye") {
		t.Fatalf("unknown key warning: %+v", r)
	}
	var got validateResult
	if err := json.Unmarshal([]byte(r.stdout), &got); err != nil {
		t.Fatalf("json result %q: %v", r.stdout, err)
	}
	if got.Passed || len(got.Failures) != 1 || !strings.Contains(got.Failures[0], "Grype") {
		t.Fatalf("result %+v", got)
	}

	r = run(t, "", "validate", "--format", "table", grypeReport)
	if r.code != ExitOK || !strings.Contains(r.stdout, "pass") {
		t.Fatalf("table pass: %+v", r)
	}
	r = run(t, "", "validate", "-f", typo, "--format", "markdown", grypeReport)
	if !strings.Contains(r.stdout, "| fail") {
		t.Fatalf("markdown: %q", r.stdout)
	}
	if r := run(t, "", "validate", "--format", "yaml", grypeReport); r.code != ExitUsage {
		t.Fatalf("bad format: %+v", r)
	}
}

func TestValidateInputTypeStdin(t *testing.T) {
	clearEnv(t)
	body, err := os.ReadFile(grypeReport)
	if err != nil {
		t.Fatal(err)
	}
	config := writeFile(t, "gatecheck.yaml", criticalLimit)
	if r := run(t, string(body), "validate", "-f", config, "--input-type", "grype"); r.code != ExitValidation {
		t.Fatalf("stdin: %+v", r)
	}
	lcov := writeFile(t, "report.txt", "SF:a.go\nDA:1,1\nDA:2,0\nLF:2\nLH:1\nend_of_record\n")
	cov := writeFile(t, "gatecheck.yaml", "version: \"1\"\ncoverage:\n  lineThreshold: 80\n")
	r := run(t, "", "validate", "-f", cov, "--input-type", "lcov", lcov)
	if r.code != ExitValidation || !strings.Contains(r.stderr, "percent") {
		t.Fatalf("lcov via --input-type with a percent threshold: %+v", r)
	}
	cov40 := writeFile(t, "gatecheck.yaml", "version: \"1\"\ncoverage:\n  lineThreshold: 40\n")
	if r := run(t, "", "validate", "-f", cov40, "-i", "lcov", lcov); r.code != ExitOK {
		t.Fatalf("40 percent of a 50 percent report should pass: %+v", r)
	}
}

func TestListFormats(t *testing.T) {
	clearEnv(t)
	r := run(t, "", "list", "--format", "json", grypeReport)
	var table struct {
		Columns []string            `json:"columns"`
		Rows    []map[string]string `json:"rows"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &table); err != nil || len(table.Rows) == 0 {
		t.Fatalf("list json %q: %v", r.stdout, err)
	}
	if _, ok := table.Rows[0][table.Columns[0]]; !ok {
		t.Fatalf("rows are not keyed by column: %+v", table.Rows[0])
	}
	if r := run(t, "", "list", "--markdown", grypeReport); !strings.HasPrefix(strings.TrimSpace(r.stdout), "|") {
		t.Fatalf("markdown: %q", r.stdout)
	}
	if r := run(t, "", "list", "--markdown", "--format", "json", grypeReport); r.code != ExitUsage {
		t.Fatalf("conflicting format flags: %+v", r)
	}

	empty := writeFile(t, "gitleaks-report.json", "[]")
	r = run(t, "", "list-all", "--format", "json", grypeReport, empty)
	var all []struct {
		File   string          `json:"file"`
		Report json.RawMessage `json:"report"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &all); err != nil || len(all) != 2 || all[0].File != grypeReport {
		t.Fatalf("list-all json %q: %v", r.stdout, err)
	}
	if r := run(t, "", "list-all", grypeReport, "missing.json"); r.code != ExitUsage || !strings.Contains(r.stdout, "GRYPE") {
		t.Fatalf("list-all with a missing file: %+v", r)
	}
	if r := run(t, "", "list-all", "--epss", "--epss-filename", epssCSV, grypeReport); r.code != ExitOK || !strings.Contains(r.stdout, "EPSS") {
		t.Fatalf("list-all --epss-filename: %+v", r)
	}
}

func TestBundleCommands(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	bundle := filepath.Join(dir, "gatecheck-bundle.tar.gz")
	big := make([]byte, 200_000)
	for i := range big {
		big[i] = byte('a' + i%26)
	}
	if err := os.WriteFile(bundle, big, 0o600); err != nil {
		t.Fatal(err)
	}
	if r := run(t, "", "bundle", "create", "-t", "ci,main", bundle, grypeReport); r.code != ExitOK {
		t.Fatalf("create over a larger file: %+v", r)
	}
	readBundle := func() *archive.Bundle {
		t.Helper()
		f, err := os.Open(bundle)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = f.Close() }()
		b := archive.NewBundle()
		if err := archive.UntarGzipBundle(f, b); err != nil {
			t.Fatalf("bundle is corrupt: %v", err)
		}
		return b
	}
	b := readBundle()
	if tags := b.Manifest().Files["grype-report.json"].Tags; strings.Join(tags, ",") != "ci,main" {
		t.Fatalf("tags %v", tags)
	}

	if r := run(t, "", "bundle", "add", bundle, epssCSV); r.code != ExitOK {
		t.Fatalf("add: %+v", r)
	}
	if r := run(t, "", "bundle", "remove", bundle, "epss_scores-2023-06-01.csv"); r.code != ExitOK {
		t.Fatalf("remove: %+v", r)
	}
	info, err := os.Stat(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if len(readBundle().Manifest().Files) != 1 {
		t.Fatal("remove did not remove")
	}
	if r := run(t, "", "bundle", "remove", bundle, "not-there.json"); r.code != ExitUsage {
		t.Fatalf("removing a missing label should fail: %+v", r)
	}
	after, err := os.Stat(bundle)
	if err != nil {
		t.Fatal(err)
	}
	if after.Size() != info.Size() {
		t.Fatal("failed remove changed the bundle")
	}
}

func TestConfigCommands(t *testing.T) {
	clearEnv(t)
	r := run(t, "", "config", "init")
	if r.code != ExitOK || !strings.Contains(r.stdout, "\n  severityLimit:") {
		t.Fatalf("config init should be indented by two spaces: %q", r.stdout)
	}
	r = run(t, "", "config", "init", "-o", "json")
	if !strings.Contains(r.stdout, "\n  \"version\"") {
		t.Fatalf("json init: %q", r.stdout)
	}
	if r := run(t, "", "config", "init", "-o", "xml"); r.code != ExitUsage {
		t.Fatalf("bad output: %+v", r)
	}
	src := writeFile(t, "gatecheck.yaml", criticalLimit)
	r = run(t, "", "config", "convert", "-f", src, "-o", "toml")
	if r.code != ExitOK || !strings.Contains(r.stdout, "[grype") {
		t.Fatalf("convert: %+v", r)
	}
}

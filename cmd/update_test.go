package cmd

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gatecheckdev/gatecheck/pkg/gatecheck"
)

func TestUpdateCommandFlags(t *testing.T) {
	if updateCmd.Name() != "update" {
		t.Fatalf("name %s", updateCmd.Name())
	}
	aliases := map[string]bool{}
	for _, alias := range updateCmd.Aliases {
		aliases[alias] = true
	}
	if !aliases["self-update"] || !aliases["upgrade"] {
		t.Fatalf("aliases %v", updateCmd.Aliases)
	}
	for _, name := range []string{"check", "version", "yes"} {
		if updateCmd.Flags().Lookup(name) == nil {
			t.Fatalf("missing --%s", name)
		}
	}
	if updateCmd.Flags().ShorthandLookup("y") == nil {
		t.Fatal("missing -y")
	}
}

func TestUpdateCheckCommand(t *testing.T) {
	resetUpdateCommand(t)
	exe := filepath.Join(t.TempDir(), "gatecheck")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	updateExecutable = exe

	var downloaded atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ua := r.Header.Get("User-Agent")
		if !strings.HasPrefix(ua, "gatecheck/") || !strings.Contains(ua, "https://github.com/gatecheckdev/gatecheck") {
			http.Error(w, "bad user agent "+ua, http.StatusBadRequest)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/download/") {
			downloaded.Store(true)
			http.Error(w, "download", http.StatusInternalServerError)
			return
		}
		if r.URL.Path != "/repos/gatecheckdev/gatecheck/releases/latest" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprint(w, `{"tag_name":"v0.9.0","assets":[]}`)
	}))
	t.Cleanup(srv.Close)
	updateAPIBase = srv.URL

	prev := ApplicationMetadata
	t.Cleanup(func() { ApplicationMetadata = prev })
	ApplicationMetadata.CLIVersion = "0.8.0"

	stdout, stderr, err := executeUpdate(t, "", "--check")
	if err != nil {
		t.Fatalf("check: %v\n%s\n%s", err, stdout, stderr)
	}
	if stdout != "current v0.8.0\nlatest v0.9.0\n" {
		t.Fatalf("stdout %q stderr %q", stdout, stderr)
	}
	if downloaded.Load() {
		t.Fatal("downloaded an asset")
	}
	got, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatal("binary changed")
	}
}

func TestUpdateCommandRefusesDevBuild(t *testing.T) {
	resetUpdateCommand(t)
	exe := filepath.Join(t.TempDir(), "gatecheck")
	if err := os.WriteFile(exe, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	updateExecutable = exe
	var called atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Store(true)
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	updateAPIBase = srv.URL

	prev := ApplicationMetadata
	t.Cleanup(func() { ApplicationMetadata = prev })
	ApplicationMetadata = gatecheck.ApplicationMetadata{CLIVersion: "[Not Provided]"}

	_, _, err := executeUpdate(t, "")
	if err == nil || !strings.Contains(err.Error(), "--version") {
		t.Fatalf("error %v", err)
	}
	if called.Load() {
		t.Fatal("dev build contacted the network")
	}
}

func resetUpdateCommand(t *testing.T) {
	t.Helper()
	updateAPIBase = ""
	updateExecutable = ""
	if err := updateCmd.Flags().Set("check", "false"); err != nil {
		t.Fatal(err)
	}
	if err := updateCmd.Flags().Set("version", ""); err != nil {
		t.Fatal(err)
	}
	if err := updateCmd.Flags().Set("yes", "false"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		updateAPIBase = ""
		updateExecutable = ""
		_ = updateCmd.Flags().Set("check", "false")
		_ = updateCmd.Flags().Set("version", "")
		_ = updateCmd.Flags().Set("yes", "false")
		updateCmd.SetArgs(nil)
	})
}

func executeUpdate(t *testing.T, stdin string, args ...string) (string, string, error) {
	t.Helper()
	addCommandOnce(gatecheckCmd, updateCmd)
	out := &bytes.Buffer{}
	errBuf := &bytes.Buffer{}
	root := updateCmd.Root()
	root.SetOut(out)
	root.SetErr(errBuf)
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append([]string{"update"}, args...))
	err := root.Execute()
	t.Cleanup(func() { root.SetArgs([]string{}) })
	return out.String(), errBuf.String(), err
}

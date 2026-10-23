package cmd

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/gatecheckdev/gatecheck/internal/bootstrap"
	"github.com/spf13/cobra"
)

func TestBootstrapCommandListAndPassthrough(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GATECHECK_HOME", home)
	emptyPath := t.TempDir()
	originalPath := os.Getenv("PATH")
	t.Setenv("PATH", emptyPath)

	root := NewGatecheckCommand()
	t.Cleanup(func() {
		command, _, err := root.Find([]string{"bootstrap"})
		if err != nil {
			return
		}
		_ = command.Flags().Set("list", "false")
		_ = command.Flags().Set("force", "false")
		_ = command.Flags().Set("tools", "")
	})

	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs([]string{"bootstrap", "--list"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	for _, version := range []string{bootstrap.GrypeVersion, bootstrap.SyftVersion, bootstrap.GitleaksVersion, bootstrap.SemgrepVersion} {
		if !strings.Contains(out.String(), version) {
			t.Fatalf("list missing %s\n%s", version, out.String())
		}
	}

	out.Reset()
	errb.Reset()
	root.SetArgs([]string{"bootstrap", "--help"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
	help := out.String()
	for _, flag := range []string{"--tools", "--force", "--list"} {
		if !strings.Contains(help, flag) {
			t.Fatalf("help missing %s\n%s", flag, help)
		}
	}
	clearHelp(root)

	out.Reset()
	errb.Reset()
	root.SetArgs([]string{"bootstrap", "--tools", "trivy"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected unknown tool")
	}

	out.Reset()
	errb.Reset()
	root.SetArgs([]string{"grype", "--version"})
	err := root.Execute()
	if !errors.Is(err, bootstrap.ErrNotInstalled) {
		t.Fatalf("err %v stderr %q", err, errb.String())
	}
	if errb.String() != "gatecheck: grype is not installed; run `gatecheck bootstrap`\n" {
		t.Fatalf("hint %q", errb.String())
	}

	t.Setenv("PATH", originalPath)

	stub := filepath.Join(t.TempDir(), "stub")
	if runtime.GOOS == "windows" {
		stub += ".exe"
	}
	buildCmdStub(t, stub)
	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(binDir, "grype")
	if runtime.GOOS == "windows" {
		dest += ".exe"
	}
	body, err := os.ReadFile(stub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, body, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dest, 0o755); err != nil {
		t.Fatal(err)
	}

	out.Reset()
	errb.Reset()
	root.SetArgs([]string{"grype", "fail"})
	err = root.Execute()
	var exitErr *bootstrap.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 4 {
		t.Fatalf("exit %v stdout %q stderr %q", err, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "fail") {
		t.Fatalf("stdout %q", out.String())
	}
	if strings.Contains(errb.String(), "exit status") {
		t.Fatalf("cobra printed the exit error: %q", errb.String())
	}
}

func clearHelp(root *cobra.Command) {
	if flag := root.Flags().Lookup("help"); flag != nil {
		_ = flag.Value.Set("false")
	}
	for _, command := range root.Commands() {
		if flag := command.Flags().Lookup("help"); flag != nil {
			_ = flag.Value.Set("false")
		}
	}
}

func buildCmdStub(t *testing.T, out string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module stub\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := []byte("package main\nimport (\n\t\"fmt\"\n\t\"os\"\n\t\"strings\"\n)\nfunc main() {\n\tfmt.Println(strings.Join(os.Args[1:], \" \"))\n\tif len(os.Args) > 1 && os.Args[1] == \"fail\" {\n\t\tos.Exit(4)\n\t}\n}\n")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), src, 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build stub: %v\n%s", err, output)
	}
}

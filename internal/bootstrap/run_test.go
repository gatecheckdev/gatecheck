package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWithExperimental(t *testing.T) {
	t.Parallel()
	got := withExperimental("/opt/gatecheck/bin/osemgrep", []string{"scan", "-e", "eval($X)"})
	if strings.Join(got, " ") != "scan --experimental -e eval($X)" {
		t.Fatalf("%q", got)
	}
	got = withExperimental("/opt/gatecheck/bin/osemgrep.exe", []string{"scan", "--experimental", "-e", "x"})
	if strings.Count(strings.Join(got, " "), "--experimental") != 1 {
		t.Fatalf("%q", got)
	}
	got = withExperimental("/opt/gatecheck/bin/osemgrep", []string{"--version"})
	if strings.Join(got, " ") != "--version" {
		t.Fatalf("%q", got)
	}
	got = withExperimental("/usr/bin/semgrep", []string{"scan", "-e", "x"})
	if strings.Join(got, " ") != "scan -e x" {
		t.Fatalf("%q", got)
	}
}

func TestRunPassthrough(t *testing.T) {
	stub := filepath.Join(t.TempDir(), exeFile("stub"))
	buildStub(t, stub)

	home := t.TempDir()
	managedDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(managedDir, 0o755); err != nil {
		t.Fatal(err)
	}
	managed := filepath.Join(managedDir, exeFile("grype"))
	if err := copyFile(stub, managed); err != nil {
		t.Fatal(err)
	}
	pathDir := t.TempDir()
	pathBin := filepath.Join(pathDir, exeFile("grype"))
	if err := copyFile(stub, pathBin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)

	var out, errb bytes.Buffer
	err := Run(context.Background(), "grype", []string{"fail"}, home, nil, &out, &errb)
	var exitErr *ExitError
	if !errors.As(err, &exitErr) || exitErr.Code != 4 {
		t.Fatalf("exit %v out %q err %q", err, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), filepath.Base(managed)) || !strings.Contains(out.String(), "fail") {
		t.Fatalf("managed binary was not used: %q", out.String())
	}
	if errb.Len() != 0 {
		t.Fatalf("stderr %q", errb.String())
	}

	out.Reset()
	if err := Run(context.Background(), "grype", []string{"ok"}, t.TempDir(), nil, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "ok") || strings.Contains(out.String(), managed) {
		t.Fatalf("PATH fallback was not used: %q", out.String())
	}

	t.Setenv("PATH", t.TempDir())
	out.Reset()
	errb.Reset()
	err = Run(context.Background(), "grype", nil, t.TempDir(), nil, &out, &errb)
	if !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err %v out %q", err, out.String())
	}
	if errb.String() != "gatecheck: grype is not installed; run `gatecheck bootstrap`\n" {
		t.Fatalf("hint %q", errb.String())
	}

	ose := filepath.Join(managedDir, exeFile("osemgrep"))
	if err := copyFile(stub, ose); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if err := Run(context.Background(), "semgrep", []string{"scan", "-e", "x"}, home, nil, &out, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "scan --experimental -e x") {
		t.Fatalf("experimental args %q", out.String())
	}

	semgrepPath := filepath.Join(pathDir, exeFile("semgrep"))
	if err := copyFile(stub, semgrepPath); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)
	var stdinOut bytes.Buffer
	if err := Run(context.Background(), "semgrep", []string{"stdin"}, t.TempDir(), strings.NewReader("hello"), &stdinOut, &errb); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdinOut.String(), "hello") {
		t.Fatalf("stdin %q", stdinOut.String())
	}
	if strings.Contains(stdinOut.String(), "--experimental") {
		t.Fatalf("python semgrep got --experimental: %q", stdinOut.String())
	}
}

func exeFile(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

func buildStub(t *testing.T, out string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module stub\n\ngo 1.26.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := `package main
import (
	"fmt"
	"io"
	"os"
	"strings"
)
func main() {
	fmt.Println(os.Args[0])
	if len(os.Args) > 1 && os.Args[1] == "stdin" {
		_, _ = io.Copy(os.Stdout, os.Stdin)
		return
	}
	fmt.Println(strings.Join(os.Args[1:], " "))
	for _, arg := range os.Args[1:] {
		if arg == "fail" {
			os.Exit(4)
		}
	}
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
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

func copyFile(src, dst string) error {
	body, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := os.WriteFile(dst, body, 0o755); err != nil {
		return err
	}
	return os.Chmod(dst, 0o755)
}

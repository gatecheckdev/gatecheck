package bootstrap

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ErrNotInstalled means neither the managed binary nor a PATH fallback exists.
var ErrNotInstalled = errors.New("scanner is not installed")

// ExitError is the status of a passthrough process.
// The CLI maps ExitCode onto the process exit status.
type ExitError struct {
	Code int
}

func (e *ExitError) Error() string {
	return fmt.Sprintf("exit status %d", e.Code)
}

// ExitCode returns the process status to pass through.
func (e *ExitError) ExitCode() int {
	return e.Code
}

// Run execs the managed scanner, or the same tool on PATH when the managed copy is absent.
// osemgrep scan gets --experimental inserted when the caller did not pass it.
func Run(ctx context.Context, tool string, args []string, home string, stdin io.Reader, stdout, stderr io.Writer) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}

	bin, err := resolveBinary(tool, home)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "gatecheck: %s is not installed; run `gatecheck bootstrap`\n", tool)
		return ErrNotInstalled
	}

	args = withExperimental(bin, args)
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err = cmd.Run()
	if err == nil {
		return nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return &ExitError{Code: exitErr.ExitCode()}
	}
	return err
}

func resolveBinary(tool, home string) (string, error) {
	if strings.TrimSpace(home) == "" {
		if dir, err := ResolveHome(""); err == nil {
			home = dir
		}
	}
	if strings.TrimSpace(home) != "" {
		managed := managedBinary(BinDir(home), tool)
		if info, err := os.Stat(managed); err == nil && !info.IsDir() {
			return managed, nil
		}
	}
	for _, name := range pathFallback(tool) {
		found, err := exec.LookPath(name)
		if err == nil {
			return found, nil
		}
	}
	return "", ErrNotInstalled
}

func managedBinary(binDir, tool string) string {
	name := tool
	if tool == "semgrep" || tool == "osemgrep" {
		name = "osemgrep"
	}
	return filepath.Join(binDir, exeName(name, runtime.GOOS))
}

func pathFallback(tool string) []string {
	switch tool {
	case "semgrep":
		return []string{"semgrep", "osemgrep"}
	case "osemgrep":
		return []string{"osemgrep"}
	default:
		return []string{tool}
	}
}

// withExperimental inserts --experimental after scan when bin is osemgrep and the flag is absent.
func withExperimental(bin string, args []string) []string {
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(bin)), ".exe")
	if base != "osemgrep" {
		return args
	}
	if !containsArg(args, "scan") || containsArg(args, "--experimental") {
		return args
	}
	out := make([]string, 0, len(args)+1)
	inserted := false
	for _, arg := range args {
		out = append(out, arg)
		if !inserted && arg == "scan" {
			out = append(out, "--experimental")
			inserted = true
		}
	}
	return out
}

func containsArg(args []string, want string) bool {
	for _, arg := range args {
		if arg == want {
			return true
		}
	}
	return false
}

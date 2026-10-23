package update

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestSwapUnixReplacesExistingFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("renaming over an existing file is the windows path")
	}
	dir := t.TempDir()
	dest := filepath.Join(dir, "gatecheck")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "next")
	if err := os.WriteFile(tmp, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	leftover, err := swapFile(dest, tmp, "linux")
	if err != nil {
		t.Fatal(err)
	}
	if leftover != "" {
		t.Fatalf("leftover %s", leftover)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content %q", got)
	}
}

func TestSwapWindowsReplacesAndRemovesBackup(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "gatecheck.exe")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(dir, "next")
	if err := os.WriteFile(tmp, []byte("new"), 0o755); err != nil {
		t.Fatal(err)
	}
	leftover, err := swapFile(dest, tmp, "windows")
	if err != nil {
		t.Fatal(err)
	}
	if leftover != "" {
		t.Fatalf("leftover %s", leftover)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("content %q", got)
	}
	if _, err := os.Stat(dest + ".old"); !os.IsNotExist(err) {
		t.Fatalf("backup remains: %v", err)
	}
}

func TestSwapWindowsRestoresPreviousBinary(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "gatecheck.exe")
	if err := os.WriteFile(dest, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := swapWindows(dest, filepath.Join(dir, "missing"))
	if err == nil {
		t.Fatal("expected rename to fail")
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "old" {
		t.Fatalf("restored %q", got)
	}
}

func TestNotWritableDirectory(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("directory mode bits do not block this user")
	}
	dir := t.TempDir()
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	err := ensureWritable(dir)
	if err == nil {
		t.Fatal("expected permission error")
	}
	if !strings.Contains(err.Error(), "sudo") || !strings.Contains(err.Error(), "reinstall") {
		t.Fatalf("error %v", err)
	}
}

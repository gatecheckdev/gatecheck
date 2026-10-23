package update

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func resolveExecutable(path string) (string, error) {
	if path == "" {
		resolved, err := os.Executable()
		if err != nil {
			return "", fmt.Errorf("find the running gatecheck binary: %w", err)
		}
		path = resolved
	}
	resolved, err := evalSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("resolve the running gatecheck binary: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("resolve the running gatecheck binary: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("resolve the running gatecheck binary: %s is a directory", resolved)
	}
	return resolved, nil
}

func evalSymlinks(path string) (string, error) {
	return filepath.EvalSymlinks(path)
}

func dirOf(path string) string {
	return filepath.Dir(path)
}

func ensureWritable(dir string) error {
	f, err := os.CreateTemp(dir, ".gatecheck-write-check-*")
	if err != nil {
		return writeError(dir, err)
	}
	name := f.Name()
	closeErr := f.Close()
	removeErr := os.Remove(name)
	if closeErr != nil {
		return writeError(dir, closeErr)
	}
	if removeErr != nil {
		return writeError(dir, removeErr)
	}
	return nil
}

func installBinary(dest string, data []byte, goos string) (string, error) {
	info, err := os.Stat(dest)
	if err != nil {
		return "", writeError(dirOf(dest), err)
	}
	mode := info.Mode().Perm()
	if mode&0o111 == 0 {
		mode |= 0o755
	}
	tmp, err := writeTemp(dirOf(dest), data, mode)
	if err != nil {
		return "", writeError(dirOf(dest), err)
	}
	leftover, err := swapFile(dest, tmp, goos)
	if err != nil {
		return "", writeError(dirOf(dest), err)
	}
	return leftover, nil
}

func writeTemp(dir string, data []byte, mode os.FileMode) (string, error) {
	f, err := os.CreateTemp(dir, ".gatecheck-new-*")
	if err != nil {
		return "", err
	}
	name := f.Name()
	success := false
	defer func() {
		if !success {
			_ = f.Close()
			_ = os.Remove(name)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Chmod(mode); err != nil {
		return "", err
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	success = true
	return name, nil
}

func swapFile(dest, tmp, goos string) (string, error) {
	if goos == "windows" {
		return swapWindows(dest, tmp)
	}
	if err := os.Rename(tmp, dest); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	return "", nil
}

// swapWindows renames the running executable aside before moving the new one
// into place. Windows refuses to overwrite an executable that is still running.
func swapWindows(dest, tmp string) (string, error) {
	backup := dest + ".old"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		backup = fmt.Sprintf("%s.old-%d", dest, time.Now().UnixNano())
	}
	if err := os.Rename(dest, backup); err != nil {
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dest); err != nil {
		if restoreErr := os.Rename(backup, dest); restoreErr != nil {
			_ = os.Remove(tmp)
			return "", fmt.Errorf("replace %s: %w (previous binary is at %s)", dest, err, backup)
		}
		_ = os.Remove(tmp)
		return "", err
	}
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return backup, nil
	}
	return "", nil
}

func writeError(dir string, err error) error {
	if err == nil {
		return nil
	}
	if isNotWritable(err) {
		return fmt.Errorf("cannot update gatecheck in %s: the directory is not writable. Re-run with sudo, or reinstall gatecheck into a directory you can write", dir)
	}
	return fmt.Errorf("update gatecheck in %s: %w", dir, err)
}

func isNotWritable(err error) bool {
	if os.IsPermission(err) {
		return true
	}
	return errors.Is(err, syscall.EROFS) || errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM)
}

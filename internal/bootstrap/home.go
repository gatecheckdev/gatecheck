package bootstrap

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ResolveHome returns the gatecheck data directory.
// An explicit path wins, then GATECHECK_HOME, then the platform data directory.
func ResolveHome(explicit string) (string, error) {
	return resolveHome(runtime.GOOS, readEnv(), explicit)
}

func readEnv() homeEnv {
	return homeEnv{
		GatecheckHome: os.Getenv("GATECHECK_HOME"),
		XDGDataHome:   os.Getenv("XDG_DATA_HOME"),
		Home:          homeDir(),
		LocalAppData:  os.Getenv("LOCALAPPDATA"),
		AppData:       os.Getenv("APPDATA"),
	}
}

func homeDir() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return dir
}

type homeEnv struct {
	GatecheckHome string
	XDGDataHome   string
	Home          string
	LocalAppData  string
	AppData       string
}

func resolveHome(goos string, env homeEnv, explicit string) (string, error) {
	if dir := strings.TrimSpace(explicit); dir != "" {
		return dir, nil
	}
	if dir := strings.TrimSpace(env.GatecheckHome); dir != "" {
		return dir, nil
	}
	switch goos {
	case "windows":
		base := firstNonEmpty(env.LocalAppData, env.AppData, env.Home)
		if base == "" {
			return "", errors.New("cannot locate gatecheck home: set GATECHECK_HOME")
		}
		return filepath.Join(base, "gatecheck"), nil
	case "darwin":
		if dir := strings.TrimSpace(env.XDGDataHome); dir != "" {
			return filepath.Join(dir, "gatecheck"), nil
		}
		if env.Home == "" {
			return "", errors.New("cannot locate gatecheck home: set GATECHECK_HOME")
		}
		return filepath.Join(env.Home, "Library", "Application Support", "gatecheck"), nil
	default:
		if dir := strings.TrimSpace(env.XDGDataHome); dir != "" {
			return filepath.Join(dir, "gatecheck"), nil
		}
		if env.Home == "" {
			return "", errors.New("cannot locate gatecheck home: set GATECHECK_HOME")
		}
		return filepath.Join(env.Home, ".local", "share", "gatecheck"), nil
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

// BinDir is the directory of managed scanner binaries inside home.
func BinDir(home string) string {
	return filepath.Join(home, "bin")
}

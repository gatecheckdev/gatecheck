package bootstrap

import (
	"path/filepath"
	"testing"
)

func TestResolveHome(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		goos     string
		env      homeEnv
		explicit string
		want     string
	}{
		{
			name:     "explicit",
			goos:     "linux",
			explicit: "/opt/gatecheck",
			env:      homeEnv{GatecheckHome: "/ignored", Home: "/home/ada"},
			want:     "/opt/gatecheck",
		},
		{
			name: "env",
			goos: "linux",
			env:  homeEnv{GatecheckHome: "/srv/gatecheck", XDGDataHome: "/xdg", Home: "/home/ada"},
			want: "/srv/gatecheck",
		},
		{
			name: "xdg",
			goos: "linux",
			env:  homeEnv{XDGDataHome: "/xdg", Home: "/home/ada"},
			want: filepath.Join("/xdg", "gatecheck"),
		},
		{
			name: "linux default",
			goos: "linux",
			env:  homeEnv{Home: "/home/ada"},
			want: filepath.Join("/home/ada", ".local", "share", "gatecheck"),
		},
		{
			name: "darwin xdg",
			goos: "darwin",
			env:  homeEnv{XDGDataHome: "/xdg", Home: "/Users/ada"},
			want: filepath.Join("/xdg", "gatecheck"),
		},
		{
			name: "darwin default",
			goos: "darwin",
			env:  homeEnv{Home: "/Users/ada"},
			want: filepath.Join("/Users/ada", "Library", "Application Support", "gatecheck"),
		},
		{
			name: "windows localappdata",
			goos: "windows",
			env:  homeEnv{LocalAppData: `C:\Users\ada\AppData\Local`, AppData: `C:\Users\ada\AppData\Roaming`, Home: `C:\Users\ada`},
			want: filepath.Join(`C:\Users\ada\AppData\Local`, "gatecheck"),
		},
		{
			name: "windows appdata",
			goos: "windows",
			env:  homeEnv{AppData: `C:\Users\ada\AppData\Roaming`, Home: `C:\Users\ada`},
			want: filepath.Join(`C:\Users\ada\AppData\Roaming`, "gatecheck"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := resolveHome(tc.goos, tc.env, tc.explicit)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}

	if _, err := resolveHome("linux", homeEnv{}, ""); err == nil {
		t.Fatal("expected error when home is unknown")
	}
}

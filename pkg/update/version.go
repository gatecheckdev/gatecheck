package update

import (
	"errors"
	"fmt"
	"strings"
)

// compareVersions reports the semver precedence of a relative to b.
// A leading v is ignored. Build metadata is ignored. A prerelease is older
// than the same numbered release.
func compareVersions(a, b string) (int, error) {
	pa, err := parseSemver(a)
	if err != nil {
		return 0, fmt.Errorf("invalid version %q", strings.TrimSpace(a))
	}
	pb, err := parseSemver(b)
	if err != nil {
		return 0, fmt.Errorf("invalid version %q", strings.TrimSpace(b))
	}
	return pa.cmp(pb), nil
}

func displayVersion(raw string) string {
	parsed, err := parseSemver(raw)
	if err != nil {
		shown := strings.TrimSpace(raw)
		if shown == "" {
			return "dev"
		}
		return shown
	}
	return "v" + parsed.String()
}

func releaseTag(version string) (string, error) {
	parsed, err := parseSemver(version)
	if err != nil {
		return "", fmt.Errorf("invalid release version %q. Use vX.Y.Z", strings.TrimSpace(version))
	}
	return "v" + parsed.String(), nil
}

type semver struct {
	major int64
	minor int64
	patch int64
	pre   []preID
}

type preID struct {
	num     int64
	str     string
	numeric bool
}

func (v semver) String() string {
	base := fmt.Sprintf("%d.%d.%d", v.major, v.minor, v.patch)
	if len(v.pre) == 0 {
		return base
	}
	parts := make([]string, len(v.pre))
	for i, id := range v.pre {
		if id.numeric {
			parts[i] = fmt.Sprintf("%d", id.num)
		} else {
			parts[i] = id.str
		}
	}
	return base + "-" + strings.Join(parts, ".")
}

func (v semver) cmp(other semver) int {
	if c := cmp64(v.major, other.major); c != 0 {
		return c
	}
	if c := cmp64(v.minor, other.minor); c != 0 {
		return c
	}
	if c := cmp64(v.patch, other.patch); c != 0 {
		return c
	}
	return cmpPre(v.pre, other.pre)
}

func cmpPre(a, b []preID) int {
	switch {
	case len(a) == 0 && len(b) == 0:
		return 0
	case len(a) == 0:
		return 1
	case len(b) == 0:
		return -1
	}
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if c := cmpPreID(a[i], b[i]); c != 0 {
			return c
		}
	}
	return cmp64(int64(len(a)), int64(len(b)))
}

func cmpPreID(a, b preID) int {
	switch {
	case a.numeric && b.numeric:
		return cmp64(a.num, b.num)
	case a.numeric:
		return -1
	case b.numeric:
		return 1
	case a.str < b.str:
		return -1
	case a.str > b.str:
		return 1
	default:
		return 0
	}
}

func cmp64(a, b int64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func parseSemver(raw string) (semver, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return semver{}, errInvalidVersion
	}
	if s[0] == 'v' || s[0] == 'V' {
		s = s[1:]
	}
	if s == "" {
		return semver{}, errInvalidVersion
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		if i == 0 || strings.TrimSpace(s[i+1:]) == "" {
			return semver{}, errInvalidVersion
		}
		s = s[:i]
	}
	var pre string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = s[i+1:]
		s = s[:i]
		if s == "" || pre == "" {
			return semver{}, errInvalidVersion
		}
	}
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, errInvalidVersion
	}
	major, err := parseNumeric(parts[0])
	if err != nil {
		return semver{}, err
	}
	minor, err := parseNumeric(parts[1])
	if err != nil {
		return semver{}, err
	}
	patch, err := parseNumeric(parts[2])
	if err != nil {
		return semver{}, err
	}
	var ids []preID
	if pre != "" {
		for _, part := range strings.Split(pre, ".") {
			id, err := parsePreID(part)
			if err != nil {
				return semver{}, err
			}
			ids = append(ids, id)
		}
	}
	return semver{major: major, minor: minor, patch: patch, pre: ids}, nil
}

func parseNumeric(s string) (int64, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, errInvalidVersion
	}
	var n int64
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errInvalidVersion
		}
		n = n*10 + int64(r-'0')
		if n < 0 {
			return 0, errInvalidVersion
		}
	}
	return n, nil
}

func parsePreID(s string) (preID, error) {
	if s == "" || !validPreID(s) {
		return preID{}, errInvalidVersion
	}
	numeric := true
	for _, r := range s {
		if r < '0' || r > '9' {
			numeric = false
			break
		}
	}
	if !numeric {
		return preID{str: s}, nil
	}
	if len(s) > 1 && s[0] == '0' {
		return preID{}, errInvalidVersion
	}
	n, err := parseNumeric(s)
	if err != nil {
		return preID{}, err
	}
	return preID{num: n, numeric: true}, nil
}

func validPreID(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '-':
		default:
			return false
		}
	}
	return true
}

var errInvalidVersion = errors.New("invalid version")

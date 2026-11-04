package license

import "testing"

func TestParse(t *testing.T) {
	cases := map[string]string{
		"MIT":                                       "MIT",
		"MIT OR Apache-2.0":                         "(MIT OR Apache-2.0)",
		"MIT or Apache-2.0 and BSD-3-Clause":        "(MIT OR (Apache-2.0 AND BSD-3-Clause))",
		"(MIT OR Apache-2.0) AND BSD-3-Clause":      "((MIT OR Apache-2.0) AND BSD-3-Clause)",
		"GPL-2.0-only WITH Classpath-exception-2.0": "GPL-2.0-only WITH Classpath-exception-2.0",
	}
	for in, want := range cases {
		got, err := Parse(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		if got.String() != want {
			t.Errorf("%q parsed as %q, want %q", in, got.String(), want)
		}
	}
	for _, bad := range []string{"", "MIT OR", "(MIT", "AND MIT", "MIT WITH", "public domain"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q should not parse", bad)
		}
	}
}

func TestPolicyCheck(t *testing.T) {
	deny := Policy{Deny: []string{"GPL-*", "AGPL-*"}}
	allow := Policy{Allow: []string{"MIT", "Apache-2.0", "BSD-*"}}
	cases := []struct {
		name     string
		policy   Policy
		licenses []string
		fail     bool
	}{
		{"deny match", deny, []string{"GPL-3.0-only"}, true},
		{"deny case", deny, []string{"gpl-2.0-or-later"}, true},
		{"deny does not hit LGPL", deny, []string{"LGPL-2.1-only"}, false},
		{"or with a way out", deny, []string{"MIT OR GPL-3.0-only"}, false},
		{"and needs both", deny, []string{"MIT AND GPL-3.0-only"}, true},
		{"two entries are and", deny, []string{"MIT", "AGPL-3.0-only"}, true},
		{"with keeps base deny", deny, []string{"GPL-2.0-only WITH Classpath-exception-2.0"}, true},
		{"free text name", Policy{Deny: []string{"public domain"}}, []string{"Public Domain"}, true},
		{"allow hit", allow, []string{"BSD-3-Clause"}, false},
		{"allow miss", allow, []string{"MPL-2.0"}, true},
		{"allow or", allow, []string{"MPL-2.0 OR MIT"}, false},
		{"unknown passes by default", deny, nil, false},
		{"noassertion is unknown", Policy{DenyUnknown: true}, []string{"NOASSERTION"}, true},
		{"deny unknown", Policy{DenyUnknown: true}, []string{""}, true},
		{"deny unknown with license", Policy{DenyUnknown: true}, []string{"MIT"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, fail := tc.policy.Check(Package{Name: "pkg", Version: "1", Licenses: tc.licenses})
			if fail != tc.fail {
				t.Fatalf("fail=%v want %v (%v)", fail, tc.fail, v)
			}
			if fail && v.Error() == "" {
				t.Fatal("empty violation")
			}
		})
	}

	exception := Policy{Deny: []string{"GPL-*"}, Allow: []string{"GPL-2.0-only WITH Classpath-exception-2.0", "MIT"}}
	if v, fail := exception.Check(Package{Licenses: []string{"GPL-2.0-only WITH Classpath-exception-2.0"}}); fail {
		t.Fatalf("explicit WITH allow should pass: %v", v)
	}
	if _, fail := exception.Check(Package{Licenses: []string{"GPL-2.0-only"}}); !fail {
		t.Fatal("bare GPL should still fail")
	}
}

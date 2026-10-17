package routes

import (
	"strings"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name, raw, want string
		ok              bool
	}{
		{"root", "/", "/", true},
		{"plain", "/a/b", "/a/b", true},
		{"trailing slash", "/a/", "/a/", true},
		{"sub-delims and colon", "/a:b@c!$&'()*+,;=", "/a:b@c!$&'()*+,;=", true},
		{"M4 decodes unreserved letter", "/%61dmin", "/admin", true},
		{"M4 decodes tilde", "/%7Euser", "/~user", true},
		{"M4 keeps reserved escape", "/a%3Fb", "/a%3Fb", true},
		{"M4 upper-cases kept escape", "/a%3ab", "/a%3Ab", true},
		{"M4 keeps non-ASCII escape", "/%C3%A9", "/%C3%A9", true},
		{"M4 does not decode twice", "/a%252Fb", "/a%252Fb", true},
		{"M4 resolves dot", "/a/./b", "/a/b", true},
		{"M4 resolves dot-dot", "/a/../b", "/b", true},
		{"M4 trailing dot", "/a/.", "/a/", true},
		{"M4 trailing dot-dot", "/a/b/..", "/a/", true},
		{"M4 dot-dot to root", "/a/..", "/", true},
		{"M4 lone dot", "/.", "/", true},
		{"M4 encoded dot-dot resolved", "/a/%2E%2E/b", "/b", true},
		{"M4 lower-case encoded dot-dot resolved", "/a/%2e%2e/b", "/b", true},
		{"M4 encoded dot resolved", "/a/%2E/b", "/a/b", true},
		{"M4 empty segment", "/a//b", "", false},
		{"M4 leading empty segment", "//admin", "", false},
		{"M4 trailing empty segment", "/a//", "", false},
		{"M4 root empty segment", "//", "", false},
		{"M4 empty segment before dot-dot", "/a//../b", "", false},
		{"M4 empty segment after dot", "/./", "/", true},
		{"M4 dots inside a segment kept", "/a/..b/.c", "/a/..b/.c", true},
		{"M4 dot-dot above root", "/..", "", false},
		{"M4 encoded dot-dot above root", "/%2E%2E/x", "", false},
		{"M4 climbs above root later", "/a/../../b", "", false},
		{"M4 encoded slash", "/a%2Fb", "", false},
		{"M4 lower-case encoded slash", "/a%2fb", "", false},
		{"M5 malformed escape", "/a%zz", "", false},
		{"M5 truncated escape", "/a%2", "", false},
		{"M5 bare percent", "/a%", "", false},
		{"M5 relative", "a/b", "", false},
		{"M5 empty", "", "", false},
		{"M5 asterisk form", "*", "", false},
		{"M5 absolute form", "http://h/a", "", false},
		{"M5 space", "/a b", "", false},
		{"M5 query not matched", "/a?b", "", false},
		{"M5 fragment", "/a#b", "", false},
		{"M5 backslash", `/a\b`, "", false},
		{"M5 raw non-ASCII", "/é", "", false},
		{"M5 control byte", "/a\x00", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := NormalizePath(tt.raw)
			if got != tt.want || ok != tt.ok {
				t.Errorf("NormalizePath(%q) = %q, %v; want %q, %v", tt.raw, got, ok, tt.want, tt.ok)
			}
		})
	}
}

func FuzzNormalizePath(f *testing.F) {
	for _, s := range []string{"/", "/a/./b/../c", "/%2E%2E/", "/a%2Fb", "/%7e%41", "/a//..", "/x/%2e"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, ok := NormalizePath(raw)
		if !ok {
			if got != "" {
				t.Fatalf("NormalizePath(%q) = %q, false; want empty", raw, got)
			}
			return
		}
		if again, ok := NormalizePath(got); !ok || again != got {
			t.Fatalf("NormalizePath(%q) = %q, %v; want %q, true (fixed point of %q)", got, again, ok, got, raw)
		}
		if !strings.HasPrefix(got, "/") || strings.Contains(strings.ToUpper(got), "%2F") {
			t.Fatalf("NormalizePath(%q) = %q, want a path without an encoded slash", raw, got)
		}
		segs := strings.Split(got[1:], "/")
		for i, seg := range segs {
			if seg == "." || seg == ".." || (seg == "" && i < len(segs)-1) {
				t.Fatalf("NormalizePath(%q) = %q, want no dot or empty segment", raw, got)
			}
		}
		for i := 0; i < len(got); i++ {
			if got[i] == '%' && (unreserved(fromHex(got[i+1:i+3])) || strings.ToUpper(got[i+1:i+3]) != got[i+1:i+3]) {
				t.Fatalf("NormalizePath(%q) = %q, want unreserved characters decoded and hex upper-case", raw, got)
			}
		}
	})
}

func fromHex(s string) byte {
	hi, _ := unhex(s[0])
	lo, _ := unhex(s[1])
	return hi<<4 | lo
}

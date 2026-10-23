package routes

import "strings"

const upperHex = "0123456789ABCDEF"

// NormalizePath returns the path that the router matches a request by (M4).
// raw is the request-target's path bytes as received, without the query; see
// Table.Select. NormalizePath decodes percent-encoded unreserved characters,
// upper-cases the hex of every other escape and resolves dot segments
// (RFC 3986 §5.2.4).
//
// It reports false when the path matches no route (M4, M5): raw does not
// begin with "/", holds a byte outside the RFC 3986 path grammar or a
// malformed escape, encodes "/", has an empty segment other than after a
// trailing "/", or has a ".." segment that would climb above the root. The
// result is a fixed point: normalizing it again returns it unchanged.
func NormalizePath(raw string) (string, bool) {
	if !strings.HasPrefix(raw, "/") {
		return "", false
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		switch {
		case c == '%':
			if i+2 >= len(raw) {
				return "", false
			}
			hi, ok1 := unhex(raw[i+1])
			lo, ok2 := unhex(raw[i+2])
			if !ok1 || !ok2 {
				return "", false
			}
			v := hi<<4 | lo
			switch {
			case v == '/':
				return "", false
			case unreserved(v):
				b.WriteByte(v)
			default:
				b.WriteByte('%')
				b.WriteByte(upperHex[v>>4])
				b.WriteByte(upperHex[v&0xf])
			}
			i += 2
		case c == '/' || pathChar(c):
			b.WriteByte(c)
		default:
			return "", false
		}
	}
	return removeDotSegments(b.String())
}

// removeDotSegments resolves "." and ".." in an absolute path. Unlike
// RFC 3986, it fails on an empty segment other than the last, and on a ".."
// at the root, a dot segment it cannot resolve (M4).
func removeDotSegments(p string) (string, bool) {
	segs := strings.Split(p[1:], "/")
	out := make([]string, 0, len(segs))
	for i, s := range segs {
		last := i == len(segs)-1
		switch s {
		case "":
			if !last {
				return "", false
			}
		case ".":
		case "..":
			if len(out) == 0 {
				return "", false
			}
			out = out[:len(out)-1]
		default:
			out = append(out, s)
			continue
		}
		if last {
			out = append(out, "") // "/a/." and "/a/b/.." both become "/a/"
		}
	}
	return "/" + strings.Join(out, "/"), true
}

func unreserved(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '.' || c == '_' || c == '~'
}

// pathChar reports whether c is an RFC 3986 pchar other than an escape.
func pathChar(c byte) bool {
	return unreserved(c) || strings.IndexByte("!$&'()*+,;=:@", c) >= 0
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

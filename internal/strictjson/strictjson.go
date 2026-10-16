// Package strictjson rejects JSON that encoding/json would accept but
// silently reinterpret: duplicate object keys, unpaired surrogate escapes,
// invalid UTF-8 and trailing documents.
package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

// maxDepth is encoding/json's nesting limit.
const maxDepth = 10000

// Validate returns an error unless data is exactly one UTF-8 JSON document
// with no duplicate object keys, no unpaired surrogate escapes and at most
// 10000 levels of nesting. Run it before encoding/json, which keeps the last
// duplicate and maps unpaired surrogates to U+FFFD. Errors never quote
// document content, so callers may return them for documents holding secrets.
func Validate(data []byte) error {
	if !utf8.Valid(data) {
		return fmt.Errorf("JSON must be UTF-8")
	}
	if err := validateUnicodeEscapes(data); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	// A float64 overflow is valid JSON, and its error would quote the number.
	dec.UseNumber()
	var value func(depth int) error
	value = func(depth int) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		d, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		// Bound the recursion here rather than rely on the decoder: a stack
		// overflow is fatal, not a recoverable panic.
		if depth >= maxDepth {
			return fmt.Errorf("JSON exceeds nesting depth %d", maxDepth)
		}
		switch d {
		case '{':
			seen := map[string]bool{}
			for dec.More() {
				key, err := dec.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok {
					return fmt.Errorf("invalid JSON key")
				}
				if seen[k] {
					return fmt.Errorf("duplicate JSON object key")
				}
				seen[k] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return fmt.Errorf("unexpected JSON delimiter")
		}
		_, err = dec.Token()
		return err
	}
	if err := value(0); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("JSON document is empty or truncated")
		}
		// This SyntaxError quotes the offending byte.
		if se := (*json.SyntaxError)(nil); errors.As(err, &se) && strings.HasPrefix(se.Error(), "invalid character") {
			return fmt.Errorf("invalid character in JSON at offset %d", se.Offset)
		}
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("expected exactly one JSON document")
	}
	return nil
}

// encoding/json replaces unpaired surrogates with U+FFFD. Reject them rather
// than allowing distinct policy strings to silently collapse during decoding.
func validateUnicodeEscapes(data []byte) error {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			break
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			break
		}
		n, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			continue
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return fmt.Errorf("unpaired Unicode surrogate")
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return fmt.Errorf("unpaired Unicode surrogate")
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return fmt.Errorf("unpaired Unicode surrogate")
			}
			i += 6
		}
	}
	return nil
}

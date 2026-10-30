package yamlutil

import (
	"bytes"
	"strings"
	"testing"
)

type document struct {
	Name    string         `yaml:"name"`
	Nested  nested         `yaml:"nested"`
	Indexed map[int]string `yaml:"indexed"`
}

type nested struct {
	Value string `yaml:"value"`
}

// A measured document means one thing. Every input here could be read as two.
func TestDecodeTreeRefusesAmbiguousDocuments(t *testing.T) {
	for name, data := range map[string][]byte{
		"empty":              nil,
		"oversized":          bytes.Repeat([]byte("a"), maxDocumentSize+1),
		"malformed":          []byte("name: [a\n"),
		"second document":    []byte("name: a\n---\nname: b\n"),
		"anchor and alias":   []byte("nested: &n\n  value: a\naliased: *n\n"),
		"merge key":          []byte("nested:\n  value: a\n<<:\n  name: b\n"),
		"non-scalar key":     []byte("? [a, b]\n: a\n"),
		"noncanonical index": []byte("indexed:\n  01: a\n"),
		"hex index":          []byte("indexed:\n  0x1: a\n"),
		"duplicate key":      []byte("name: a\nname: b\n"),
		"nested duplicate":   []byte("nested:\n  value: a\n  value: b\n"),
		"deep nesting":       []byte(strings.Repeat("[", maxDepth+2) + strings.Repeat("]", maxDepth+2)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeTree(data); err == nil {
				t.Fatalf("accepted %s input", name)
			}
		})
	}
}

func TestDecodeRefusesAnUndeclaredField(t *testing.T) {
	var doc document
	if err := Decode([]byte("name: a\nrole: server\n"), &doc); err == nil {
		t.Fatal("accepted a field the target type does not declare")
	}
}

func TestDecodeAndDecodeTreeAgreeOnWhatTheDocumentWrote(t *testing.T) {
	data := []byte("name: a\nnested:\n  value: b\nindexed:\n  1: c\n")
	var doc document
	if err := Decode(data, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Name != "a" || doc.Nested.Value != "b" || doc.Indexed[1] != "c" {
		t.Fatalf("decoded %+v", doc)
	}
	tree, err := DecodeTree(data)
	if err != nil {
		t.Fatal(err)
	}
	var written []string
	for i := 0; i < len(tree.Content[0].Content); i += 2 {
		written = append(written, tree.Content[0].Content[i].Value)
	}
	if got := strings.Join(written, ","); got != "name,nested,indexed" {
		t.Fatalf("tree reports the keys %q", got)
	}
}

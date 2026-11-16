package strictjson

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name  string
		input string
		ok    bool
	}{
		{"object", `{"a":1,"b":[{"a":2}]}`, true},
		{"scalar", `"x"`, true},
		{"number beyond float64", `[123456789e9999]`, true},
		{"paired surrogate escape", `"\ud83d\ude00"`, true},
		{"same key in sibling objects", `[{"a":1},{"a":2}]`, true},
		{"duplicate key", `{"a":1,"a":2}`, false},
		{"nested duplicate key", `{"a":{"b":1,"b":1}}`, false},
		{"duplicate key in array element", `[{"a":1,"a":1}]`, false},
		{"trailing document", `{} {}`, false},
		{"trailing garbage", `{}x`, false},
		{"invalid UTF-8", "\"\xff\"", false},
		{"lone low surrogate", `"\udc00"`, false},
		{"lone high surrogate", `"\ud83dx"`, false},
		{"empty", ``, false},
		{"truncated", `{"a":`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate([]byte(tt.input))
			if (err == nil) != tt.ok {
				t.Errorf("Validate(%q) = %v, want ok %v", tt.input, err, tt.ok)
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	type document struct {
		Name string `json:"name"`
	}
	var decoded document
	if err := Unmarshal([]byte(`{"name":"a"}`), &decoded); err != nil || decoded.Name != "a" {
		t.Fatalf("Unmarshal() = %+v, %v, want name a", decoded, err)
	}
	for _, tt := range []struct {
		name  string
		input string
	}{
		{"unknown field", `{"name":"a","surprise":1}`},
		{"duplicate known key", `{"name":"a","name":"a"}`},
		{"trailing document", `{"name":"a"} {}`},
		{"invalid UTF-8", "{\"name\":\"\xff\"}"},
		{"empty", ``},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var decoded document
			if err := Unmarshal([]byte(tt.input), &decoded); err == nil {
				t.Errorf("Unmarshal(%q) = %+v, want an error", tt.input, decoded)
			}
		})
	}
}

// A map target names no field, so validation is all that refuses a duplicate key.
func TestUnmarshalIntoAMapRefusesADuplicateKey(t *testing.T) {
	var fields map[string]json.RawMessage
	if err := Unmarshal([]byte(`{"a":1,"a":2}`), &fields); err == nil {
		t.Errorf("Unmarshal(duplicate key) = %v, want an error", fields)
	}
}

func TestValidateDepth(t *testing.T) {
	nested := func(n int) []byte { return []byte(strings.Repeat("[", n) + strings.Repeat("]", n)) }
	if err := Validate(nested(maxDepth)); err != nil {
		t.Errorf("Validate(%d nested arrays) = %v, want nil", maxDepth, err)
	}
	if err := Validate(nested(maxDepth + 1)); err == nil || !strings.Contains(err.Error(), "depth") {
		t.Errorf("Validate(%d nested arrays) = %v, want a nesting error", maxDepth+1, err)
	}
}

func TestValidateQuotesNoContent(t *testing.T) {
	for _, input := range []string{`{"k":s3cret}`, `[1,s3cret]`, `{"k":1 s3cret}`, `{s3cret:1}`, `{"k":123456789e9999 s3cret}`} {
		if err := Validate([]byte(input)); err == nil || strings.Contains(err.Error(), "'s'") || strings.Contains(err.Error(), "123456789") {
			t.Errorf("Validate(%q) = %v, want an error that quotes no input", input, err)
		}
	}
}

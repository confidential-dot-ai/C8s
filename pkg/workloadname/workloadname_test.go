package workloadname

import (
	"strings"
	"testing"
)

func TestValid(t *testing.T) {
	tests := []struct {
		name           string
		valid, grammar bool
	}{
		{"vllm", true, true},
		{"A0._-", true, true},
		{"a.", true, true},
		{"z", true, true},
		{"Z", true, true},
		{"9", true, true},
		{"x_", true, true},
		{"x-", true, true},
		// Bytes adjacent to each accepted range.
		{"`", false, false},
		{"{", false, false},
		{"@", false, false},
		{"[", false, false},
		{"/", false, false},
		{":", false, false},
		{"_x", false, false},
		{strings.Repeat("a", MaxLen), true, true},
		{strings.Repeat("a", MaxLen+1), false, true},
		{"", false, false},
		{".a", false, false},
		{"-a", false, false},
		{"a/b", false, false},
		{"a b", false, false},
		{"café", false, false},
	}
	for _, tt := range tests {
		if got := Valid(tt.name); got != tt.valid {
			t.Errorf("Valid(%q) = %v, want %v", tt.name, got, tt.valid)
		}
		if got := ValidGrammar(tt.name); got != tt.grammar {
			t.Errorf("ValidGrammar(%q) = %v, want %v", tt.name, got, tt.grammar)
		}
	}
}

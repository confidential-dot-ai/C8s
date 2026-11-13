package testutil

import (
	"strings"
	"testing"
)

// CheckHelpFlags fails t unless the usage section of a command's help has a
// line defining each flag in listed and none defining a flag in omitted. A
// flag is written as help prints it, such as "--url" or "-o, --output".
func CheckHelpFlags(t testing.TB, help string, listed, omitted []string) {
	t.Helper()
	_, usage, ok := strings.Cut(help, "\nUsage:")
	if !ok {
		t.Fatalf("help has no usage section:\n%s", help)
	}
	for _, flag := range listed {
		if !definesFlag(usage, flag) {
			t.Errorf("help does not list %s:\n%s", flag, usage)
		}
	}
	for _, flag := range omitted {
		if definesFlag(usage, flag) {
			t.Errorf("help lists %s:\n%s", flag, usage)
		}
	}
}

func definesFlag(usage, flag string) bool {
	for _, line := range strings.Split(usage, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, flag+" ") || strings.HasPrefix(line, flag+"[") {
			return true
		}
	}
	return false
}

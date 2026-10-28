package cds

import (
	"fmt"
	"regexp"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
)

func compileDNSPatterns(raws []string, path string) ([]*regexp.Regexp, error) {
	patterns, err := cmdsutil.CompileDNSSANPatterns(raws)
	if err != nil {
		return nil, fmt.Errorf("--dns-san-pattern: %w", err)
	}
	if path == "" {
		return patterns, nil
	}
	name, err := cmdsutil.ReadSANFile("--dns-san-file", path)
	if err != nil {
		return nil, err
	}
	literal, err := cmdsutil.CompileDNSSANName(name)
	if err != nil {
		return nil, fmt.Errorf("--dns-san-file: %w", err)
	}
	return append(patterns, literal), nil
}

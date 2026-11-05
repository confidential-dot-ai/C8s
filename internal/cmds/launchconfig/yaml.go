package launchconfig

import (
	"fmt"

	"github.com/confidential-dot-ai/c8s/internal/yamlutil"
)

// Parse strictly validates the offline launch document. Guest callers must
// use Verify first; Parse alone provides no authentication.
func Parse(data []byte) (*Document, error) {
	tree, err := yamlutil.DecodeTree(data)
	if err != nil {
		return nil, fmt.Errorf("launch configuration: %w", err)
	}
	var doc Document
	if err := yamlutil.Decode(data, &doc); err != nil {
		return nil, fmt.Errorf("launch configuration: %w", err)
	}
	doc.serverTokenPresent = yamlutil.PathPresent(tree, "rke2", "serverToken")
	if err := doc.validate(); err != nil {
		return nil, err
	}
	return &doc, nil
}

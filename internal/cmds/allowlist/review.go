package allowlist

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

// A review applies to one byte-exact document. It can accept a search-path
// finding about a measured driver mount, but cannot accept an invalid policy
// or a collision with the live allowlist.
type findingReview struct {
	Schema         string   `json:"schema"`
	DocumentSHA256 string   `json:"documentSha256"`
	ReviewedBy     string   `json:"reviewedBy"`
	Reason         string   `json:"reason"`
	Findings       []string `json:"findings"`
}

func acceptReviewedFindings(cmd *cobra.Command, data []byte, findings []finding, name string) ([]finding, error) {
	if name == "" {
		return findings, nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("read finding review: %w", err)
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, 1<<20))
	dec.DisallowUnknownFields()
	var review findingReview
	if err := dec.Decode(&review); err != nil {
		return nil, fmt.Errorf("parse finding review: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("finding review must contain exactly one JSON object")
	}
	if review.Schema != "c8s.allowlist-review/v1" || strings.TrimSpace(review.ReviewedBy) == "" || strings.TrimSpace(review.Reason) == "" || len(review.Findings) == 0 {
		return nil, fmt.Errorf("finding review requires its schema, reviewer, reason, and findings")
	}
	hash := sha256.Sum256(data)
	if review.DocumentSHA256 != hex.EncodeToString(hash[:]) {
		return nil, fmt.Errorf("finding review does not match the exact allowlist input bytes")
	}
	pending := map[string]bool{}
	for _, text := range review.Findings {
		if text == "" || pending[text] {
			return nil, fmt.Errorf("finding review has an empty or repeated finding")
		}
		pending[text] = true
	}
	var remaining []finding
	var accepted []string
	for _, finding := range findings {
		if !pending[finding.String()] {
			remaining = append(remaining, finding)
			continue
		}
		if !finding.reviewable {
			return nil, fmt.Errorf("finding cannot be accepted by a review: %s", finding)
		}
		delete(pending, finding.String())
		accepted = append(accepted, finding.String())
	}
	if len(pending) != 0 {
		return nil, fmt.Errorf("finding review contains findings absent from this document; review the current input")
	}
	// Print after the whole record passes, so a rejected review reports no
	// accepted finding and cannot make a partial acceptance look successful.
	var output bytes.Buffer
	for _, text := range accepted {
		fmt.Fprintf(&output, "accepted lint finding (%s): %s\n", review.ReviewedBy, text)
	}
	_, err = cmd.ErrOrStderr().Write(output.Bytes())
	return remaining, err
}

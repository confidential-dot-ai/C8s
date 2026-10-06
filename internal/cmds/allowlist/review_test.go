package allowlist

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"testing"

	"github.com/spf13/cobra"
)

func TestFindingReviewCannotAcceptOtherErrorsOrChangedInput(t *testing.T) {
	data := []byte(`{"schema":"c8s.allowlist/v1"}`)
	hash := sha256.Sum256(data)
	reviewed := finding{err: true, msg: "measured driver overlaps PATH", reviewable: true}
	fatal := errorf("two workloads match the same sandbox")
	makeReview := func(findings []string) string {
		r := findingReview{Schema: "c8s.allowlist-review/v1", DocumentSHA256: hex.EncodeToString(hash[:]), ReviewedBy: "operator", Reason: "Measured read-only driver mount", Findings: findings}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return writeFile(t, "review.json", string(b))
	}
	cmd := &cobra.Command{}
	cmd.SetErr(io.Discard)
	path := makeReview([]string{reviewed.String()})
	remaining, err := acceptReviewedFindings(cmd, data, []finding{reviewed, fatal}, path)
	if err != nil || len(remaining) != 1 || remaining[0].msg != fatal.msg {
		t.Fatalf("review hid another error: %v %v", remaining, err)
	}
	if _, err := acceptReviewedFindings(cmd, append(data, '\n'), []finding{reviewed}, path); err == nil {
		t.Fatal("review accepted changed input bytes")
	}
	if _, err := acceptReviewedFindings(cmd, data, []finding{fatal}, makeReview([]string{fatal.String()})); err == nil {
		t.Fatal("review accepted a non-reviewable error")
	}
	if _, err := acceptReviewedFindings(cmd, data, nil, path); err == nil {
		t.Fatal("review accepted a stale finding")
	}
	if _, err := acceptReviewedFindings(cmd, data, []finding{reviewed}, makeReview([]string{reviewed.String(), reviewed.String()})); err == nil {
		t.Fatal("review accepted duplicate findings")
	}
}

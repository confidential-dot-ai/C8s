package steps

import (
	"strings"
	"testing"
	"time"
)

// The window opens when the pod was deleted and is judged by when the cloud
// API received the delete. When the step began, and when it first saw the
// delete listed, decide nothing.
func TestDeleteInWindow(t *testing.T) {
	deleted := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	const window = 30 * time.Second
	at := func(after time.Duration) *cloudCall { return &cloudCall{ReceivedAt: deleted.Add(after)} }

	for _, tc := range []struct {
		name  string
		first *cloudCall
		want  string
	}{
		{"received inside the window, however late it was seen", at(29 * time.Second), ""},
		{"received as the window closes", at(window), ""},
		{"received after the window, however late the step began", at(32 * time.Second), "later than 30s"},
		{"never received", nil, "received no delete"},
		{"received at a time the cloud API does not state", &cloudCall{}, "does not say when"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := deleteInWindow("alpha", deleted, window, tc.first)
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("refused: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

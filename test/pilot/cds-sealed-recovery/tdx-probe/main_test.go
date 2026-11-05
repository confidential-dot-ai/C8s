package main

import (
	"bytes"
	"testing"
)

func TestResultAndFreshNonceAreBoundTogether(t *testing.T) {
	q := request{Nonce: bytes.Repeat([]byte{1}, 32)}
	r := result{Version: 1, FieldID: fieldID, Status: "0000000000000000", Features: "0000000000001000", LaunchSHA256: "launch"}
	original := binding(q, r)
	changed := r
	changed.Features = "0000000000000000"
	if binding(q, changed) == original {
		t.Fatal("feature substitution not bound")
	}
	changed = r
	changed.Status = "c000010000000000"
	if binding(q, changed) == original {
		t.Fatal("native failure substitution not bound")
	}
	changed = r
	changed.LaunchSHA256 = "other-launch"
	if binding(q, changed) == original {
		t.Fatal("launch substitution not bound")
	}
	q.Nonce[0] ^= 1
	if binding(q, r) == original {
		t.Fatal("stale reply usable for new nonce")
	}
}

func TestMalformedNativeResultIsNotFeatureAbsence(t *testing.T) {
	for _, b := range []string{"", "0 0", "0000000000000000", "0000000000000000 0000000000001000 extra", "0000000000000000 not-hexadecimal!"} {
		if _, _, err := parseFeatures([]byte(b)); err == nil {
			t.Fatalf("accepted %q", b)
		}
	}
	s, f, err := parseFeatures([]byte("c000010000000000 0000000000000000\n"))
	if err != nil || s != "c000010000000000" || f != "0000000000000000" {
		t.Fatalf("native unsupported status lost: %q %q %v", s, f, err)
	}
}

func TestAmbiguousAndUnknownRequestsRejected(t *testing.T) {
	for _, b := range []string{`{"nonce":"AA==","nonce":"AQ=="}`, `{"nonce":"AA==","features":"1000"}`, `{} {}`} {
		var q request
		if decode([]byte(b), &q) == nil {
			t.Fatalf("accepted %s", b)
		}
	}
}

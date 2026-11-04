package httputil

import (
	"errors"
	"fmt"
	"testing"
)

var (
	errQuota = errors.New("holder quota reached")
	errFull  = errors.New("store full")
)

var sentinels = map[string]error{
	"quota": errQuota,
	"full":  errFull,
}

// A status carries the message and the sentinel, so a caller across the log
// still matches the error with errors.Is.
func TestStatusCarriesTheSentinelAndMessage(t *testing.T) {
	wrapped := fmt.Errorf("%w: three paths held", errQuota)
	status := StatusOf(wrapped, sentinels)
	if status.Kind != "quota" || status.Message != wrapped.Error() {
		t.Fatalf("status = %+v", status)
	}
	err := status.Err(sentinels)
	if !errors.Is(err, errQuota) || errors.Is(err, errFull) || err.Error() != wrapped.Error() {
		t.Fatalf("rebuilt %v", err)
	}
}

// An error no sentinel names keeps its message only.
func TestStatusOfOtherAndSuccess(t *testing.T) {
	status := StatusOf(errors.New("disk I/O error"), sentinels)
	if status.Kind != otherKind {
		t.Fatalf("status = %+v", status)
	}
	if err := status.Err(sentinels); err == nil || errors.Unwrap(err) != nil || err.Error() != "disk I/O error" {
		t.Fatalf("rebuilt %v", err)
	}
	if status := StatusOf(nil, sentinels); status != (Status{}) || status.Err(sentinels) != nil {
		t.Fatalf("a succeeded command carries %+v", status)
	}
}

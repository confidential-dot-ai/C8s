package nriimagepolicy

import (
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

// With logging.syslog set, records reach that socket, not stdout.
func TestLogWriterSendsRecordsToSyslog(t *testing.T) {
	dir, err := os.MkdirTemp("", "nrilog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "log")
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	w, err := logWriter(loggingConfig{Syslog: path})
	if err != nil {
		t.Fatal(err)
	}
	logger, err := certutil.NewJSONLoggerTo(w, "info")
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("audit", slog.String("action", "deny"))
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buf[:n]); !strings.Contains(got, "nri-image-policy") || !strings.Contains(got, `"action":"deny"`) {
		t.Fatalf("syslog record = %q, want the tagged JSON record", got)
	}
	if _, err := logWriter(loggingConfig{Syslog: filepath.Join(dir, "missing")}); err == nil {
		t.Error("logWriter accepted a socket that does not exist")
	}
}

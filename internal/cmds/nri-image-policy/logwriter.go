package nriimagepolicy

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
)

// logWriter is where the plugin's log and audit records go: the configured
// syslog socket, one JSON record per message, or else stdout. Close releases
// the syslog connection and leaves the process's stdout open.
func logWriter(cfg loggingConfig) (io.WriteCloser, error) {
	if cfg.Syslog == "" {
		return stdoutLog{os.Stdout}, nil
	}
	w, err := syslog.Dial("unixgram", cfg.Syslog, syslog.LOG_INFO|syslog.LOG_DAEMON, "nri-image-policy")
	if err != nil {
		return nil, fmt.Errorf("logging.syslog %s: %w", cfg.Syslog, err)
	}
	return w, nil
}

// stdoutLog keeps the process's stdout open when the log sink is closed.
type stdoutLog struct{ io.Writer }

func (stdoutLog) Close() error { return nil }

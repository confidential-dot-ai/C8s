package nriimagepolicy

import (
	"fmt"
	"io"
	"log/syslog"
	"os"
)

// logWriter is where the plugin's log and audit records go: the configured
// syslog socket, one JSON record per message, or else stdout.
func logWriter(cfg loggingConfig) (io.Writer, error) {
	if cfg.Syslog == "" {
		return os.Stdout, nil
	}
	w, err := syslog.Dial("unixgram", cfg.Syslog, syslog.LOG_INFO|syslog.LOG_DAEMON, "nri-image-policy")
	if err != nil {
		return nil, fmt.Errorf("logging.syslog %s: %w", cfg.Syslog, err)
	}
	return w, nil
}

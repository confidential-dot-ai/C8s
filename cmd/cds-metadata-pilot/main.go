// cds-metadata-pilot is a single-machine, durable comparison service. Production
// HA requires a replicated transactional database; this executable is a pilot.
package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:9443", "TLS listen address")
	database := flag.String("db", "", "persistent SQLite file on durable local storage")
	namespace := flag.String("namespace", "", "exact CDS object prefix for this dedicated service")
	tokenFile := flag.String("token-file", "", "private file with an independent bearer token")
	cert := flag.String("tls-cert", "", "TLS certificate PEM file")
	key := flag.String("tls-key", "", "TLS private key PEM file")
	flag.Parse()
	if *database == "" || *cert == "" || *key == "" {
		return fmt.Errorf("db, tls-cert and tls-key are required")
	}
	info, err := os.Stat(*tokenFile)
	if err != nil || info.Mode().Perm()&0077 != 0 || info.Size() > 4097 {
		return fmt.Errorf("token-file must be a private, bounded file")
	}
	data, err := os.ReadFile(*tokenFile)
	if err != nil {
		return fmt.Errorf("cannot read token-file")
	}
	defer clear(data)
	service, err := metadatapilot.Open(*database, *namespace, strings.TrimSpace(string(data)))
	if err != nil {
		return err
	}
	defer service.Close()
	server := &http.Server{Addr: *listen, Handler: service, ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 6 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	finished := make(chan error, 1)
	go func() { finished <- server.ListenAndServeTLS(*cert, *key) }()
	select {
	case err := <-finished:
		return err
	case <-ctx.Done():
		shutdown, stop := context.WithTimeout(context.Background(), 6*time.Second)
		defer stop()
		return server.Shutdown(shutdown)
	}
}

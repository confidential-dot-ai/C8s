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
	clustersFile := flag.String("clusters-file", "", "private JSON manifest of namespaces and token_file paths")
	dbDirectory := flag.String("db-dir", "", "absolute directory for independent per-cluster databases")
	cert := flag.String("tls-cert", "", "TLS certificate PEM file")
	key := flag.String("tls-key", "", "TLS private key PEM file")
	flag.Parse()
	if *cert == "" || *key == "" {
		return fmt.Errorf("tls-cert and tls-key are required")
	}
	var service interface {
		http.Handler
		Close()
	}
	if *clustersFile != "" {
		if *database != "" || *namespace != "" || *tokenFile != "" {
			return fmt.Errorf("clusters-file is exclusive with db, namespace and token-file")
		}
		configs, err := clusterConfigs(*clustersFile)
		if err != nil {
			return err
		}
		fleet, err := metadatapilot.OpenFleet(*dbDirectory, configs)
		clear(configs)
		if err != nil {
			return err
		}
		service = fleet
	} else {
		if *database == "" || *dbDirectory != "" {
			return fmt.Errorf("single-cluster mode requires db; db-dir requires clusters-file")
		}
		data, err := privateFile(*tokenFile, 4097)
		if err != nil {
			return err
		}
		single, err := metadatapilot.Open(*database, *namespace, strings.TrimSpace(string(data)))
		clear(data)
		if err != nil {
			return err
		}
		service = single
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

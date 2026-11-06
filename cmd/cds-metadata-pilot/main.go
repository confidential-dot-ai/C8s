// cds-metadata-pilot serves the local SQLite control or an explicit three-member
// etcd current-state backend. No production backend changes by default.
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
	etcdEndpoints := flag.String("etcd-endpoints", "", "three comma-separated HTTPS etcd members; current-state API only")
	etcdCluster := flag.String("etcd-cluster-id", "", "pinned canonical decimal etcd cluster ID")
	etcdCA := flag.String("etcd-root-ca", "", "private file containing the dedicated etcd CA PEM")
	etcdCert := flag.String("etcd-client-cert", "", "private file containing the etcd client certificate PEM")
	etcdKey := flag.String("etcd-client-key", "", "private file containing the etcd client key PEM")
	flag.Parse()
	if *cert == "" || *key == "" {
		return fmt.Errorf("tls-cert and tls-key are required")
	}
	var service interface {
		http.Handler
		Close()
	}
	if *etcdEndpoints != "" {
		if *database != "" || *dbDirectory != "" {
			return fmt.Errorf("etcd mode is exclusive with SQLite db and db-dir")
		}
		var configs []metadatapilot.ClusterConfig
		if *clustersFile != "" {
			if *namespace != "" || *tokenFile != "" {
				return fmt.Errorf("clusters-file is exclusive with namespace and token-file")
			}
			var err error
			configs, err = clusterConfigs(*clustersFile)
			if err != nil {
				return err
			}
		} else {
			data, err := privateFile(*tokenFile, 4097)
			if err != nil {
				return err
			}
			configs = []metadatapilot.ClusterConfig{{Namespace: *namespace, Token: strings.TrimSpace(string(data))}}
			clear(data)
		}
		defer clear(configs)
		ha, err := openEtcd(configs, *etcdEndpoints, *etcdCluster, *etcdCA, *etcdCert, *etcdKey)
		if err != nil {
			return err
		}
		service = ha
	} else if *etcdCluster != "" || *etcdCA != "" || *etcdCert != "" || *etcdKey != "" {
		return fmt.Errorf("etcd credentials require explicit etcd-endpoints")
	} else if *clustersFile != "" {
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

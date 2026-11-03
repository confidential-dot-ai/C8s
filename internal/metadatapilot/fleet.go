package metadatapilot

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"path/filepath"
)

// MaxClusters bounds startup allocation. Incoming requests can never create a
// cluster, actor, database, or queue. This is still a single-host SQLite pilot.
const MaxClusters = 256

type ClusterConfig struct {
	Namespace string
	Token     string
}

// Fleet routes an immutable configured set of clusters to independent actors,
// databases and admission budgets. The namespace header selects a candidate;
// that Service authenticates the cluster-specific token before admitting work.
// Physical CPU, disk and HTTP transport remain shared resources.
type Fleet struct{ clusters map[string]*Service }

func OpenFleet(directory string, configs []ClusterConfig) (*Fleet, error) {
	if !filepath.IsAbs(directory) || len(configs) == 0 || len(configs) > MaxClusters {
		return nil, errors.New("metadata pilot: absolute database directory and 1..256 configured clusters required")
	}
	// Validate the whole set before creating any files or goroutines. A token
	// cannot grant access to two clusters, even by a configuration mistake.
	names, tokens := make(map[string]bool), make(map[[32]byte]bool)
	for _, cfg := range configs {
		digest := sha256.Sum256([]byte(cfg.Token))
		if !validNamespace(cfg.Namespace) || !ValidToken(cfg.Token) || names[cfg.Namespace] || tokens[digest] {
			return nil, errors.New("metadata pilot: invalid or duplicate cluster namespace/token")
		}
		names[cfg.Namespace], tokens[digest] = true, true
	}
	f := &Fleet{clusters: make(map[string]*Service, len(configs))}
	for _, cfg := range configs {
		digest := sha256.Sum256([]byte(cfg.Namespace))
		// A namespace is never interpreted as a filesystem path.
		path := filepath.Join(directory, hex.EncodeToString(digest[:])+".db")
		s, err := Open(path, cfg.Namespace, cfg.Token)
		if err != nil {
			f.Close()
			return nil, err
		}
		f.clusters[cfg.Namespace] = s
	}
	return f, nil
}

func (f *Fleet) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if s := f.clusters[r.Header.Get("X-CDS-Namespace")]; s != nil {
		s.ServeHTTP(w, r)
		return
	}
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func (f *Fleet) Close() {
	// Signal every actor before waiting on any database operation.
	for _, s := range f.clusters {
		s.cancel()
	}
	for _, s := range f.clusters {
		<-s.done
	}
}

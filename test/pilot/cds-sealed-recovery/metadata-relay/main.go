// metadata-relay hosts the real metadata pilot behind the native acceptance
// fixture's bounded pipe transport. It never receives a CDS key or plaintext
// application state. This single-host service is not replicated metadata HA.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/metadatapilot"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-sealed-recovery/snpaccept"
)

func main() {
	database := flag.String("db", "", "owned persistent metadata file")
	namespace := flag.String("namespace", "", "exact owned CDS prefix")
	flag.Parse()
	if err := serve(*database, *namespace, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func serve(database, namespace string, input io.Reader, output io.Writer) error {
	token := rand.Text() + rand.Text()
	s, err := metadatapilot.Open(database, namespace, token)
	if err != nil {
		return err
	}
	defer s.Close()
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 32<<10), 3<<20)
	encoder := json.NewEncoder(output)
	for scanner.Scan() {
		var q snpaccept.StorageRequest
		d := json.NewDecoder(bytes.NewReader(scanner.Bytes()))
		d.DisallowUnknownFields()
		if err := d.Decode(&q); err != nil {
			return fmt.Errorf("invalid bounded native metadata message")
		}
		if _, err := d.Token(); err != io.EOF {
			return fmt.Errorf("multiple native metadata messages on one line")
		}
		response := answer(s, namespace, token, q)
		if err := encoder.Encode(response); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func answer(service http.Handler, namespace, token string, q snpaccept.StorageRequest) snpaccept.StorageResponse {
	r := snpaccept.StorageResponse{ID: q.ID, Status: http.StatusBadRequest}
	path := ""
	switch q.Method {
	case "STATE_READ":
		path = metadatapilot.StateReadPath
	case "STATE_COMMIT":
		path = metadatapilot.StateCommitPath
	}
	if q.ID == 0 || path == "" || q.Path != "/pilot/"+namespace+"/metadata"+path || q.Match != "" || q.Absent != "" || len(q.Data) > metadatapilot.MaxTransactionBytes {
		return r
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	// This in-process fixture adapter represents the guest's TLS endpoint;
	// there is no host HTTP listener or plaintext network endpoint to protect.
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "https://native-metadata"+path, bytes.NewReader(q.Data))
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-CDS-Namespace", namespace)
	request.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	service.ServeHTTP(w, request)
	r.Status, r.Data = w.Code, bytes.Clone(w.Body.Bytes())
	return r
}

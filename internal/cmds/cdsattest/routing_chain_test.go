package cdsattest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/pkg/cdsgenesis"
)

// C-ID: the router's route-manifest read refuses a CDS that does not name
// the chain entry the node pins, and reads from one that does.
func TestRouterCDSClientHoldsToTheNodePin(t *testing.T) {
	for answer, refused := range map[string]bool{"0:other": true, "3:abc": false} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(cdsgenesis.Header, answer)
			http.NotFound(w, nil)
		}))
		address := filepath.Join(t.TempDir(), "cds-address")
		if err := os.WriteFile(address, cmdsutil.FormatCDSAddress("cds.example:8443", "3:abc"), 0o600); err != nil {
			t.Fatal(err)
		}
		cds, err := routerCDSClient(srv.URL, srv.Client(), address)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cds.Routes(context.Background())
		srv.Close()
		if errors.Is(err, cdsgenesis.ErrOtherGenesis) != refused {
			t.Errorf("answer %q: %v", answer, err)
		}
	}
}

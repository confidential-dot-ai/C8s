package taattest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/pkg/cdspin"
)

// C-ID: the router's route-manifest read refuses a Trust Authority that does not name
// the chain entry the node pins, and reads from one that does.
func TestRouterCDSClientHoldsToTheNodePin(t *testing.T) {
	for answer, refused := range map[string]bool{"0:other": true, "3:abc": false} {
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(cdspin.Header, answer)
			http.NotFound(w, nil)
		}))
		address := filepath.Join(t.TempDir(), "cds-address")
		if err := os.WriteFile(address, cmdsutil.FormatTAAddress("cds.example:8443", "3:abc"), 0o600); err != nil {
			t.Fatal(err)
		}
		ta, err := routerCDSClient(srv.URL, srv.Client(), address)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ta.Routes(context.Background())
		srv.Close()
		if errors.Is(err, cdspin.ErrOtherGenesis) != refused {
			t.Errorf("answer %q: %v", answer, err)
		}
	}
}

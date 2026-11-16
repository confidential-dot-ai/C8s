package cds

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/attestation-go/remote/mockapi"
	"github.com/confidential-dot-ai/c8s/pkg/types"
)

// The node image set of a replica as its cluster's commands move it.
type commandedNodeImages struct {
	images  atomic.Pointer[refvalues.ReferenceValues]
	version atomic.Uint64
}

func certifiedByCommand(images ...remote.ImagePin) *commandedNodeImages {
	moving := &commandedNodeImages{}
	moving.certify(images...)
	return moving
}

// What a SetNodeImages decree does: the whole set, never a delta.
func (c *commandedNodeImages) certify(images ...remote.ImagePin) {
	c.images.Store(&refvalues.ReferenceValues{
		Family: teetypes.FamilySNP,
		Images: images,
	})
	c.version.Add(1)
}

func (c *commandedNodeImages) Current() refvalues.ReferenceValues {
	return *c.images.Load()
}

func (c *commandedNodeImages) Generation() uint64 {
	return c.version.Load()
}

func (c *commandedNodeImages) Refresh() error {
	return nil
}

func TestANodeImageCommandMovesWhatCDSCertifies(t *testing.T) {
	stub := newStubAttestationApi(t, testLaunchDigest)
	certified := certifiedByCommand(imagePin(t, "node", otherLaunchDigest))
	h := newTestAttestHandler(t, stub.URL(), nil)
	h.NodeImages = certified

	// The caller runs the image the cluster has yet to accept.
	csrPEM, _ := generateCSR(t)
	wantRefusal(t, postAttest(t, h, issueChallenge(t, h), csrPEM), http.StatusForbidden, types.ErrorCodeMeasurementDenied)

	// The operator accepts the image being rolled out beside the old one.
	certified.certify(
		imagePin(t, "node", otherLaunchDigest),
		imagePin(t, "node-next", testLaunchDigest),
	)
	if w := postAttest(t, h, issueChallenge(t, h), csrPEM); w.Code != http.StatusOK {
		t.Fatalf("a caller on an accepted node image was refused: %d %s", w.Code, w.Body)
	}
	if names := publishedImages(t, certified); len(names) != 2 {
		t.Fatalf("/measurements publishes %v, want the old image and the new one", names)
	}

	// The nodes are relaunched, and the next command retires the old image.
	certified.certify(imagePin(t, "node-next", testLaunchDigest))
	if names := publishedImages(t, certified); len(names) != 1 || names[0] != "node-next" {
		t.Fatalf("/measurements publishes %v, want the new image alone", names)
	}
	stub.SetVerdict(mockapi.PassingVerdict(otherLaunchDigest))
	wantRefusal(t, postAttest(t, h, issueChallenge(t, h), csrPEM), http.StatusForbidden, types.ErrorCodeMeasurementDenied)
}

// As a verifier reads them.
func publishedImages(t *testing.T, certified *commandedNodeImages) []string {
	t.Helper()
	w := httptest.NewRecorder()
	handleMeasurements(certified)(w, httptest.NewRequest(http.MethodGet, "/measurements", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /measurements = %d %s", w.Code, w.Body)
	}
	var document struct {
		Measurements []struct {
			Name string `json:"name"`
		} `json:"measurements"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &document); err != nil {
		t.Fatalf("/measurements does not decode: %v: %s", err, w.Body)
	}
	names := make([]string, 0, len(document.Measurements))
	for _, image := range document.Measurements {
		names = append(names, image.Name)
	}
	return names
}

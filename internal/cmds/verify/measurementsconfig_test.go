package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

const (
	mcDigestA = "aa11000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
	mcDigestB = "bb22000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

func mcSet(t *testing.T, entries string) refvalues.ReferenceValues {
	t.Helper()
	s, err := refvalues.ParseRendered([]byte(`{"schema_version":"1","tee":"sev-snp","measurements":[` + entries + `]}`))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// collectFailures stands in for the verdict's fail sink.
func collectFailures() (func(string, ...any), *[]string) {
	var msgs []string
	return func(format string, args ...any) { msgs = append(msgs, fmt.Sprintf(format, args...)) }, &msgs
}

func TestCheckServedMeasurementsExactMatch(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	fail, msgs := collectFailures()

	checkServedMeasurements(want, measurementsReport{served: want, fetched: true}, fail)
	if len(*msgs) != 0 {
		t.Errorf("identical sets reported a difference: %v", *msgs)
	}
}

func TestMeasurementsReadbackScope(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	plan := &verifyPlan{refValues: want}
	for _, kind := range []string{"cds", "auto", "lb", "workload"} {
		t.Run(kind, func(t *testing.T) {
			fail, messages := collectFailures()
			checkMeasurementsConfig(config{kind: kind, measurementsConfig: "policy.json"}, plan,
				measurementsReport{note: "no CDS policy endpoint"}, fail)
			if kind == "workload" {
				if len(*messages) != 0 {
					t.Fatalf("workload receipt required a CDS readback: %v", *messages)
				}
			} else if len(*messages) != 1 || !strings.Contains((*messages)[0], "cannot be checked") {
				t.Fatalf("CDS policy readback did not fail closed: %v", *messages)
			}
		})
	}
}

// An image the target admits and the operator did not pin is the substitution
// this check exists to catch.
func TestCheckServedMeasurementsReportsAnExtraImage(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	served := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"},{"name":"rogue","measurement":"00`+mcDigestB+`"}`)
	fail, msgs := collectFailures()

	checkServedMeasurements(want, measurementsReport{served: served, fetched: true}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "admits an image") {
		t.Fatalf("extra entry not reported: %v", *msgs)
	}
	if !strings.Contains((*msgs)[0], "rogue") {
		t.Errorf("failure does not name the offending image: %s", (*msgs)[0])
	}
}

// The other direction means the cluster enforces less than the operator thinks.
func TestCheckServedMeasurementsReportsAMissingImage(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"},{"name":"b","measurement":"00`+mcDigestB+`"}`)
	served := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	fail, msgs := collectFailures()

	checkServedMeasurements(want, measurementsReport{served: served, fetched: true}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "does not admit") {
		t.Fatalf("missing entry not reported: %v", *msgs)
	}
}

// A target enforcing nothing is the loudest finding, not a quiet difference.
func TestCheckServedMeasurementsReportsAnEmptySet(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	fail, msgs := collectFailures()

	checkServedMeasurements(want, measurementsReport{served: refvalues.ReferenceValues{Family: teetypes.FamilySNP}, fetched: true}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "empty measurement set") {
		t.Fatalf("an unpinned target was not reported: %v", *msgs)
	}
}

// Names carry no matching semantics, so the same pin under another name is
// still the same pin.
func TestCheckServedMeasurementsIgnoresNames(t *testing.T) {
	want := mcSet(t, `{"name":"local-name","measurement":"00`+mcDigestA+`"}`)
	served := mcSet(t, `{"name":"cluster-name","measurement":"00`+mcDigestA+`"}`)
	fail, msgs := collectFailures()

	checkServedMeasurements(want, measurementsReport{served: served, fetched: true}, fail)
	if len(*msgs) != 0 {
		t.Errorf("differing names reported as a mismatch: %v", *msgs)
	}
}

// Neither an unfetched check nor a failed fetch may pass silently.
func TestCheckServedMeasurementsNeverPassesUnchecked(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)

	fail, msgs := collectFailures()
	checkServedMeasurements(want, measurementsReport{note: "target kind is not cds"}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "cannot be checked") {
		t.Errorf("unfetched check did not fail: %v", *msgs)
	}

	fail, msgs = collectFailures()
	checkServedMeasurements(want, measurementsReport{fetchErr: fmt.Errorf("connection refused")}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "could not fetch") {
		t.Errorf("fetch error did not fail: %v", *msgs)
	}
}

// A target on the other platform is a policy error, not a per-image diff.
func TestCheckServedMeasurementsReportsPlatformMismatch(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	served, err := refvalues.ParseRendered([]byte(
		`{"schema_version":"1","tee":"tdx","measurements":[{"name":"a","mrtd":"00` + mcDigestA + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	fail, msgs := collectFailures()

	checkServedMeasurements(want, measurementsReport{served: served, fetched: true}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "the target enforces") {
		t.Fatalf("platform mismatch not reported: %v", *msgs)
	}
}

// End to end over HTTPS: the fetch must read a real served document, and must
// refuse a server whose certificate is not the one that was attested — that
// binding is what stops a substituted endpoint answering for CDS.
func TestFetchServedMeasurementsBindsToTheAttestedCert(t *testing.T) {
	doc, err := refvalues.Format(mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/measurements" {
			http.NotFound(w, r)
			return
		}
		w.Write(doc)
	}))
	defer srv.Close()

	leaf := srv.Certificate().Raw
	sum := sha256.Sum256(leaf)
	attested := hex.EncodeToString(sum[:])

	got, err := fetchServedMeasurements(context.Background(), srv.URL, "example.com", attested, 10*time.Second)
	if err != nil {
		t.Fatalf("fetch over the attested cert failed: %v", err)
	}
	if len(got.Images) != 1 || got.Family != teetypes.FamilySNP {
		t.Fatalf("served set = %+v, want the one pinned image", got)
	}

	// A different attested fingerprint must abort the handshake.
	if _, err := fetchServedMeasurements(context.Background(), srv.URL, "example.com", strings.Repeat("00", 32), 10*time.Second); err == nil {
		t.Error("fetch accepted a server that is not the attested target")
	}

	// No attested cert at all is refused rather than fetched unbound.
	if _, err := fetchServedMeasurements(context.Background(), srv.URL, "example.com", "", 10*time.Second); err == nil {
		t.Error("fetch proceeded with nothing to bind to")
	}
}

// A target that does not serve the endpoint must be reported, never treated as
// agreement.
func TestFetchServedMeasurementsReportsAMissingEndpoint(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(http.NotFound))
	defer srv.Close()
	sum := sha256.Sum256(srv.Certificate().Raw)

	_, err := fetchServedMeasurements(context.Background(), srv.URL, "example.com", hex.EncodeToString(sum[:]), 10*time.Second)
	if err == nil {
		t.Fatal("a 404 was not reported")
	}
	if !strings.Contains(err.Error(), "not served") {
		t.Errorf("error %q does not explain the missing endpoint", err)
	}
}

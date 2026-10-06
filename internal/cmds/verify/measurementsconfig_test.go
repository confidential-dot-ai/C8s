package verify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
)

// loadNodeIdentities returns the testdata fixture as CDS serves it (server
// plus agent entries) and narrowed to the server entry a client pins.
func loadNodeIdentities(t *testing.T) (serverOnly, serverAndAgent refvalues.ReferenceValues) {
	t.Helper()
	full, err := refvalues.Load(filepath.Join("..", "..", "..", "internal", "testdata", "node-identities.json"))
	if err != nil {
		t.Fatal(err)
	}
	if full.Images[0].Name != "server" {
		t.Fatalf("fixture leads with %q, the server entry must come first", full.Images[0].Name)
	}
	server := full
	server.Images = full.Images[:1]
	return server, full
}

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

	checkServedMeasurements("--image-policy-file", want, measurementsReport{served: want, fetched: true}, fail)
	if len(*msgs) != 0 {
		t.Errorf("identical sets reported a difference: %v", *msgs)
	}
}

// Workload receipts have no CDS endpoint. Their image policy still pins the
// hardware image and launch key, but only CDS verification reads served policy.
func TestMeasurementsReadbackScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"1","tee":"sev-snp","measurements":[{"name":"a","measurement":"00`+mcDigestA+`"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"cds", "auto", "lb", "workload"} {
		t.Run(kind, func(t *testing.T) {
			plan, err := buildPolicy(config{kind: kind, measurementsConfig: path})
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.refValues.Images) != 1 {
				t.Fatal("lost target image pin")
			}
			fail, messages := collectFailures()
			checkServedPolicy(plan, measurementsReport{note: "no CDS policy endpoint"}, fail)
			if kind == "workload" {
				if len(*messages) != 0 {
					t.Fatalf("workload receipt required CDS readback: %v", *messages)
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

	checkServedMeasurements("--image-policy-file", want, measurementsReport{served: served, fetched: true}, fail)
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

	checkServedMeasurements("--image-policy-file", want, measurementsReport{served: served, fetched: true}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "does not admit") {
		t.Fatalf("missing entry not reported: %v", *msgs)
	}
}

// A target enforcing nothing is the loudest finding, not a quiet difference.
func TestCheckServedMeasurementsReportsAnEmptySet(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)
	fail, msgs := collectFailures()

	checkServedMeasurements("--image-policy-file", want, measurementsReport{served: refvalues.ReferenceValues{Family: teetypes.FamilySNP}, fetched: true}, fail)
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

	checkServedMeasurements("--image-policy-file", want, measurementsReport{served: served, fetched: true}, fail)
	if len(*msgs) != 0 {
		t.Errorf("differing names reported as a mismatch: %v", *msgs)
	}
}

// Neither an unfetched check nor a failed fetch may pass silently.
func TestCheckServedMeasurementsNeverPassesUnchecked(t *testing.T) {
	want := mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)

	fail, msgs := collectFailures()
	checkServedMeasurements("--image-policy-file", want, measurementsReport{note: "target kind is not cds"}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "cannot be checked") {
		t.Errorf("unfetched check did not fail: %v", *msgs)
	}

	fail, msgs = collectFailures()
	checkServedMeasurements("--image-policy-file", want, measurementsReport{fetchErr: fmt.Errorf("connection refused")}, fail)
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

	checkServedMeasurements("--image-policy-file", want, measurementsReport{served: served, fetched: true}, fail)
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

// On a launch-config new cluster the client pins the server entry alone while
// CDS serves every admitted identity; --served-policy-file carries the second
// set so the first can stay narrow.
func TestCheckServedPolicyPrefersServedPolicyFile(t *testing.T) {
	serverOnly, serverAndAgent := loadNodeIdentities(t)
	report := measurementsReport{served: serverAndAgent, fetched: true}

	// With --served-policy-file the equality check compares against it, not
	// the narrower --image-policy-file target pin.
	plan := &verifyPlan{refValues: serverOnly, served: &servedSet{flag: "--served-policy-file", want: serverAndAgent}}
	fail, msgs := collectFailures()
	checkServedPolicy(plan, report, fail)
	if len(*msgs) != 0 {
		t.Fatalf("served set equals --served-policy-file, got %v", *msgs)
	}

	// Without it the check falls back to --image-policy-file: the agent
	// entries CDS admits are reported, pinning the pre-split behaviour.
	plan = &verifyPlan{refValues: serverOnly, served: &servedSet{flag: "--image-policy-file", want: serverOnly}}
	fail, msgs = collectFailures()
	checkServedPolicy(plan, report, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "admits an image --image-policy-file does not pin") {
		t.Fatalf("fallback to --image-policy-file changed: %v", *msgs)
	}

	// A --served-policy-file missing an entry the target admits fails,
	// naming its own flag.
	plan = &verifyPlan{served: &servedSet{flag: "--served-policy-file", want: serverOnly}}
	fail, msgs = collectFailures()
	checkServedPolicy(plan, report, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "admits an image --served-policy-file does not pin") {
		t.Fatalf("narrow --served-policy-file not reported: %v", *msgs)
	}

	// No policy flag, no check — even with a fetched report.
	fail, msgs = collectFailures()
	checkServedPolicy(&verifyPlan{}, report, fail)
	if len(*msgs) != 0 {
		t.Fatalf("check ran without a policy flag: %v", *msgs)
	}
}

// A --served-policy-file check against a non-cds target fails closed and
// names the flag whose file could not be compared.
func TestCheckServedPolicyNamesTheFlagOnAnUncheckedTarget(t *testing.T) {
	plan := &verifyPlan{served: &servedSet{flag: "--served-policy-file", want: mcSet(t, `{"name":"a","measurement":"00`+mcDigestA+`"}`)}}
	fail, msgs := collectFailures()
	checkServedPolicy(plan, measurementsReport{note: "target kind is not cds (use --kind cds to enable)"}, fail)
	if len(*msgs) != 1 || !strings.Contains((*msgs)[0], "--served-policy-file cannot be checked") {
		t.Fatalf("unchecked target did not fail naming the flag: %v", *msgs)
	}
}

// gatherMeasurements must run when --served-policy-file alone asked for the
// check; a silent skip would let a substituted CDS policy pass.
func TestGatherMeasurementsRunsForServedPolicyFileAlone(t *testing.T) {
	report := gatherMeasurements(context.Background(), config{kind: "lb"}, &verifyPlan{served: &servedSet{flag: "--served-policy-file"}}, &evidence{})
	if report.note == "" {
		t.Fatal("a non-cds target must record why the check could not run")
	}
	if got := gatherMeasurements(context.Background(), config{kind: "cds"}, &verifyPlan{}, &evidence{}); got.fetched || got.note != "" || got.fetchErr != nil {
		t.Fatalf("no policy flag means no fetch: %+v", got)
	}
}

func TestBuildPolicyLoadsServedPolicyFile(t *testing.T) {
	_, serverAndAgent := loadNodeIdentities(t)
	path := filepath.Join(t.TempDir(), "peers.json")
	data, err := refvalues.Format(serverAndAgent)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := buildPolicy(config{servedPolicyFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if plan.served == nil || plan.served.flag != "--served-policy-file" || len(plan.served.want.Images) != 2 {
		t.Fatalf("served policy = %+v", plan.served)
	}
	if !plan.refValues.Empty() {
		t.Fatal("--served-policy-file must not pin the target's identity")
	}

	// The flag feeds only the served-set check, so it combines with the
	// independent target pins.
	if _, err := buildPolicy(config{servedPolicyFile: path, measurements: []string{strings.Repeat("ab", 48)}}); err != nil {
		t.Fatalf("--served-policy-file must not exclude --measurements: %v", err)
	}

	// An unreadable file is a usage error naming the flag.
	if _, err := buildPolicy(config{servedPolicyFile: path + ".missing"}); err == nil || !strings.Contains(err.Error(), "--served-policy-file") {
		t.Fatalf("unreadable file did not fail naming the flag: %v", err)
	}

	// The flag feeds only the served-set check, so it does not exclude
	// --image-manifest (the error below is the missing manifest file).
	if _, err := buildPolicy(config{servedPolicyFile: path, imageManifest: path + ".missing"}); err == nil || strings.Contains(err.Error(), "--served-policy-file") {
		t.Fatalf("--served-policy-file must not exclude --image-manifest: %v", err)
	}
}

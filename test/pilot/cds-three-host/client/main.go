// The local qualification client verifies the guest's native armTLS identity
// before sending a fixed, operator-signed phase. No CI or remote shell is used.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"time"

	"github.com/confidential-dot-ai/attestation-go/attestation/tdx"
	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/remote"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
	"github.com/confidential-dot-ai/c8s/test/pilot/cds-three-host/protocol"
)

func main() {
	launch := flag.String("launch", "", "independently rendered launch file")
	key := flag.String("key", "", "private test operator key")
	endpoint := flag.String("endpoint", "", "owned loopback VM tunnel")
	request := flag.String("request", "", "fixed bounded phase JSON")
	receipt := flag.String("receipt", "", "new private receipt")
	flag.Parse()
	if err := run(*launch, *key, *endpoint, *request, *receipt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func read(path string, limit int64) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > limit {
		return nil, errors.New("bounded regular input required")
	}
	b, e := io.ReadAll(io.LimitReader(f, limit+1))
	if len(b) > int(limit) {
		return nil, errors.New("input grew beyond bound")
	}
	return b, e
}
func run(lp, kp, origin, qp, out string) error {
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "https" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("explicit owned loopback tunnel required")
	}
	launch, e := read(lp, 64<<10)
	if e != nil {
		return e
	}
	cfg, e := cdsconfig.Parse(launch)
	if e != nil {
		return e
	}
	if cfg.Nodes.Family != "tdx" || len(cfg.Nodes.Images) != 2 {
		return errors.New("two independent TDX image tuples required")
	}
	for i := range cfg.Nodes.Images {
		cfg.Nodes.Images[i].LaunchFile = launch
	}
	key, e := read(kp, 4096)
	if e != nil {
		return e
	}
	signer, e := operatorauth.NewSignerFromKeyPEM(key)
	if e != nil {
		return e
	}
	body, e := read(qp, 16<<10)
	if e != nil {
		return e
	}
	if e = strictjson.Validate(body); e != nil {
		return e
	}
	var q protocol.Request
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&q); e != nil {
		return e
	}
	if !q.Valid() {
		return errors.New("invalid fixed phase")
	}
	// This loopback verifier is in the client's TCB. It accepts verification
	// only, performs Intel signature/collateral/revocation checks locally, and
	// cannot attest, issue tokens or sign caller-provided keys.
	verifier := httptest.NewServer(http.HandlerFunc(verifyTDX))
	defer verifier.Close()
	client, e := armtls.NewVerifyingHTTPClient(armtls.Pins{Images: cfg.Nodes.Images}, verifier.URL)
	if e != nil {
		return e
	}
	defer client.CloseIdleConnections()
	client.Timeout = 5 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	req, e := http.NewRequestWithContext(ctx, "POST", origin+"/phase", bytes.NewReader(body))
	if e != nil {
		return e
	}
	auth, e := signer.WithTTL(operatorauth.MaxTokenValidity).Authorization("POST", "/phase", body)
	if e != nil {
		return e
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	response, e := client.Do(req)
	if e != nil {
		return e
	}
	defer response.Body.Close()
	answer, e := io.ReadAll(io.LimitReader(response.Body, (256<<10)+1))
	if e != nil {
		return e
	}
	if len(answer) > 256<<10 {
		return errors.New("oversized phase reply")
	}
	if response.StatusCode != 200 {
		return fmt.Errorf("phase HTTP %d", response.StatusCode)
	}
	var result protocol.Reply
	if e = json.Unmarshal(answer, &result); e != nil {
		return e
	}
	if result.Operation != q.Operation {
		return errors.New("phase mismatch")
	}
	receipt := map[string]any{"native_tdx_armtls_verified": true, "image_and_launch_verified": true, "result": result, "production_ready": false, "operator_exclusion_qualified": false}
	b, e := json.MarshalIndent(receipt, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	_, e = f.Write(b)
	if e == nil {
		e = f.Sync()
	}
	f.Close()
	if e != nil {
		return e
	}
	if !result.Passed {
		return errors.New("verified phase assertion failed; inspect bounded guest diagnostics")
	}
	return nil
}
func verifyTDX(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" || r.URL.Path != "/verify" {
		http.NotFound(w, r)
		return
	}
	var q remote.VerifyRequest
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&q) != nil || q.Platform != teetypes.PlatformTDX || q.Params == nil || (q.IssueToken != nil && *q.IssueToken) {
		http.Error(w, "verification request refused", 400)
		return
	}
	v := q.Params
	if v.MinTcb != nil || len(v.ExpectedLaunchDigest) != 0 || (v.AllowDebug != nil && *v.AllowDebug) {
		http.Error(w, "unsupported policy", 400)
		return
	}
	var ev tdx.TdxEvidence
	if json.Unmarshal(q.Evidence, &ev) != nil {
		http.Error(w, "bad TDX evidence", 400)
		return
	}
	params := teetypes.VerifyParams{ExpectedReportData: v.ExpectedReportData, ExpectedInitDataHash: v.ExpectedInitDataHash, ExpectedLaunchDigest: v.ExpectedMRTD, ExpectedRTMRs: [][]byte{v.ExpectedRTMR0, v.ExpectedRTMR1, v.ExpectedRTMR2, v.ExpectedRTMR3}}
	result, err := tdx.VerifyEvidence(ev, params, tdx.Options{CheckRevocations: true, GetCollateral: true})
	if err != nil {
		http.Error(w, "native TDX verification failed: "+err.Error(), 400)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(remote.VerifyResponse{Result: *result})
}

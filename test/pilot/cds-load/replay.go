package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

type recordedRequest struct {
	Method, Path, Authorization string
	Body                        []byte
	Expected, Status            int
}
type requestJournal struct {
	Run, Mode string
	CreatedAt time.Time
	Requests  []recordedRequest
}

func saveJournal(path string, value requestJournal, exclusive bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if exclusive {
		flags = os.O_WRONLY | os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := json.NewEncoder(f).Encode(value); err != nil {
		return err
	}
	return f.Sync()
}

func replay(endpoints []endpoint, path string, timeout time.Duration) error {
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm()&0077 != 0 || info.Size() > 8<<20 {
		return errors.New("replay requires a private, bounded journal")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var journal requestJournal
	if err := json.Unmarshal(data, &journal); err != nil {
		return err
	}
	if time.Since(journal.CreatedAt) >= operatorauth.MaxTokenValidity-time.Second*10 {
		return errors.New("replay journal is outside the token validity window")
	}
	checks := 0
	for i, request := range journal.Requests {
		if request.Status != request.Expected {
			continue
		}
		if request.Method != http.MethodPut || request.Authorization == "" ||
			(request.Path != "/allowlist" && !strings.HasPrefix(request.Path, "/secrets/pilot/"+journal.Run+"/")) {
			return errors.New("invalid recorded mutation")
		}
		status, body, err := send(endpoints[(i+1)%len(endpoints)], request, timeout)
		if err != nil || status != http.StatusConflict || strings.TrimSpace(string(body)) != operatorauth.ErrTokenReused.Error() {
			return fmt.Errorf("replay %d not rejected as spent: HTTP %d (%v)", i, status, err)
		}
		checks++
	}
	if checks == 0 {
		return errors.New("no acknowledged writes to check")
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "replay", "run": journal.Run, "checks": checks, "passed": true})
}

func policyDocument(name string) []byte {
	return []byte(`{"schema":"c8s.allowlist/v1","workloads":{"` + name + `":{"label":"synthetic pilot policy","containers":[{"digest":"sha256:` +
		strings.Repeat("22", 32) + `","command":{"policy":"any"},"args":{"policy":"any"}}]}}}`)
}

func send(target endpoint, r recordedRequest, timeout time.Duration) (int, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, r.Method, target.url+r.Path, bytes.NewReader(r.Body))
	if err != nil {
		return 0, nil, err
	}
	req.GetBody = nil
	req.Header.Set("Authorization", r.Authorization)
	req.Header.Set("Content-Type", "application/json")
	res, err := target.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	return res.StatusCode, body, err
}

// This checks immediate policy visibility. It is deliberately reported separately
// from workload-secret release: the latter also needs a real attested workload.
func revokePolicy(endpoints []endpoint, signer *operatorauth.Signer, timeout time.Duration) error {
	// Establish a positive observation on every target before testing removal.
	warm := recordedRequest{Method: http.MethodPut, Path: "/allowlist", Body: policyDocument("revocation-probe")}
	auth, err := signer.Authorization(warm.Method, warm.Path, warm.Body)
	if err != nil {
		return err
	}
	warm.Authorization = auth
	code, _, err := send(endpoints[0], warm, timeout)
	if err != nil || code != http.StatusNoContent {
		return fmt.Errorf("revocation warmup failed: HTTP %d (%v)", code, err)
	}
	for i, target := range endpoints {
		code, body, err := send(target, recordedRequest{Method: http.MethodGet, Path: "/allowlist"}, timeout)
		var policy struct {
			Workloads map[string]json.RawMessage `json:"workloads"`
		}
		if err != nil || code != http.StatusOK || json.Unmarshal(body, &policy) != nil || policy.Workloads["revocation-probe"] == nil {
			return fmt.Errorf("replica %d did not observe the positive policy", i)
		}
	}
	r := recordedRequest{Method: http.MethodPut, Path: "/allowlist", Body: []byte(`{"schema":"c8s.allowlist/v1","workloads":{}}`)}
	r.Authorization, err = signer.Authorization(r.Method, r.Path, r.Body)
	if err != nil {
		return err
	}
	code, _, err = send(endpoints[0], r, timeout)
	if err != nil || code != http.StatusNoContent {
		return fmt.Errorf("policy revocation not acknowledged: HTTP %d (%v)", code, err)
	}
	for i, target := range endpoints {
		code, body, err := send(target, recordedRequest{Method: http.MethodGet, Path: "/allowlist"}, timeout)
		var policy struct {
			Schema    string                     `json:"schema"`
			Workloads map[string]json.RawMessage `json:"workloads"`
		}
		if err != nil || code != http.StatusOK || json.Unmarshal(body, &policy) != nil || policy.Schema != "c8s.allowlist/v1" || policy.Workloads == nil || len(policy.Workloads) != 0 {
			return fmt.Errorf("replica %d did not return the revoked policy immediately after acknowledgement: HTTP %d", i, code)
		}
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "immediate-policy-revocation", "checks": len(endpoints), "passed": true, "workload_secret_release_tested": false})
}

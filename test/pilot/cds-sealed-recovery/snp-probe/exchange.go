//go:build linux

package main

// This exchange carries only a disposable encrypted sentinel and public SNP
// evidence. It has no command execution, file upload, CDS-key or key-release API.
import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"syscall"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/client"
	"github.com/google/go-sev-guest/verify"
	"golang.org/x/net/netutil"
)

const exchangeLimit = 8192

type probeRequest struct {
	Operation   string    `json:"operation"`
	Nonce       []byte    `json:"nonce"`
	Measurement string    `json:"measurement"`
	Capsule     *envelope `json:"capsule,omitempty"`
}

type probeResult struct {
	Outcome              string    `json:"outcome"`
	Capsule              *envelope `json:"capsule,omitempty"`
	FullAcceptancePassed bool      `json:"full_acceptance_passed"`
}

type probeReply struct {
	Result probeResult `json:"result"`
	Report []byte      `json:"report"`
}

func decodeStrict(body []byte, out any) error {
	if len(body) == 0 || len(body) > exchangeLimit {
		return errors.New("invalid exchange size")
	}
	if err := strictjson.Validate(body); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	return d.Decode(out)
}

func (r probeRequest) validate() ([]byte, error) {
	m, err := hex.DecodeString(r.Measurement)
	if err != nil || len(m) != 48 || bytes.Equal(m, make([]byte, 48)) || len(r.Nonce) != 32 || bytes.Equal(r.Nonce, make([]byte, 32)) {
		return nil, errors.New("nonzero measurement and fresh 32-byte nonce required")
	}
	switch r.Operation {
	case "seal":
		if r.Capsule != nil {
			return nil, errors.New("seal takes no secret or capsule input")
		}
	case "open":
		if r.Capsule == nil {
			return nil, errors.New("open requires an encrypted probe capsule")
		}
		b, _ := json.Marshal(r.Capsule)
		if _, err := decodeEnvelope(b); err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("seal or open required")
	}
	return m, nil
}

// Struct encoding fixes field order. A domain-separated JSON message
// bind both the challenge/input capsule and the complete result to REPORT_DATA.
func replyBinding(req probeRequest, result probeResult) [64]byte {
	b, _ := json.Marshal(struct {
		Domain  string       `json:"domain"`
		Request probeRequest `json:"request"`
		Result  probeResult  `json:"result"`
	}{"c8s/snp-disposable-exchange/v1", req, result})
	return sha512.Sum512(b)
}

func exchange(d client.Device, launch []byte, req probeRequest) (probeReply, error) {
	m, err := req.validate()
	if err != nil {
		return probeReply{}, err
	}
	var input envelope
	if req.Capsule != nil {
		input = *req.Capsule
	}
	e, err := probe(d, req.Operation, m, launch, input)
	result := probeResult{Outcome: "rejected"}
	if err == nil {
		result.Outcome, result.Capsule = "sealed", &e
		if req.Operation == "open" {
			result.Outcome = "opened"
		}
	}
	// Attest even a failed open, so a transport error cannot masquerade as a
	// successful different-chip rejection. Invalid launches still fail closed.
	nonce := replyBinding(req, result)
	raw, err := client.GetRawReportAtVmpl(d, nonce, 0)
	if err != nil {
		return probeReply{}, err
	}
	r, err := abi.ReportToProto(raw)
	if err != nil {
		return probeReply{}, err
	}
	if err := checkReport(r, nonce, m, launch); err != nil {
		return probeReply{}, err
	}
	return probeReply{Result: result, Report: raw}, nil
}

type probeJob struct {
	ctx   context.Context
	req   probeRequest
	reply chan exchangeResult
}
type exchangeResult struct {
	reply probeReply
	err   error
}

// One actor owns the firmware device. Eight queued requests and a bounded
// listener keep both hardware work and waiting connections bounded.
func probeHandler(ctx context.Context, do func(probeRequest) (probeReply, error)) (http.Handler, <-chan struct{}) {
	jobs := make(chan probeJob, 8)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-ctx.Done():
				return
			case job := <-jobs:
				if ctx.Err() != nil || job.ctx.Err() != nil {
					continue
				}
				r, err := do(job.req)
				job.reply <- exchangeResult{r, err}
			}
		}
	}()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/probe" || r.URL.RawQuery != "" {
			http.Error(w, "POST /v1/probe required", http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, exchangeLimit))
		var req probeRequest
		if err != nil || decodeStrict(body, &req) != nil {
			http.Error(w, "invalid bounded request", http.StatusBadRequest)
			return
		}
		if _, err := req.validate(); err != nil {
			http.Error(w, "invalid probe request", http.StatusBadRequest)
			return
		}
		job := probeJob{r.Context(), req, make(chan exchangeResult, 1)}
		select {
		case jobs <- job:
		default:
			w.Header().Set("Retry-After", "1")
			http.Error(w, "probe queue full", http.StatusTooManyRequests)
			return
		}
		select {
		case result := <-job.reply:
			if result.err != nil {
				http.Error(w, "hardware or launch check failed", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			_ = json.NewEncoder(w).Encode(result.reply)
		case <-r.Context().Done():
		case <-ctx.Done():
			http.Error(w, "probe stopped", http.StatusServiceUnavailable)
		}
	}), done
}

func serve(args []string, out io.Writer) error {
	f := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := f.String("listen", "127.0.0.1:8445", "public probe exchange; no secret plaintext")
	launchPath := f.String("launch-file", "/run/confai/operator-pubkey", "immutable measured launch file")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("unexpected arguments")
	}
	launch, err := readBounded(*launchPath, 1<<20)
	if err != nil {
		return err
	}
	d := &client.LinuxDevice{}
	if err := d.Open("/dev/sev-guest"); err != nil {
		return err
	}
	defer d.Close()
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	handler, done := probeHandler(ctx, func(req probeRequest) (probeReply, error) { return exchange(d, launch, req) })
	s := &http.Server{Handler: handler,
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 20 * time.Second,
		IdleTimeout: 5 * time.Second, MaxHeaderBytes: 4096}
	go func() { <-ctx.Done(); _ = s.Close() }()
	fmt.Fprintln(out, "disposable SNP probe ready")
	err = s.Serve(netutil.LimitListener(l, 32))
	stop()
	<-done // The actor relinquishes the device before the deferred Close.
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Check semantic and nonce binding before fetching certificates. Signature and
// issuer revocation verification remain mandatory in the caller.
func checkReply(req probeRequest, reply probeReply, launch []byte) error {
	m, err := req.validate()
	if err != nil {
		return err
	}
	r, err := abi.ReportToProto(reply.Report)
	if err != nil {
		return err
	}
	if err := checkReport(r, replyBinding(req, reply.Result), m, launch); err != nil {
		return err
	}
	signer, err := abi.ParseSignerInfo(r.SignerInfo)
	if err != nil || signer.SigningKey != abi.VcekReportSigner || signer.MaskChipKey || len(r.ChipId) != 64 || bytes.Equal(r.ChipId, make([]byte, 64)) {
		return errors.New("unmasked chip identity and VCEK signature required")
	}
	if len(r.ReportId) != 32 || bytes.Equal(r.ReportId, make([]byte, 32)) {
		return errors.New("nonzero hardware guest report ID required")
	}
	if reply.Result.FullAcceptancePassed {
		return errors.New("primitive probe cannot establish full acceptance")
	}
	if reply.Result.Outcome == "rejected" {
		if reply.Result.Capsule != nil {
			return errors.New("rejected probe returned a capsule")
		}
		return nil
	}
	e := reply.Result.Capsule
	if e == nil || (req.Operation == "seal" && reply.Result.Outcome != "sealed") || (req.Operation == "open" && reply.Result.Outcome != "opened") {
		return errors.New("unexpected probe result")
	}
	b, _ := json.Marshal(e)
	if _, err := decodeEnvelope(b); err != nil {
		return err
	}
	h := sha256.Sum256(launch)
	if e.Measurement != req.Measurement || e.LaunchSHA256 != hex.EncodeToString(h[:]) {
		return errors.New("capsule binding mismatch")
	}
	if req.Operation == "open" {
		want, _ := json.Marshal(req.Capsule)
		if !bytes.Equal(b, want) {
			return errors.New("opened a different capsule")
		}
	}
	return nil
}

func request(args []string, out io.Writer) error {
	f := flag.NewFlagSet("request", flag.ContinueOnError)
	target := f.String("url", "http://127.0.0.1:24445/v1/probe", "authenticated local VM port-forward")
	operation := f.String("operation", "", "seal or open")
	pin := f.String("measurement", "", "independently built SNP measurement")
	launchPath := f.String("launch-file", "", "independently approved launch bytes")
	capsulePath := f.String("capsule-file", "", "seal: new output file; open: existing capsule")
	expect := f.String("expect", "", "sealed, opened, or rejected")
	if err := f.Parse(args); err != nil {
		return err
	}
	u, err := url.Parse(*target)
	// No arbitrary destination, redirect or proxy: this is a local VM tunnel,
	// not an outbound service request. Certificate fetching uses normal egress.
	if err != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/v1/probe" || f.NArg() != 0 || *capsulePath == "" {
		return errors.New("explicit loopback VM port-forward and capsule path required")
	}
	if (*operation == "seal" && *expect != "sealed") || (*operation == "open" && *expect != "opened" && *expect != "rejected") {
		return errors.New("explicit expected outcome required")
	}
	launch, err := readBounded(*launchPath, 1<<20)
	if err != nil {
		return err
	}
	req := probeRequest{Operation: *operation, Measurement: *pin, Nonce: make([]byte, 32)}
	if _, err := rand.Read(req.Nonce); err != nil {
		return err
	}
	if req.Operation == "open" {
		b, err := readBounded(*capsulePath, 4096)
		if err != nil {
			return err
		}
		e, err := decodeEnvelope(b)
		if err != nil {
			return err
		}
		req.Capsule = &e
	}
	if _, err := req.validate(); err != nil {
		return err
	}
	body, _ := json.Marshal(req)
	httpClient := &http.Client{Timeout: 25 * time.Second, Transport: &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	defer httpClient.CloseIdleConnections()
	resp, err := httpClient.Post(u.String(), "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("probe returned HTTP %d; no attested result", resp.StatusCode)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, exchangeLimit+1))
	var reply probeReply
	if err != nil {
		return err
	}
	if err := decodeStrict(body, &reply); err != nil {
		return err
	}
	if err := checkReply(req, reply, launch); err != nil {
		return err
	}
	options := verify.DefaultOptions()
	options.CheckRevocations, options.Now = true, time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := verify.RawSnpReportContext(ctx, reply.Report, options); err != nil {
		return fmt.Errorf("AMD report verification: %w", err)
	}
	if req.Operation == "seal" && reply.Result.Outcome == *expect {
		if err := writeNew(*capsulePath, *reply.Result.Capsule); err != nil {
			return err
		}
	}
	r, _ := abi.ReportToProto(reply.Report)
	chipHash := sha256.Sum256(r.ChipId)
	guestHash := sha256.Sum256(r.ReportId)
	err = json.NewEncoder(out).Encode(struct {
		Request                   probeRequest `json:"request"`
		Reply                     probeReply   `json:"reply"`
		ChipSHA256                string       `json:"chip_sha256"`
		GuestReportIDSHA256       string       `json:"guest_report_id_sha256"`
		SignatureVerified         bool         `json:"signature_verified"`
		IssuerRevocationChecked   bool         `json:"issuer_revocation_checked"`
		MinimumTCBQualified       bool         `json:"minimum_tcb_qualified"`
		OperatorExclusionVerified bool         `json:"operator_exclusion_verified"`
		VersionRetirementVerified bool         `json:"version_retirement_verified"`
		FullAcceptancePassed      bool         `json:"full_acceptance_passed"`
	}{Request: req, Reply: reply, ChipSHA256: hex.EncodeToString(chipHash[:]), GuestReportIDSHA256: hex.EncodeToString(guestHash[:]), SignatureVerified: true, IssuerRevocationChecked: true})
	if err != nil {
		return err
	}
	if reply.Result.Outcome != *expect {
		return fmt.Errorf("verified unexpected outcome %q", reply.Result.Outcome)
	}
	return nil
}

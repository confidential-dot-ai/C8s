package armtls

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/confidential-dot-ai/c8s/internal/strictjson"
	"github.com/google/go-tdx-guest/pcs"
)

type nativeCollateral struct {
	ctx         context.Context
	now         time.Time
	client      *http.Client
	unavailable atomic.Bool
}

func newNativeCollateral(
	ctx context.Context,
	now time.Time,
) *nativeCollateral {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	// Preserve deployment proxy routing. Only authenticated vendor collateral,
	// never a proxy's verdict, can pass the SDK and freshness checks below.
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxResponseHeaderBytes = 128 << 10
	transport.MaxConnsPerHost = 2
	return &nativeCollateral{ctx: ctx, now: now, client: &http.Client{
		Transport:     transport,
		Timeout:       15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (f *nativeCollateral) get(raw string) (map[string][]string, []byte, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
		return nil, nil, errors.New("native collateral: vendor HTTPS endpoint required")
	}
	switch u.Hostname() {
	case "kdsintf.amd.com", "api.trustedservices.intel.com", "certificates.trustedservices.intel.com":
	default:
		return nil, nil, errors.New("native collateral: unapproved vendor host")
	}
	if _, err := nativeCollateralKind(u); err != nil {
		return nil, nil, err
	}
	request, err := http.NewRequestWithContext(f.ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, nil, err
	}
	response, err := f.client.Do(request)
	if err != nil {
		f.unavailable.Store(true)
		return nil, nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		if response.StatusCode == http.StatusRequestTimeout || response.StatusCode == http.StatusTooManyRequests || response.StatusCode >= 500 {
			f.unavailable.Store(true)
		}
		return nil, nil, errors.New("native collateral: unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (4<<20)+1))
	if err != nil {
		f.unavailable.Store(true)
		return nil, nil, err
	}
	if len(body) > 4<<20 {
		return nil, nil, errors.New("native collateral: bounded response required")
	}
	if err := checkNativeCollateral(u, body, f.now); err != nil {
		return nil, nil, err
	}
	return response.Header.Clone(), body, nil
}

// These are rejection guards. The SDK subsequently authenticates the exact
// bytes, signer and revocation entries; a valid time window alone grants nothing.
func checkNativeCollateral(
	u *url.URL,
	body []byte,
	now time.Time,
) error {
	kind, err := nativeCollateralKind(u)
	if err != nil {
		return err
	}
	switch kind {
	case "crl":
		der := body
		if block, rest := pem.Decode(body); block != nil {
			if block.Type != "X509 CRL" || len(strings.TrimSpace(string(rest))) != 0 {
				return errors.New("native collateral: malformed CRL")
			}
			der = block.Bytes
		}
		crl, err := x509.ParseRevocationList(der)
		if err != nil {
			return errors.New("native collateral: malformed CRL")
		}
		for _, extension := range crl.Extensions {
			if extension.Critical || extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 27}) || extension.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 28}) {
				return errors.New("native collateral: unsupported scoped, delta or critical CRL extension")
			}
		}
		for _, entry := range crl.RevokedCertificateEntries {
			for _, extension := range entry.Extensions {
				if extension.Critical {
					return errors.New("native collateral: unsupported critical CRL entry extension")
				}
			}
		}
		return checkNativeWindow(crl.ThisUpdate, crl.NextUpdate, now)
	case "tcb":
		return checkNativeSignedWindow(body, "tcbInfo", now)
	case "qe":
		return checkNativeSignedWindow(body, "enclaveIdentity", now)
	case "vcek":
		return nil // VCEK/certificate chain; the SDK validates its validity and root.
	default:
		return errors.New("native collateral: unsupported response kind")
	}
}

func nativeCollateralKind(u *url.URL) (string, error) {
	if u == nil || u.RawPath != "" {
		return "", errors.New("native collateral: canonical vendor path required")
	}
	switch u.Hostname() {
	case "kdsintf.amd.com":
		parts := strings.Split(u.Path, "/")
		if len(parts) == 5 && parts[0] == "" && parts[1] == "vcek" && parts[2] == "v1" && (parts[3] == "Milan" || parts[3] == "Genoa") {
			if parts[4] == "crl" && u.RawQuery == "" {
				return "crl", nil
			}
			if chip, err := hex.DecodeString(parts[4]); err == nil && len(chip) == 64 {
				return "vcek", nil
			}
		}
	case "api.trustedservices.intel.com":
		switch u.Path {
		case "/tdx/certification/v4/tcb":
			return "tcb", nil
		case "/tdx/certification/v4/qe/identity":
			return "qe", nil
		case "/sgx/certification/v4/pckcrl":
			return "crl", nil
		}
	case "certificates.trustedservices.intel.com":
		if u.Path == "/IntelSGXRootCA.der" && u.RawQuery == "" {
			return "crl", nil
		}
	}
	return "", errors.New("native collateral: unsupported vendor path")
}

func checkNativeWindow(
	issued time.Time,
	expires time.Time,
	now time.Time,
) error {
	if issued.IsZero() || expires.IsZero() || !issued.Before(expires) || issued.After(now) || !now.Before(expires) {
		return errors.New("native collateral: current nonempty validity window required")
	}
	return nil
}

func checkNativeSignedWindow(
	body []byte,
	payload string,
	now time.Time,
) error {
	if err := strictjson.Validate(body); err != nil {
		return errors.New("native collateral: ambiguous signed JSON")
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope) != 2 || envelope[payload] == nil || envelope["signature"] == nil {
		return errors.New("native collateral: canonical signed envelope required")
	}
	// Exact outer keys prevent encoding/json's case-insensitive struct match
	// from selecting unsigned TCBINFO while the SDK authenticates tcbInfo.
	var window struct {
		IssueDate  time.Time `json:"issueDate"`
		NextUpdate time.Time `json:"nextUpdate"`
	}
	if err := json.Unmarshal(envelope[payload], &window); err != nil {
		return errors.New("native collateral: malformed validity window")
	}
	if payload == "tcbInfo" {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(envelope[payload], &fields); err != nil || !bytes.Equal(bytes.TrimSpace(fields["tcbType"]), []byte("0")) {
			return errors.New("native collateral: explicit component-wise TCB type zero required")
		}
		var info pcs.TcbInfo
		if err := json.Unmarshal(envelope[payload], &info); err != nil {
			return errors.New("native collateral: malformed TCB info")
		}
		if info.TcbType != 0 {
			return errors.New("native collateral: only component-wise TCB type zero is qualified")
		}
		base := info.TdxModule
		if len(base.Mrsigner.Bytes) != 48 || len(base.Attributes.Bytes) != 8 || len(base.AttributesMask.Bytes) != 8 {
			return errors.New("native collateral: complete TDX module identity required")
		}
		for _, identity := range info.TdxModuleIdentities {
			if !bytes.Equal(identity.Mrsigner.Bytes, base.Mrsigner.Bytes) || !bytes.Equal(identity.Attributes.Bytes, base.Attributes.Bytes) || !bytes.Equal(identity.AttributesMask.Bytes, base.AttributesMask.Bytes) {
				return errors.New("native collateral: divergent named TDX module identity is not qualified")
			}
		}
	}
	return checkNativeWindow(window.IssueDate, window.NextUpdate, now)
}

type nativeSNPFetch struct{ *nativeCollateral }

func (f nativeSNPFetch) Get(raw string) ([]byte, error) { _, body, err := f.get(raw); return body, err }

type nativeTDXFetch struct{ *nativeCollateral }

func (f nativeTDXFetch) Get(raw string) (map[string][]string, []byte, error) { return f.get(raw) }

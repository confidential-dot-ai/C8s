package collateral

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-tdx-guest/verify/trust"
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/localverify"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/sitecollateral"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/strictjson"
)

func NewCmd() *cobra.Command {
	root := &cobra.Command{Use: "collateral", Short: "Prepare and check site collateral against an enrolled TDX quote"}
	root.AddCommand(&cobra.Command{
		Use:   "prepare-intel RAW-QUOTE TARGET GENERATION NEW-DIRECTORY",
		Short: "Collect and validate Intel responses on a connected, time-synchronized workstation",
		Args:  cobra.ExactArgs(4),
		RunE: func(cmd *cobra.Command, args []string) error {
			gen, err := strconv.ParseUint(args[2], 10, 64)
			if err != nil || gen == 0 || args[1] == "" {
				return errors.New("supply an inventory ID and positive generation")
			}
			return prepare(cmd.Context(), args[0], args[1], gen, args[3], cmd.OutOrStdout())
		},
	}, &cobra.Command{
		Use:   "check-intel RAW-QUOTE MANIFEST OBJECT-DIRECTORY",
		Short: "Verify all objects of an Intel snapshot locally at the workstation's authenticated time",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			return check(cmd.Context(), args[0], args[1], args[2], cmd.OutOrStdout())
		},
	})
	return root
}

type intelResponses struct {
	manifest       sitecollateral.Manifest
	bodies         map[string][]byte
	issuerDeadline time.Time
}

func (r *intelResponses) Get(name string) (map[string][]string, []byte, error) {
	obj, ok := r.manifest.Objects[name]
	if !ok {
		return nil, nil, fmt.Errorf("candidate lacks Intel object %s", name)
	}
	return obj.Header, r.bodies[name], nil
}

func (r *intelResponses) deadline(ctx context.Context, quotePath string, getter trust.HTTPSGetter) (time.Time, error) {
	quote, err := os.ReadFile(quotePath)
	if err != nil {
		return time.Time{}, err
	}
	end, err := localverify.IntelMediaDeadline(ctx, quote, getter, time.Now())
	if err != nil {
		return time.Time{}, err
	}
	if len(r.bodies) != 4 {
		return time.Time{}, errors.New("expected exactly the four Intel objects required by this target")
	}
	if !r.issuerDeadline.IsZero() && r.issuerDeadline.Before(end) {
		end = r.issuerDeadline
	}
	return end.UTC(), nil
}

func (r *intelResponses) record(name string, headers http.Header, body []byte) error {
	for k, values := range headers {
		if !strings.HasSuffix(strings.ToLower(k), "-issuer-chain") || len(values) != 1 {
			return fmt.Errorf("unexpected header %q in %s", k, name)
		}
		chain, err := url.QueryUnescape(values[0])
		if err != nil {
			return err
		}
		for rest := []byte(strings.TrimSpace(chain)); len(rest) > 0; {
			block, tail := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" {
				return fmt.Errorf("invalid issuer PEM for %s", name)
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return fmt.Errorf("%s issuer: %w", name, err)
			}
			if r.issuerDeadline.IsZero() || cert.NotAfter.Before(r.issuerDeadline) {
				r.issuerDeadline = cert.NotAfter
			}
			rest = []byte(strings.TrimSpace(string(tail)))
		}
	}
	r.bodies[name] = body
	r.manifest.Objects[name] = sitecollateral.Object{SHA256: fmt.Sprintf("%x", sha256.Sum256(body)), Header: headers}
	return nil
}

type capture struct {
	ctx       context.Context
	client    *http.Client
	responses *intelResponses
}

func (c *capture) Get(name string) (map[string][]string, []byte, error) {
	req, err := http.NewRequestWithContext(c.ctx, http.MethodGet, name, nil)
	if err != nil {
		return nil, nil, err
	}
	u := req.URL
	if u.Scheme != "https" || u.User != nil || (u.Host != "api.trustedservices.intel.com" && u.Host != "certificates.trustedservices.intel.com") {
		return nil, nil, fmt.Errorf("unexpected Intel object origin %s", u.Host)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, nil, fmt.Errorf("fetch Intel object %s: %s", name, resp.Status)
	}
	body, err := readObject(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch Intel object %s: %w", name, err)
	}
	headers := make(http.Header)
	for _, k := range []string{"Tcb-Info-Issuer-Chain", "Sgx-Enclave-Identity-Issuer-Chain", "Sgx-Pck-Crl-Issuer-Chain"} {
		if values := resp.Header.Values(k); len(values) > 0 {
			headers[k] = values
		}
	}
	if err := c.responses.record(name, headers, body); err != nil {
		return nil, nil, err
	}
	return headers, body, nil
}

func readObject(r io.Reader) ([]byte, error) {
	const limit = 8 << 20
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if len(b) > limit {
		return nil, errors.New("object exceeds 8 MiB")
	}
	return b, err
}

func prepare(ctx context.Context, quote, target string, generation uint64, out string, w io.Writer) error {
	r := intelResponses{
		manifest: sitecollateral.Manifest{Target: target, Generation: generation, Objects: make(map[string]sitecollateral.Object)},
		bodies:   make(map[string][]byte),
	}
	client := &http.Client{
		Timeout:       15 * time.Second,
		Transport:     &http.Transport{DialContext: (&net.Dialer{Timeout: 4 * time.Second}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	defer client.CloseIdleConnections()
	end, err := r.deadline(ctx, quote, &capture{ctx: ctx, client: client, responses: &r})
	if err != nil {
		return err
	}
	r.manifest.ExpiresAt = end
	if err := os.Mkdir(out, 0700); err != nil {
		return err
	}
	objects := filepath.Join(out, "objects")
	if err := os.Mkdir(objects, 0700); err != nil {
		return err
	}
	for name, body := range r.bodies {
		if err := os.WriteFile(filepath.Join(objects, r.manifest.Objects[name].SHA256), body, 0600); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(r.manifest, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), raw, 0600); err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, end.Format(time.RFC3339Nano))
	return err
}

func check(ctx context.Context, quote, path, dir string, w io.Writer) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var m sitecollateral.Manifest
	if err := strictjson.Unmarshal(raw, &m); err != nil {
		return err
	}
	r := intelResponses{manifest: sitecollateral.Manifest{Objects: make(map[string]sitecollateral.Object)}, bodies: make(map[string][]byte)}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if len(m.Objects) != 4 {
		return errors.New("expected exactly four Intel objects in Intel-only media")
	}
	for name, obj := range m.Objects {
		if !filepath.IsLocal(obj.SHA256) || len(obj.SHA256) != 64 || strings.ContainsAny(obj.SHA256, "/\\") {
			return fmt.Errorf("invalid digest for %s", name)
		}
		f, err := root.Open(obj.SHA256)
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		body, err := readObject(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("read %s: %w", name, err)
		}
		if err := r.record(name, obj.Header, body); err != nil {
			return err
		}
		if r.manifest.Objects[name].SHA256 != obj.SHA256 {
			return fmt.Errorf("invalid content digest for %s", name)
		}
	}
	end, err := r.deadline(ctx, quote, &r)
	if err != nil {
		return err
	}
	if !time.Now().Before(m.ExpiresAt) || m.ExpiresAt.After(end) {
		return fmt.Errorf("snapshot expiry %s outside Intel validity (ends %s)", m.ExpiresAt, end)
	}
	_, err = fmt.Fprintln(w, m.ExpiresAt.UTC().Format(time.RFC3339Nano))
	return err
}

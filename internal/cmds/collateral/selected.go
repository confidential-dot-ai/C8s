package collateral

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"time"

	"github.com/google/go-tdx-guest/pcs"
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/sitecollateral"
)

type selectedObject struct {
	URL         string `json:"url"`
	Body        []byte `json:"body"`
	IssuerChain string `json:"issuer_chain,omitempty"`
}

type intelSelection struct {
	sitecollateral.Selection
	Time      time.Time        `json:"time"`
	ExpiresAt time.Time        `json:"expiresAt"`
	Objects   []selectedObject `json:"objects"`
}

func selectedTDX() *cobra.Command {
	return &cobra.Command{
		Use:   "selected-tdx PROFILE",
		Short: "Read the selected Intel objects and current site time for the measured verifier",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := sitecollateral.Open(cmd.Context(), args[0])
			if errors.Is(err, sitecollateral.ErrUnavailable) {
				return &cmdsutil.ExitStatusError{Status: 3, Err: err}
			}
			if err != nil {
				return err
			}
			selection, err := intelObjects(s)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(selection)
		},
	}
}

var tcbInfoURL = regexp.MustCompile("^" + regexp.QuoteMeta(pcs.TcbInfoURL("")) + "[0-9a-f]{12}$")

func intelObjects(s *sitecollateral.Snapshot) (intelSelection, error) {
	result := intelSelection{
		Selection: s.Selection,
		Time:      s.Time.UTC(),
		ExpiresAt: s.Manifest.ExpiresAt.UTC(),
	}
	seen := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(s.Manifest.Objects)) {
		u, err := url.Parse(name)
		if err != nil {
			return result, err
		}
		if u.Scheme == "" {
			continue
		}
		var header string
		switch {
		case tcbInfoURL.MatchString(name):
			header = "Tcb-Info-Issuer-Chain"
		case name == pcs.QeIdentityURL():
			header = "Sgx-Enclave-Identity-Issuer-Chain"
		case name == pcs.PckCrlURL("platform") || name == pcs.PckCrlURL("processor"):
			header = "Sgx-Pck-Crl-Issuer-Chain"
		case name == "https://certificates.trustedservices.intel.com/IntelSGXRootCA.der":
		default:
			return result, fmt.Errorf("unexpected Intel selector %q", name)
		}
		if seen[header] {
			return result, fmt.Errorf("multiple responses for the same Intel object: %s", name)
		}
		seen[header] = true
		headers, body, err := s.Get(name)
		if err != nil {
			return result, err
		}
		obj := selectedObject{URL: name, Body: body}
		if header != "" {
			values := http.Header(headers).Values(header)
			if len(values) != 1 || values[0] == "" {
				return result, fmt.Errorf("%s requires one %s", name, header)
			}
			obj.IssuerChain, err = url.QueryUnescape(values[0])
			if err != nil {
				return result, fmt.Errorf("%s issuer chain: %w", name, err)
			}
		}
		result.Objects = append(result.Objects, obj)
	}
	if len(result.Objects) != 4 {
		return result, fmt.Errorf("expected all four Intel objects, got %d", len(result.Objects))
	}
	return result, nil
}

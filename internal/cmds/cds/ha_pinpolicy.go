package cds

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdspins"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// newHAPinPolicyCmd reads the pin decree the replicas applied from a CDS the
// caller pins, and writes the CDS policy that decree makes: what nodes
// follow, as an operator policy file. After an image rollout the bundle's
// server.json pins only the old image; this is its replacement.
func newHAPinPolicyCmd() *cobra.Command {
	var (
		conn      cdsconn.Options
		clusterID string
		decrKey   string
		out       string
		decreeOut string
	)
	cmd := &cobra.Command{
		Use:   "pin-policy",
		Short: "Print the pin decree in force and write the CDS policy it makes (GET /ha/pins, over armTLS)",
		Long: "Reads the replicas' pin decree over armTLS from a CDS that --image-policy-file pins, checks\n" +
			"the operator signature and the cluster, and prints its base_epoch (the pin floor for new nodes).\n" +
			"With --out it writes the CDS policy the decree makes: its images under the launch keys of\n" +
			"--image-policy-file, exactly the set nodes follow. Use that file as --image-policy-file afterwards.\n" +
			"With --decree-out it writes the signed decree itself: add-cds-node --pin-decree takes a new\n" +
			"cds node's peer images and pin floor from it.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if conn.MeasurementsConfig == "" || clusterID == "" || decrKey == "" {
				return errors.New("--image-policy-file, --cluster-id and --decree-public-key are required")
			}
			current, err := refvalues.Load(conn.MeasurementsConfig)
			if err != nil {
				return err
			}
			key, err := readDecreeKey(decrKey)
			if err != nil {
				return err
			}
			hc, err := conn.HTTPClient(cmd.Context())
			if err != nil {
				return err
			}
			return writePinPolicy(cmd.Context(), hc, conn.URL, current, clusterID, key, out, decreeOut, cmd.OutOrStdout())
		},
	}
	cdsconn.BindFlags(cmd.Flags(), &conn)
	cmd.Flags().StringVar(&clusterID, "cluster-id", "", "the cluster the decree must be for")
	cmd.Flags().StringVar(&decrKey, "decree-public-key", "", "PEM public key the decree must be signed with (bundle cdsHA.decreeKey)")
	cmd.Flags().StringVar(&out, "out", "", "write the CDS policy the decree makes to this new file")
	cmd.Flags().StringVar(&decreeOut, "decree-out", "", "write the signed pin decree to this new file (for add-cds-node --pin-decree)")
	return cmd
}

// writePinPolicy fetches the pin decree with hc, an attested client, checks
// it, prints it, and writes the policy it makes to out and the decree to
// decreeOut (each unless empty).
func writePinPolicy(ctx context.Context, hc *http.Client, url string, current refvalues.ReferenceValues, clusterID string, decreeKey []byte, out, decreeOut string, w io.Writer) error {
	sd, err := cdspins.GetPins(ctx, hc, url)
	if err != nil {
		return err
	}
	if sd == nil {
		return errors.New("the replicas serve no pin decree: the pin set is the launch document's, keep the bundle's policy")
	}
	if err := cdsha.VerifyPinDecree(*sd, clusterID, decreeKey); err != nil {
		return fmt.Errorf("pin decree: %w", err)
	}
	policy, err := cdspins.Policy(current, sd.Decree.Images)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "base_epoch=%d intent=%s images=%d\n", sd.Decree.BaseEpoch, sd.Decree.IntentID, len(sd.Decree.Images))
	if out != "" {
		data, err := refvalues.Format(policy)
		if err != nil {
			return err
		}
		if err := writeNewFile(out, data, w); err != nil {
			return err
		}
	}
	if decreeOut != "" {
		data, err := json.Marshal(sd)
		if err != nil {
			return err
		}
		if err := writeNewFile(decreeOut, data, w); err != nil {
			return err
		}
	}
	return nil
}

// writeNewFile writes data to path, which must not exist yet.
func writeNewFile(path string, data []byte, w io.Writer) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Fprintf(w, "wrote %s\n", path)
	return nil
}

// readDecreeKey reads a PEM PUBLIC KEY file as PKIX DER.
func readDecreeKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "PUBLIC KEY" {
		return nil, errors.New("--decree-public-key: want a PEM PUBLIC KEY")
	}
	return b.Bytes, nil
}

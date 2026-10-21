package cds

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
)

// newHACmd groups the operator side of HA CDS.
func newHACmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ha", Short: "Operate a highly available CDS"}
	cmd.AddCommand(newHADecreeCmd(), newHAStatusCmd(), newHARecoverCmd(), newHADecreesCmd(), newHARecoveryKeyCmd())
	return cmd
}

func newHADecreeCmd() *cobra.Command {
	var (
		d          cdsha.Decree
		kind       string
		keyPath    string
		namespace  string
		expiresIn  time.Duration
		ackFork    bool
		ackRecover bool
		images     []string
	)
	cmd := &cobra.Command{
		Use:   "decree",
		Short: "Sign a decree and print it as a CDSDecree object for kubectl apply",
		Long: "Signs a Genesis, UpdateMeasurements or RotateKey decree with the operator key and prints the\n" +
			"decree object (a ConfigMap) as JSON. Apply it with kubectl; the leader replica\n" +
			"applies it and every replica checks the signature. Re-sign with the current epoch\n" +
			"if it is rejected for a base_epoch conflict.\n\n" +
			"Genesis names the one node whose replica starts the cluster (--bootstrap-node) and\n" +
			"expires after 10 minutes by default: a cluster is born once.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			d.Kind = cdsha.DecreeKind(kind)
			switch d.Kind {
			case cdsha.Genesis, cdsha.Recover:
				if d.BootstrapNode == "" {
					return fmt.Errorf("a %s decree needs --bootstrap-node: the node whose replica starts (or carries on) the cluster", d.Kind)
				}
				if !cmd.Flags().Changed("expires-in") {
					expiresIn = 10 * time.Minute
				}
				if d.Kind == cdsha.Recover {
					if !ackRecover {
						return errors.New("a Recover decree is break-glass after losing a majority of replicas for good: writes the lost replicas had and the survivor did not are gone, and if they were only cut off they could carry on as the old majority. Make sure they are destroyed, follow with RotateKey, and pass --i-understand-recover-is-break-glass")
					}
					fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: follow Recover with a RotateKey decree, so any lost replica that comes back holds a retired key.")
				}
			default:
				if d.BootstrapNode != "" {
					return errors.New("--bootstrap-node is for Genesis and Recover only")
				}
			}
			if d.Kind != cdsha.Genesis && !cmd.Flags().Changed("base-epoch") {
				// Replicas apply a decree only at the epoch it names; one
				// signed without it (epoch 0) is refused, and only in their logs.
				return fmt.Errorf("a %s decree needs --base-epoch: the epoch 'c8s cds ha status' shows now", d.Kind)
			}
			if d.Kind == cdsha.RotateKey {
				if !ackFork {
					return errors.New("RotateKey forks the mesh: every workload must be re-issued under the new key. Pass --i-understand-rotation-forks-the-cluster to continue (C4, D11)")
				}
				if len(d.Measurements) == 0 {
					fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: RotateKey without --measurements delivers the new key to the current pin set (D14). Prefer UpdateMeasurements first (D13).")
				}
			}
			if err := setDecreeImages(&d, images); err != nil {
				return err
			}
			key, err := loadECPrivateKey(keyPath)
			if err != nil {
				return err
			}
			if d.IntentID == "" {
				d.IntentID = randomID()
			}
			d.ExpiresAt = time.Now().Add(expiresIn).UTC().Truncate(time.Second)
			sd, err := cdsha.SignDecree(d, key)
			if err != nil {
				return err
			}
			cm, err := cdsha.DecreeConfigMap(namespace, sd)
			if err != nil {
				return err
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(cm)
		},
	}
	f := cmd.Flags()
	f.StringVar(&d.ClusterID, "cluster-id", "", "cluster the decree is for")
	f.Uint64Var(&d.BaseEpoch, "base-epoch", 0, "the epoch you observed (c8s cds ha status)")
	f.StringVar(&kind, "kind", string(cdsha.UpdateMeasurements), "Genesis (mint the first key), UpdateMeasurements, RotateKey, SetVoters, or Recover (break-glass after losing a majority)")
	f.IntVar(&d.Voters, "voters", 0, "SetVoters: the new voter seat count (odd); more replicas than seats serve as non-voters")
	f.StringSliceVar(&d.Measurements, "measurements", nil, "complete new replica pin set (D6); optional for RotateKey (D14). Derived from --image when that is given")
	f.StringArrayVar(&images, "image", nil, "a CDS launch identity, mrtd:rtmr1:rtmr2 in hex; repeat for each. Lets nodes and pods follow the pin set (GET /ha/pins), so a CDS image rollout needs no node relaunch")
	f.StringVar(&d.IntentID, "intent-id", "", "decree nonce (default random)")
	f.StringVar(&d.BootstrapNode, "bootstrap-node", "", "Genesis: the node whose replica starts the cluster; Recover: the surviving node")
	f.StringVar(&keyPath, "operator-key", "", "PEM EC private key matching the cluster's --ha-operator-key")
	f.StringVar(&namespace, "namespace", "c8s-cds-decrees", "namespace the decree object is written to (the replicas' --ha-decree-namespace)")
	f.DurationVar(&expiresIn, "expires-in", time.Hour, "decree lifetime")
	f.BoolVar(&ackFork, "i-understand-rotation-forks-the-cluster", false, "required for RotateKey")
	f.BoolVar(&ackRecover, "i-understand-recover-is-break-glass", false, "required for Recover")
	_ = cmd.MarkFlagRequired("cluster-id")
	_ = cmd.MarkFlagRequired("operator-key")
	return cmd
}

func newHAStatusCmd() *cobra.Command {
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "status URL...",
		Short: "Report each replica's role, epoch, mesh CA and freshness from GET /ha/status",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, urls []string) error {
			client := &http.Client{Timeout: timeout}
			var seen []cdsha.Status
			for _, u := range urls {
				hb, err := fetchHAStatus(cmd.Context(), client, u)
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "%-40s ERROR %v\n", u, err)
					continue
				}
				seen = append(seen, hb)
				fmt.Fprintf(cmd.OutOrStdout(), "%-40s node=%s state=%s epoch=%d serving=%t ca=%.16s voters=%d non_voters=%d applied=%d\n",
					u, hb.NodeName, hb.State, hb.Epoch, hb.Serving, hb.CAFingerprint, len(hb.Voters), len(hb.NonVoters), hb.AppliedIndex)
			}
			return reportDivergence(seen, len(urls))
		},
	}
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Second, "per-replica timeout")
	return cmd
}

func reportDivergence(seen []cdsha.Status, want int) error {
	if len(seen) != want {
		return fmt.Errorf("%d of %d replicas unreachable", want-len(seen), want)
	}
	for _, hb := range seen {
		if hb.Epoch != seen[0].Epoch || hb.CAFingerprint != seen[0].CAFingerprint || !hb.Serving {
			return errors.New("replicas disagree or are not serving")
		}
	}
	return nil
}

func fetchHAStatus(ctx context.Context, c *http.Client, url string) (cdsha.Status, error) {
	var hb cdsha.Status
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url+"/ha/status", nil)
	if err != nil {
		return hb, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return hb, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return hb, errors.New(resp.Status)
	}
	return hb, json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&hb)
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("operator key: no PEM block")
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	anyKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("operator key: %w", err)
	}
	k, ok := anyKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("operator key is not ECDSA")
	}
	return k, nil
}

func randomID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// setDecreeImages fills d.Images from --image values and derives the replica
// pins from them; explicit --measurements must then be the same set.
func setDecreeImages(d *cdsha.Decree, specs []string) error {
	if len(specs) == 0 {
		return nil
	}
	if d.Kind != cdsha.UpdateMeasurements && d.Kind != cdsha.RotateKey {
		return fmt.Errorf("--image is for UpdateMeasurements and RotateKey decrees")
	}
	var pins []string
	for _, spec := range specs {
		parts := strings.Split(strings.ToLower(strings.TrimSpace(spec)), ":")
		if len(parts) != 3 {
			return fmt.Errorf("--image %q: want mrtd:rtmr1:rtmr2", spec)
		}
		img := cdsha.DecreeImage{MRTD: parts[0], RTMR1: parts[1], RTMR2: parts[2]}
		pin, err := img.Pin()
		if err != nil {
			return fmt.Errorf("--image %q: %w", spec, err)
		}
		d.Images = append(d.Images, img)
		pins = append(pins, pin)
	}
	pins = slices.Compact(slices.Sorted(slices.Values(pins)))
	if len(d.Measurements) > 0 {
		given := slices.Compact(slices.Sorted(slices.Values(d.Measurements)))
		if !slices.Equal(given, pins) {
			return errors.New("--measurements must be exactly the pins of the --image values (or leave it out)")
		}
	}
	d.Measurements = pins
	return nil
}

// newHADecreesCmd prints the replicas' record of applied decrees, read over
// armTLS from a CDS the caller pins: the operator's decisions as the cluster
// applied them, signatures included, for audit.
func newHADecreesCmd() *cobra.Command {
	var (
		conn    cdsconn.Options
		asJSON  bool
		decrKey string
	)
	cmd := &cobra.Command{
		Use:   "decrees",
		Short: "Print the decrees the cluster applied (GET /ha/decrees, over armTLS)",
		Long: "Reads the record of applied decrees from a serving replica over armTLS, so the record is\n" +
			"the replicas' agreed state, not the decree objects in Kubernetes (which the host controls).\n" +
			"With --decree-public-key each record's operator signature is checked.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			hc, err := conn.HTTPClient(cmd.Context())
			if err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(cmd.Context(), http.MethodGet, strings.TrimRight(conn.URL, "/")+"/ha/decrees", nil)
			if err != nil {
				return err
			}
			resp, err := hc.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("GET /ha/decrees: %s", resp.Status)
			}
			var records []cdsha.DecreeRecord
			if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&records); err != nil {
				return fmt.Errorf("GET /ha/decrees: %w", err)
			}
			return printDecrees(cmd.OutOrStdout(), records, decrKey, asJSON)
		},
	}
	cdsconn.BindFlags(cmd.Flags(), &conn)
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the records as JSON")
	cmd.Flags().StringVar(&decrKey, "decree-public-key", "", "PEM public key the decrees must be signed with (bundle cdsHA.decreeKey); checks every record")
	return cmd
}

func printDecrees(w io.Writer, records []cdsha.DecreeRecord, keyPath string, asJSON bool) error {
	var pub []byte
	if keyPath != "" {
		data, err := os.ReadFile(keyPath)
		if err != nil {
			return err
		}
		b, _ := pem.Decode(data)
		if b == nil || b.Type != "PUBLIC KEY" {
			return errors.New("--decree-public-key: want a PEM PUBLIC KEY")
		}
		pub = b.Bytes
	}
	bad := 0
	for _, r := range records {
		if pub != nil {
			if err := cdsha.VerifyDecreeSignature(r.Decree, pub); err != nil {
				bad++
				fmt.Fprintf(w, "UNVERIFIED epoch=%d intent=%s: %v\n", r.Epoch, r.Decree.Decree.IntentID, err)
			}
		}
	}
	if asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(records); err != nil {
			return err
		}
	} else {
		for _, r := range records {
			d := r.Decree.Decree
			fmt.Fprintf(w, "epoch=%-4d %s %-18s intent=%s base=%d", r.Epoch, time.UnixMilli(r.AtMS).UTC().Format(time.RFC3339), d.Kind, d.IntentID, d.BaseEpoch)
			if len(d.Images) > 0 {
				fmt.Fprintf(w, " images=%d", len(d.Images))
			}
			if d.Voters > 0 {
				fmt.Fprintf(w, " voters=%d", d.Voters)
			}
			if d.BootstrapNode != "" {
				fmt.Fprintf(w, " node=%s", d.BootstrapNode)
			}
			fmt.Fprintln(w)
		}
	}
	if bad > 0 {
		return fmt.Errorf("%d of %d records do not carry a valid operator signature", bad, len(records))
	}
	return nil
}

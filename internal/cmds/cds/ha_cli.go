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
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cdsconn"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
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
		target     = cdsconn.Options{DirectCDS: true}
	)
	cmd := &cobra.Command{
		Use:   "decree",
		Short: "Sign a decree and print it as a CDSDecree object for kubectl apply",
		Long: "Signs a Genesis, UpdateMeasurements or RotateKey decree with the operator key and prints the\n" +
			"decree object (a ConfigMap) as JSON. Apply it with kubectl; the leader replica\n" +
			"applies it and every replica checks the signature. Re-sign with the current epoch\n" +
			"if it is rejected for a base_epoch conflict.\n\n" +
			"Genesis and Recover act on one replica process: the CLI reads its member ID from GET /ha/status\n" +
			"of --target-url over armTLS (pin it with --target-image-policy-file or --target-measurements) and\n" +
			"signs it into the decree (target_member). A restarted replica has a new ID, so the decree is then\n" +
			"dead: read the ID again and re-sign. --bootstrap-node defaults to the target's node.\n" +
			"They expire after 10 minutes by default.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			d.Kind = cdsha.DecreeKind(kind)
			if d.Alone && d.Kind != cdsha.Genesis {
				return errors.New("--alone is for Genesis only")
			}
			switch d.Kind {
			case cdsha.Genesis, cdsha.Recover:
				if target.URL == "" {
					return fmt.Errorf("a %s decree needs --target-url: the replica it is for (on --bootstrap-node), whose member ID is read over armTLS", d.Kind)
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
				if d.BootstrapNode != "" || target.URL != "" {
					return errors.New("--bootstrap-node and --target-url are for Genesis and Recover only")
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
			key, err := certutil.LoadECPrivateKeyFile(keyPath)
			if err != nil {
				return err
			}
			if d.Kind == cdsha.Genesis || d.Kind == cdsha.Recover {
				st, err := readTargetStatus(cmd.Context(), target)
				if err != nil {
					return fmt.Errorf("target replica status: %w", err)
				}
				if err := bindTarget(&d, st); err != nil {
					return err
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "decree for member %s on node %s\n", d.TargetMember, d.BootstrapNode)
				if d.Alone {
					fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: --alone: the replica starts the cluster even if it finds no other replica. Use it only for a one-replica cluster: with more, a host that hides the others gets a cluster beside them.")
				}
			}
			if d.IntentID == "" {
				d.IntentID = cdsha.NewIntentID()
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
	f.StringVar(&d.BootstrapNode, "bootstrap-node", "", "Genesis: the node whose replica starts the cluster; Recover: the surviving node (default: the --target-url replica's node)")
	f.StringVar(&keyPath, "operator-key", "", "PEM EC private key matching the cluster's --ha-operator-key")
	f.StringVar(&namespace, "namespace", "c8s-cds-decrees", "namespace the decree object is written to (the replicas' --ha-decree-namespace)")
	f.DurationVar(&expiresIn, "expires-in", time.Hour, "decree lifetime")
	f.BoolVar(&ackFork, "i-understand-rotation-forks-the-cluster", false, "required for RotateKey")
	f.BoolVar(&ackRecover, "i-understand-recover-is-break-glass", false, "required for Recover")
	f.BoolVar(&d.Alone, "alone", false, "Genesis: start even if the replica finds no other replica (a one-replica cluster only)")
	bindTargetFlags(f, &target)
	_ = cmd.MarkFlagRequired("cluster-id")
	_ = cmd.MarkFlagRequired("operator-key")
	return cmd
}

// bindTargetFlags adds the connection flags of the replica a one-shot decree
// is for, as "target-" flags: `ha decree` has its own --measurements and
// --operator-key.
func bindTargetFlags(f *pflag.FlagSet, o *cdsconn.Options) {
	all := pflag.NewFlagSet("", pflag.ContinueOnError)
	cdsconn.BindFlags(all, o)
	all.VisitAll(func(fl *pflag.Flag) {
		if fl.Name != "operator-key" {
			fl.Name, fl.Shorthand = "target-"+fl.Name, ""
			fl.Usage = "target replica: " + fl.Usage
			f.AddFlag(fl)
		}
	})
}

// readTargetStatus reads a replica's own status over the attested channel
// the connection options build (armTLS; plaintext only with --insecure).
// Its member ID is what a one-shot decree binds to, so it must come from the
// verified replica, never from an unauthenticated answer.
func readTargetStatus(ctx context.Context, o cdsconn.Options) (cdsha.Status, error) {
	var st cdsha.Status
	hc, err := o.HTTPClient(ctx)
	if err != nil {
		return st, err
	}
	if err := getJSON(ctx, hc, o.URL, "/ha/status", 1<<16, &st); err != nil {
		return st, err
	}
	return st, nil
}

// bindTarget names the target replica's process in a Genesis or Recover
// decree: Genesis goes to a replica that holds no cluster, Recover to a
// member of the cluster it carries on.
func bindTarget(d *cdsha.Decree, st cdsha.Status) error {
	switch {
	case st.ClusterID != d.ClusterID:
		return fmt.Errorf("the target replica is of cluster %q, not %q", st.ClusterID, d.ClusterID)
	case d.BootstrapNode != "" && st.NodeName != d.BootstrapNode:
		return fmt.Errorf("the target replica runs on node %q, not --bootstrap-node %q", st.NodeName, d.BootstrapNode)
	case st.ID == "":
		return errors.New("the target replica reports no member id")
	case d.Kind == cdsha.Genesis && st.Joined:
		return errors.New("the target replica already holds a cluster: Genesis is only for a cluster that was never started")
	case d.Kind == cdsha.Recover && !st.Joined:
		return errors.New("the target replica holds no cluster: Recover carries on a survivor's state (a total loss is `c8s cds ha recover`)")
	}
	d.BootstrapNode, d.TargetMember = st.NodeName, st.ID
	return nil
}

// newHAStatusCmd reads each replica's view over armTLS, as `ha decrees` does.
// A status is the replica's own word; the command only compares them.
func newHAStatusCmd() *cobra.Command {
	conn := cdsconn.Options{DirectCDS: true}
	cmd := &cobra.Command{
		Use:   "status URL...",
		Short: "Report each replica's role, epoch, mesh CA and freshness from GET /ha/status (over armTLS)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, urls []string) error {
			var seen []cdsha.Status
			for _, u := range urls {
				// One attested client per replica: one client reaches one peer (cdsconn).
				var hb cdsha.Status
				one := conn
				one.URL = u
				hc, err := one.HTTPClient(cmd.Context())
				if err == nil {
					err = getJSON(cmd.Context(), hc, u, "/ha/status", 1<<16, &hb)
				}
				if err != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "%-40s ERROR %v\n", u, err)
					continue
				}
				seen = append(seen, hb)
				fmt.Fprintf(cmd.OutOrStdout(), "%-40s cluster=%s node=%s id=%s state=%s joined=%t epoch=%d serving=%t ca=%s voters=%d non_voters=%d applied=%d term=%d\n",
					u, hb.ClusterID, hb.NodeName, hb.ID, hb.State, hb.Joined, hb.Epoch, hb.Serving, hb.CAFingerprint, len(hb.Voters), len(hb.NonVoters), hb.AppliedIndex, hb.Term)
				if f := hb.Fenced; f != nil {
					fmt.Fprintf(cmd.OutOrStdout(), "%-40s FENCED since=%s stale_for=%s cut_off=%v decree=%s member=%s: %s\n", u,
						time.UnixMilli(f.SinceMS).UTC().Format(time.RFC3339), time.Duration(f.StaleForMS)*time.Millisecond, f.CutOffVoters, f.Decree, f.Member, f.Reason)
				}
			}
			return reportDivergence(seen, len(urls))
		},
	}
	// The connection flags of every CDS CLI, but the replicas are the
	// arguments and nothing is written.
	all := pflag.NewFlagSet("", pflag.ContinueOnError)
	cdsconn.BindFlags(all, &conn)
	all.VisitAll(func(f *pflag.Flag) {
		if f.Name != "url" && f.Name != "operator-key" {
			cmd.Flags().AddFlag(f)
		}
	})
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

// getJSON decodes the JSON answer of GET base+path, at most limit bytes.
func getJSON(ctx context.Context, hc *http.Client, base, path string, limit int64, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+path, nil)
	if err != nil {
		return err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, limit)).Decode(out); err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	return nil
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
			records, err := fetchDecreeRecord(cmd.Context(), hc, conn.URL)
			if err != nil {
				return err
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

// fetchDecreeRecord reads the decrees the cluster applied (GET /ha/decrees).
func fetchDecreeRecord(ctx context.Context, hc *http.Client, base string) ([]cdsha.DecreeRecord, error) {
	var records []cdsha.DecreeRecord
	return records, getJSON(ctx, hc, base, "/ha/decrees", 16<<20, &records)
}

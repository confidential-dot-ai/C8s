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
	cmd.AddCommand(newHADecreeCmd(), newHAStatusCmd(), newHARecoverCmd(), newHADecreesCmd(), newHARecoveryKeyCmd(), newHAPinPolicyCmd())
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
		Long: "Signs a Genesis, UpdateMeasurements, RotateKey, SetVoters or Recover decree with the operator key and prints the\n" +
			"decree object (a ConfigMap) as JSON. Apply it with kubectl; the leader replica\n" +
			"applies it and every replica checks the signature. Re-sign with the current epoch\n" +
			"if it is rejected for a base_epoch conflict.\n\n" +
			"Genesis and Recover act on one replica process: the CLI reads its member ID from GET /ha/status\n" +
			"of --target-url over armTLS (pin it with --target-image-policy-file or --target-measurements) and\n" +
			"signs it into the decree (target_member). A restarted replica has a new ID, so the decree is then\n" +
			"dead: read the ID again and re-sign. --bootstrap-node defaults to the target's node.\n" +
			"Genesis and Recover expire after 10 minutes by default, the other kinds after --expires-in.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			d.Kind = cdsha.DecreeKind(kind)
			if d.Alone && d.Kind != cdsha.Genesis {
				return errors.New("--alone is for Genesis only")
			}
			if d.ResumeEpoch != 0 && d.Kind != cdsha.Recover {
				return errors.New("--resume-epoch is for Recover only")
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
					if d.ResumeEpoch == 0 {
						return errors.New("a Recover decree needs --resume-epoch: the highest epoch you know the cluster reached (c8s cds ha decrees, or the base_epoch c8s cds ha pin-policy shows), at least --base-epoch; the survivor resumes after it, so nodes take its next pin decree")
					}
					if d.ResumeEpoch < d.BaseEpoch {
						return fmt.Errorf("--resume-epoch %d is below --base-epoch %d: name the highest epoch the cluster reached", d.ResumeEpoch, d.BaseEpoch)
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
					return errors.New("RotateKey forks the mesh: every workload must be re-issued under the new key. Pass --i-understand-rotation-forks-the-cluster to continue")
				}
				if len(d.Measurements) == 0 {
					fmt.Fprintln(cmd.ErrOrStderr(), "WARNING: RotateKey without --measurements delivers the new key to the current pin set. Prefer UpdateMeasurements first.")
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
	f.StringSliceVar(&d.Measurements, "measurements", nil, "complete new replica pin set; optional for RotateKey. Derived from --image when that is given")
	f.StringArrayVar(&images, "image", nil, "a CDS launch identity in hex: TDX mrtd:rtmr1:rtmr2, SNP the launch digest (one per accepted vCPU count); repeat for each. Lets nodes and pods follow the pin set (GET /ha/pins), so a CDS image rollout needs no node relaunch")
	f.StringVar(&d.IntentID, "intent-id", "", "decree nonce (default random)")
	f.StringVar(&d.BootstrapNode, "bootstrap-node", "", "Genesis: the node whose replica starts the cluster; Recover: the surviving node (default: the --target-url replica's node)")
	f.StringVar(&keyPath, "operator-key", "", "PEM EC private key matching the cluster's --ha-operator-key")
	f.StringVar(&namespace, "namespace", "c8s-cds-decrees", "namespace the decree object is written to (the replicas' --ha-decree-namespace)")
	f.DurationVar(&expiresIn, "expires-in", time.Hour, "decree lifetime (Genesis and Recover: 10m unless set)")
	f.BoolVar(&ackFork, "i-understand-rotation-forks-the-cluster", false, "required for RotateKey")
	f.BoolVar(&ackRecover, "i-understand-recover-is-break-glass", false, "required for Recover")
	f.BoolVar(&d.Alone, "alone", false, "Genesis: start even if the replica finds no other replica (a one-replica cluster only)")
	f.Uint64Var(&d.ResumeEpoch, "resume-epoch", 0, "Recover: the highest epoch you know the cluster reached, at least --base-epoch (required); the survivor resumes at the epoch after it")
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
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "status URL...",
		Short: "Report each replica's role, epoch, mesh CA, seats, backups and alarms from GET /ha/status (over armTLS)",
		Long: "Reads GET /ha/status from every replica over armTLS and prints one line per replica, then one line\n" +
			"for each alarm it reports (FENCED, divergence, backup_error, stuck). Leader-only fields (seats,\n" +
			"seats_filled, retiring_voters, known_voters, fenced, backup_error, last_backup) are zero on the\n" +
			"other replicas. last_backup is index:epoch:age. --json prints every replica's full status instead.\n" +
			"Exits non-zero when a replica is unreachable, does not serve, or the replicas disagree.",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, urls []string) error {
			var (
				seen    []cdsha.Status
				reports []replicaStatus
			)
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
					reports = append(reports, replicaStatus{URL: u, Error: err.Error()})
					if !asJSON {
						fmt.Fprintf(cmd.OutOrStdout(), "%-40s ERROR %v\n", u, err)
					}
					continue
				}
				seen = append(seen, hb)
				reports = append(reports, replicaStatus{URL: u, Status: &hb})
				if !asJSON {
					printStatus(cmd.OutOrStdout(), u, hb)
				}
			}
			if asJSON {
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				if err := enc.Encode(reports); err != nil {
					return err
				}
			}
			return reportDivergence(seen, len(urls))
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print each replica's URL and full /ha/status (or its error) as a JSON array")
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

// replicaStatus is one replica in `ha status --json`.
type replicaStatus struct {
	URL    string        `json:"url"`
	Status *cdsha.Status `json:"status,omitempty"`
	Error  string        `json:"error,omitempty"`
}

// printStatus prints a replica's line, then a line per alarm. Scripts read
// the line by key=: new keys are appended, and values never hold spaces, so
// free text (reasons, errors) goes on the alarm lines only.
func printStatus(w io.Writer, u string, hb cdsha.Status) {
	cp := "-"
	if hb.Checkpoint != nil {
		cp = fmt.Sprintf("%d:%.16s", hb.Checkpoint.Index, hb.Checkpoint.State)
	}
	backup := "-"
	if b := hb.LastBackup; b != nil {
		backup = fmt.Sprintf("%d:%d:%s", b.Index, b.Epoch, (time.Duration(b.AgeMS) * time.Millisecond).Round(time.Second))
	}
	stuck := "-"
	if hb.Stuck != "" {
		stuck = "deterministic"
		if hb.StuckLocal {
			stuck = "local"
		}
	}
	fmt.Fprintf(w, "%-40s cluster=%s node=%s id=%s state=%s joined=%t epoch=%d serving=%t ca=%s voters=%d non_voters=%d applied=%d term=%d checkpoint=%s"+
		" seats=%d seats_filled=%t retiring_voters=%d known_voters=%d fenced=%t backup_error=%t last_backup=%s stuck=%s awaiting_restore=%t divergence=%t\n",
		u, hb.ClusterID, hb.NodeName, hb.ID, hb.State, hb.Joined, hb.Epoch, hb.Serving, hb.CAFingerprint, len(hb.Voters), len(hb.NonVoters), hb.AppliedIndex, hb.Term, cp,
		hb.Seats, hb.SeatsFilled, len(hb.RetiringVoters), len(hb.KnownVoters), hb.Fenced != nil, hb.BackupError != "", backup, stuck, hb.AwaitingRestore, hb.Divergence != "")
	if f := hb.Fenced; f != nil {
		fmt.Fprintf(w, "%-40s FENCED since=%s stale_for=%s cut_off=%v decree=%s member=%s: %s\n", u,
			time.UnixMilli(f.SinceMS).UTC().Format(time.RFC3339), time.Duration(f.StaleForMS)*time.Millisecond, f.CutOffVoters, f.Decree, f.Member, f.Reason)
	}
	if hb.Divergence != "" {
		fmt.Fprintf(w, "%-40s divergence: %s\n", u, hb.Divergence)
	}
	if hb.BackupError != "" {
		fmt.Fprintf(w, "%-40s backup_error: %s\n", u, hb.BackupError)
	}
	if hb.Stuck != "" {
		fmt.Fprintf(w, "%-40s stuck (%s): %s\n", u, stuck, hb.Stuck)
	}
}

func reportDivergence(seen []cdsha.Status, want int) error {
	if len(seen) != want {
		return fmt.Errorf("%d of %d replicas unreachable", want-len(seen), want)
	}
	at := map[uint64]string{} // checkpoint index -> state digest
	for _, hb := range seen {
		if hb.Epoch != seen[0].Epoch || hb.CAFingerprint != seen[0].CAFingerprint || !hb.Serving {
			return errors.New("replicas disagree or are not serving")
		}
		if p := hb.Checkpoint; p != nil {
			if s, ok := at[p.Index]; ok && s != p.State {
				return fmt.Errorf("replicas hold different state at checkpoint %d", p.Index)
			}
			at[p.Index] = p.State
		}
		if strings.HasPrefix(hb.Divergence, "no majority") || strings.HasPrefix(hb.Divergence, "this leader") {
			return errors.New("the leader reports an unresolved divergence")
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
		var img cdsha.DecreeImage
		switch len(parts) {
		case 3:
			img = cdsha.DecreeImage{MRTD: parts[0], RTMR1: parts[1], RTMR2: parts[2]}
		case 1:
			img = cdsha.DecreeImage{Measurement: parts[0]}
		default:
			return fmt.Errorf("--image %q: want mrtd:rtmr1:rtmr2 (TDX) or a launch digest (SNP)", spec)
		}
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

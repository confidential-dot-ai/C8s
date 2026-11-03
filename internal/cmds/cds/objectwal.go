package cds

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/attestation"
	"github.com/confidential-dot-ai/c8s/internal/cdsha"
	"github.com/confidential-dot-ai/c8s/internal/cdsobject"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
)

const (
	objectProvisionPath = "/ha/object-wal/provision"
	objectStatsPath     = "/ha/object-wal/status"
	maxProvisionBytes   = 16 << 10
)

func newObjectReplica(ctx context.Context, cfg config, st stores) (backend, error) {
	if cfg.allowlistPersistent {
		return nil, errors.New("object WAL pilot requires disposable local allowlist storage")
	}
	if err := emptyAllowlist(st.allowlist); err != nil {
		return nil, err
	}
	running, cancel := context.WithCancel(ctx)
	launch := sha256.Sum256(cfg.measuredFile)
	node, err := cdsobject.New(running, cdsobject.Config{
		Launch: cdsha.Launch{ClusterID: cfg.measured.ClusterID, OperatorKeys: cfg.measured.OperatorKeys.Keys(),
			ConfigSHA256: hex.EncodeToString(launch[:]), Voters: cfg.measured.HA.Voters},
		Storage:        *cfg.measured.HA.ObjectWALPilot,
		WALOptions:     cfg.measured.HA.ObjectWALPilot.WALOptions(),
		Address:        net.JoinHostPort(cfg.host, strconv.Itoa(cfg.port)),
		PeerHosts:      cfg.measured.HA.Replicas,
		LaunchFile:     cfg.measuredFile,
		AttestationURL: cfg.attestationApiURL,
		Allowlist:      st.allowlist, Secrets: st.secrets, Ledger: st.bindings,
	})
	if err != nil {
		cancel()
		return nil, err
	}
	ended := make(chan struct{})
	go func() { defer close(ended); node.Run(running) }()
	r := &clusterCDS{
		handles: handles{allowlist: node.Allowlist(), secrets: node.Secrets(), bindings: node.Bindings()},
		challengePools: challengePools{
			issuance: attestation.NewSharedChallenges(challengeIssuance, cfg.challengeTTL, clusterKey(node, challengeIssuance)),
			secrets:  attestation.NewSharedChallenges(challengeSecrets, cfg.challengeTTL, clusterKey(node, challengeSecrets)),
		},
		node: node, stopNode: func() { cancel(); <-ended }, ended: ended, freshPerRequest: true,
		extraRoutes: map[string]http.HandlerFunc{
			"POST " + cdsobject.ForwardPath: node.ServeForward,
			"POST " + objectProvisionPath:   provisionObjectWAL(node),
			"GET " + objectStatsPath:        reportJSON(node.WALStats),
		},
	}
	if err := r.join(ctx, cfg); err != nil {
		r.Stop()
		return nil, err
	}
	return r, nil
}

func provisionObjectWAL(node *cdsobject.Node) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := readutil.ReadAll(r.Body, maxProvisionBytes)
		if err != nil {
			http.Error(w, "invalid provisioning body", http.StatusBadRequest)
			return
		}
		defer clear(body)
		p, err := parseProvision(body)
		if err != nil {
			http.Error(w, "invalid provisioning body", http.StatusBadRequest)
			return
		}
		defer clear(p.Key)
		if err := node.Provision(p); err != nil {
			http.Error(w, "object WAL provisioning refused", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func parseProvision(body []byte) (cdsobject.Provision, error) {
	var p cdsobject.Provision
	d := json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if _, err := d.Token(); err != io.EOF {
		return p, errors.New("multiple provisioning values")
	}
	if len(p.Key) != 32 || p.Credentials.AccessKeyID == "" || p.Credentials.SecretAccessKey == "" {
		return p, errors.New("a 32-byte key and S3 credentials are required")
	}
	return p, nil
}

func newObjectWALCmd() *cobra.Command {
	group := &cobra.Command{Use: "object-wal", Short: "Operate the experimental encrypted object-WAL CDS pilot"}
	var target replica
	var input string
	provision := &cobra.Command{
		Use: "provision", Short: "Deliver a WAL key and S3 credentials over pinned armTLS", Args: cobra.NoArgs, SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			reader := cmd.InOrStdin()
			if input != "-" {
				file, err := os.Open(input)
				if err != nil {
					return err
				}
				defer file.Close()
				reader = file
			}
			body, err := readutil.ReadAll(reader, maxProvisionBytes)
			if err != nil {
				return errors.New("read provisioning input: invalid or oversized document")
			}
			defer clear(body)
			p, err := parseProvision(body)
			if err != nil {
				return errors.New("invalid provisioning document")
			}
			clear(p.Key)
			client, address, err := target.dial(cmd.Context())
			if err != nil {
				return err
			}
			request, err := http.NewRequestWithContext(cmd.Context(), http.MethodPost,
				"https://"+address.String()+objectProvisionPath, bytes.NewReader(body))
			if err != nil {
				return err
			}
			request.Header.Set("Content-Type", "application/json")
			response, err := client.Do(request)
			if err != nil {
				return errors.New("attested WAL provisioning request failed")
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				return fmt.Errorf("WAL provisioning refused: HTTP %d", response.StatusCode)
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), "Provisioned object WAL through the verified CDS connection.")
			return err
		},
	}
	bindTargetFlags(provision, &target)
	provision.Flags().StringVar(&input, "input", "-", "operator-local JSON file containing the key (base64) and credentials; - reads stdin")
	group.AddCommand(provision)
	return group
}

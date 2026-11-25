package taha

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cdschain"
	"github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/cmdsutil"
	haapi "github.com/confidential-dot-ai/confidential-kubernetes/internal/taha"
)

type verifiedPolicy struct {
	ArtifactSHA256 cdschain.Hash                    `json:"artifact_sha256"`
	PolicySHA256   cdschain.Hash                    `json:"policy_sha256"`
	Predecessor    cdschain.Head                    `json:"predecessor"`
	Entry          cdschain.Head                    `json:"entry"`
	CurrentEntries map[cdschain.Type]cdschain.Entry `json:"current_entries"`
}

func newVerifyPolicyCmd(o *options) *cobra.Command {
	var cluster, expected, file, digest string
	cmd := &cobra.Command{
		Use:   "verify-policy",
		Short: "Check a signed policy successor against the current attested head",
		Long: `Verify the native entry in --file using independent --cluster, --genesis,
--expect-head and --image-policy-file pins. Require its exact canonical allowlist
bytes to match the reviewed --policy-sha256. Replay the log under its historical
authority and saved acknowledged floor, and require the expected predecessor to
remain the head reported by a fresh, serving replica.
current_entries contains the latest held policy and routes bodies and signatures;
an absent type has no entry in the verified log. This is not confirmation.

This check sends only GETs and changes no local record, cache or input file.
It loads no operator key and never signs or submits the candidate. --insecure
is refused. An already-held entry is refused; use observe-policy for acceptance.

Success describes the state checked, not a reserved position or proof of chain
confirmation, Git publication or application readiness. Deployment tooling must
check the accepted baseline and phase gates separately. A later write can
invalidate the successor. An absent local record is treated as first use.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := o.policyTarget("verify-policy", cluster, expected)
			if err != nil {
				return err
			}
			encoded, entry, err := readSubmittedPolicy(file, target)
			if err != nil {
				return err
			}
			approved, err := reviewedPolicyDigest(entry, digest)
			if err != nil {
				return err
			}
			w, err := o.connection(cmd.Context())
			if err != nil {
				return err
			}
			return w.verifyPolicy(cmd.Context(), cmd.OutOrStdout(), target, encoded, entry, approved)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cluster, "cluster", "", "the independently trusted cluster ID")
	f.StringVar(&expected, "expect-head", "", "the required current predecessor as <seq>:<hash>")
	f.StringVar(&file, "file", "", "the unchanged native signed policy entry to check")
	f.StringVar(&digest, "policy-sha256", "", "SHA-256 of the independently reviewed canonical allowlist bytes")
	cmdsutil.RequireFlags(cmd, "cluster", "expect-head", "file", "policy-sha256")
	return cmd
}

func reviewedPolicyDigest(entry cdschain.Entry, digest string) (cdschain.Hash, error) {
	expected, err := cdschain.ParseHash(digest)
	if err != nil {
		return cdschain.Hash{}, fmt.Errorf("--policy-sha256: %w", err)
	}
	body, err := entry.Decode()
	if err != nil {
		return cdschain.Hash{}, err
	}
	var policy cdschain.Policy
	if err := cdschain.DecodeStrict(body.Payload, &policy); err != nil {
		return cdschain.Hash{}, err
	}
	if cdschain.Hash(sha256.Sum256(policy.Allowlist)) != expected {
		return cdschain.Hash{}, errors.New("the signed policy does not match --policy-sha256")
	}
	return expected, nil
}

func (w *writer) verifyPolicy(
	ctx context.Context,
	out io.Writer,
	target policyTarget,
	encoded []byte,
	entry cdschain.Entry,
	approved cdschain.Hash,
) error {
	history, err := w.readPolicy(ctx, target, entry)
	if err != nil {
		return err
	}
	if err := target.check(history.state); err != nil {
		return fmt.Errorf("the entry is no longer a successor of the current head: %w", err)
	}
	var status haapi.Status
	if err := haapi.Call(ctx, w.client, http.MethodGet, w.url+haapi.StatusPath, nil, &status); err != nil {
		return err
	}
	if err := history.checkServingHead(status); err != nil {
		return err
	}
	current := make(map[cdschain.Type]cdschain.Entry)
	for _, held := range history.entries {
		body, err := held.Decode()
		if err != nil {
			return err
		}
		if body.Type == cdschain.TypePolicy || body.Type == cdschain.TypeRoutes {
			current[body.Type] = held
		}
	}
	return printJSON(out, verifiedPolicy{
		ArtifactSHA256: cdschain.Hash(sha256.Sum256(encoded)),
		PolicySHA256:   approved,
		Predecessor:    history.state.Head,
		Entry:          history.entry,
		CurrentEntries: current,
	})
}

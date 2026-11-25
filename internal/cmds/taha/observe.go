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

var errPolicyUnconfirmed error = &cmdsutil.ExitStatusError{
	Status: cmdsutil.ExitNotConfirmed,
	Err:    errors.New("policy acceptance is not confirmed; rerun observe-policy"),
}

type observedPolicy struct {
	ArtifactSHA256 cdschain.Hash `json:"artifact_sha256"`
	Entry          cdschain.Head `json:"entry"`
	Confirmed      cdschain.Head `json:"confirmed"`
	Held           cdschain.Head `json:"held"`
	Current        bool          `json:"current"`
	Policy         cdschain.Head `json:"policy"`
	PolicySHA256   cdschain.Hash `json:"policy_sha256"`
}

func newObservePolicyCmd(o *options) *cobra.Command {
	var cluster, expected, file string
	cmd := &cobra.Command{
		Use:   "observe-policy",
		Short: "Verify a signed policy entry's confirmation without submitting it",
		Long: `Read the attested policy log and status under independent --cluster,
--genesis, --expect-head and --image-policy-file pins. --expect-head names the
artifact's predecessor. Require the exact body and signature in --file to be
held, with recorded confirmation of that entry or a descendant on the same log.

Print JSON only after saving the confirmed head durably. current reports whether
this entry still supplies policy; policy and policy_sha256 identify the policy
at held. Historical acceptance does not prove application readiness or that the
current held head is confirmed. Missing confirmation or a changed head exits 3.
Confirmation records can be lost on replica restart: retry observation after
the consumer or explicit manual submission confirms the entry again.
An absent local record is treated as first use; retain --state-dir durably.

This command sends only reads, never loads an operator key and refuses --insecure.
It neither publishes nor submits an entry.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			target, err := o.policyTarget("observe-policy", cluster, expected)
			if err != nil {
				return err
			}
			encoded, entry, err := readSubmittedPolicy(file, target)
			if err != nil {
				return err
			}
			w, err := o.connection(cmd.Context())
			if err != nil {
				return err
			}
			return w.observePolicy(cmd.Context(), cmd.OutOrStdout(), target, encoded, entry)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cluster, "cluster", "", "the independently trusted cluster ID")
	f.StringVar(&expected, "expect-head", "", "the artifact's independently trusted predecessor as <seq>:<hash>")
	f.StringVar(&file, "file", "", "the unchanged native signed policy entry to observe")
	cmdsutil.RequireFlags(cmd, "cluster", "expect-head", "file")
	return cmd
}

func (w *writer) observePolicy(ctx context.Context, out io.Writer, target policyTarget, encoded []byte, entry cdschain.Entry) error {
	history, err := w.readPolicy(ctx, target, entry)
	if err != nil {
		return err
	}
	if history.entry.Seq > history.state.Head.Seq {
		return fmt.Errorf("the replica does not hold the entry: %w", errPolicyUnconfirmed)
	}
	var status haapi.Status
	if err := haapi.Call(ctx, w.client, http.MethodGet, w.url+haapi.StatusPath, nil, &status); err != nil {
		return err
	}
	confirmed, err := history.confirmation(status)
	if err != nil {
		return err
	}
	if err := w.o.acknowledge(target.genesis, confirmed); err != nil {
		if errors.Is(err, ErrRecordConflict) {
			return err
		}
		return &cmdsutil.ExitStatusError{
			Status: cmdsutil.ExitNotConfirmed,
			Err:    fmt.Errorf("the Trust Authority confirmed head %d (%s), but the local record was not saved; fix storage and rerun observe-policy: %w", confirmed.Seq, confirmed.Hash, err),
		}
	}
	policy := history.state.Head
	policy.Seq = history.state.PolicySeq
	policy.Hash = history.entries[policy.Seq].Hash()
	return printJSON(out, observedPolicy{
		ArtifactSHA256: cdschain.Hash(sha256.Sum256(encoded)),
		Entry:          history.entry,
		Confirmed:      confirmed,
		Held:           history.state.Head,
		Current:        policy.Seq == history.entry.Seq,
		Policy:         policy,
		PolicySHA256:   cdschain.Hash(sha256.Sum256(history.state.Policy)),
	})
}

func (h *policyHistory) checkServingHead(s haapi.Status) error {
	if s.Serving != "" || !s.Fresh || !s.IsMember || s.Pending || s.Halted != "" || s.Fork != nil || s.Evicted != "" {
		return errors.New("the replica is not serving")
	}
	if s.Held == nil || *s.Held != h.state.Head {
		return errors.New("status and the verified log have different heads")
	}
	return nil
}

func (h *policyHistory) confirmation(s haapi.Status) (cdschain.Head, error) {
	if err := h.checkServingHead(s); err != nil {
		return cdschain.Head{}, fmt.Errorf("%v: %w", err, errPolicyUnconfirmed)
	}
	var confirmed cdschain.Head
	for _, head := range s.Confirmed {
		if head.V != h.state.Head.V || head.Cluster != h.state.Cluster || head.Seq >= uint64(len(h.entries)) || head.Hash != h.entries[head.Seq].Hash() {
			return cdschain.Head{}, errors.New("a reported confirmed head is outside the verified log")
		}
		if head.Seq >= h.entry.Seq && head.Seq > confirmed.Seq {
			confirmed = head
		}
	}
	if confirmed.Hash == (cdschain.Hash{}) {
		return cdschain.Head{}, errPolicyUnconfirmed
	}
	return confirmed, nil
}

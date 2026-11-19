//go:build !c8s_node

package cdsha

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdschain"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/worker"
)

func init() { operatorCommands = append(operatorCommands, newAcceptNodeCmd) }

func newAcceptNodeCmd(o *options) *cobra.Command {
	var documentPath, imagePath string
	cmd := &cobra.Command{
		Use:   "accept-node",
		Short: "Certify the workers launched with a worker document",
		Long: `Write a nodes entry: the node images the chain certifies now (the launch
file's before its first nodes entry) plus each --worker-image entry bound to the
digest of --worker-document. The document must pin an entry of this chain
(cds.chain) and an accepted CDS build (cds.measurements). The command prints
the facts every worker launched with the document joins with, and writes only
once you confirm them on standard input.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			document, err := os.ReadFile(documentPath)
			if err != nil {
				return fmt.Errorf("--worker-document: %w", err)
			}
			image, err := os.ReadFile(imagePath)
			if err != nil {
				return fmt.Errorf("--worker-image: %w", err)
			}
			w, err := o.writer(cmd.Context())
			if err != nil {
				return err
			}
			state, err := w.verified(cmd.Context())
			if err != nil {
				return err
			}
			a, err := admitOnChain(w.chain, state, document, image)
			if err != nil {
				return err
			}
			if err := a.Report(cmd.ErrOrStderr()); err != nil {
				return err
			}
			if !cmdsutil.Confirm(cmd.Context(), cmd.InOrStdin(), cmd.ErrOrStderr(), "certify every worker launched with this document?") {
				return errors.New("not confirmed: nothing written")
			}
			head, err := w.append(cmd.Context(), state, cdschain.TypeNodes, cdschain.Nodes{Nodes: string(a.Nodes)})
			if errors.Is(err, errHeadMoved) {
				return fmt.Errorf("%w: another write landed first; run the command again", err)
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "nodes entry at head %d (%s)\n", head.Seq, head.Hash)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&documentPath, "worker-document", "", "the worker document, read once")
	f.StringVar(&imagePath, "worker-image", "", "the worker image's measurements, as 'c8s measurements derive' writes them")
	_ = cmd.MarkFlagRequired("worker-document")
	_ = cmd.MarkFlagRequired("worker-image")
	return cmd
}

// admitOnChain admits a worker document against the chain c verified, whose
// head state is state: the document must pin an entry of c and an accepted
// build, and the set it extends is the one the chain certifies now.
func admitOnChain(c *verifiedChain, state *cdschain.State, document, image []byte) (worker.Admission, error) {
	doc, err := worker.Parse(document)
	if err != nil {
		return worker.Admission{}, err
	}
	if doc.CDS.Chain == "" {
		return worker.Admission{}, errors.New("the worker document pins no chain entry (cds.chain): its workers would not follow this replica set")
	}
	pin, err := cdschain.ParsePin(doc.CDS.Chain)
	if err != nil {
		return worker.Admission{}, fmt.Errorf("cds.chain: %w", err)
	}
	if pin.Seq >= uint64(len(c.Hashes)) || c.Hashes[pin.Seq] != pin.Hash {
		return worker.Admission{}, fmt.Errorf("cds.chain %s is not an entry of this replica set's chain", doc.CDS.Chain)
	}
	cdsPin, err := acceptedPin(state, doc.CDS.Measurements)
	if err != nil {
		return worker.Admission{}, err
	}
	nodes, err := nodesInForce(state)
	if err != nil {
		return worker.Admission{}, err
	}
	return worker.Admit(bytes.NewReader(document), worker.AdmitInputs{CDSPin: cdsPin, WorkerImage: image, Nodes: nodes})
}

// acceptedPin is the accepted build that pins exactly what measurements does.
func acceptedPin(state *cdschain.State, measurements string) ([]byte, error) {
	theirs, err := refvalues.Parse([]byte(measurements))
	if err != nil {
		return nil, fmt.Errorf("cds.measurements: %w", err)
	}
	for _, b := range state.Accepted {
		mine, err := b.Values()
		if err != nil {
			return nil, err
		}
		if missing, extra := refvalues.Diff(mine, theirs); mine.Family == theirs.Family && len(missing) == 0 && len(extra) == 0 {
			return []byte(b.Measurements), nil
		}
	}
	return nil, errors.New("cds.measurements pins no CDS build the chain accepts")
}

// nodesInForce is the node image set the chain certifies: its newest nodes
// entry, else the nodes of the launch file every accepted build binds.
func nodesInForce(state *cdschain.State) ([]byte, error) {
	if state.Nodes != "" {
		return []byte(state.Nodes), nil
	}
	launch, err := cmdsutil.CDSLaunchFile(state.Pins())
	if err != nil {
		return nil, err
	}
	config, err := cdsconfig.Parse(launch)
	if err != nil {
		return nil, fmt.Errorf("the accepted builds' CDS configuration: %w", err)
	}
	return refvalues.Format(config.Nodes)
}

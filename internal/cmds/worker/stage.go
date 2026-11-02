package worker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// stagedLaunchFile is where the measured initrd stages the launch file,
// read-only, once its digest matched the launch's init data.
const stagedLaunchFile = "/run/confai/operator-pubkey"

// workerImageMarker is the file a worker image bakes; no other image runs
// stage.
const workerImageMarker = "/usr/lib/c8s/worker-image"

// NewStageCmd returns `worker stage`, run on a worker at boot.
func NewStageCmd() *cobra.Command {
	var document, bootstrapTokenFile string
	cmd := &cobra.Command{
		Use:   "stage",
		Short: "Stage this worker's measured document into its NRI floor and kubelet",
		Long: `Read the worker document the initrd staged, confirm through the node-local
attestation API that this worker's launch binding commits the document,
then publish the CDS pin and router settings under /run/c8s-node, write
the NRI floor with the document's CDS and pod and Service ranges, and write
the kubelet's configuration, bootstrap kubeconfig and static pods under
/etc/kubernetes. The node name is derived from this boot's ID. Every output
is removed first, and again if any step fails.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := stage(cmd.Context(), "", document, bootstrapTokenFile, launchconfig.DefaultAttestationAPIURL); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "worker document staged")
			return nil
		},
	}
	cmd.Flags().StringVar(&document, "document", stagedLaunchFile, "the worker document: the measured launch file the initrd stages here")
	cmd.Flags().StringVar(&bootstrapTokenFile, "bootstrap-token-file", "", "file holding the Kubernetes bootstrap token the kubelet joins with")
	_ = cmd.MarkFlagRequired("bootstrap-token-file")
	return cmd
}

// stage removes every output, then writes them from the document at
// documentPath and the bootstrap token at tokenPath. On any error it removes
// them again, so nothing usable is left behind. Off a worker image it touches
// nothing. rootDir rebases the outputs, the marker, the static pod templates
// and the boot ID for tests.
func stage(ctx context.Context, rootDir, documentPath, tokenPath, attestationAPIURL string) error {
	if err := requireWorkerImage(rootDir); err != nil {
		return err
	}
	if err := clearOutputs(rootDir); err != nil {
		return fmt.Errorf("remove stale outputs: %w", err)
	}
	if err := stageDocument(ctx, rootDir, documentPath, tokenPath, attestationAPIURL); err != nil {
		return errors.Join(err, clearOutputs(rootDir))
	}
	return nil
}

// clearOutputs removes the kubelet's inputs before the floor, the reverse of
// the order stage writes them, so an interrupted clear leaves no kubelet
// input without its floor.
func clearOutputs(rootDir string) error {
	if err := os.RemoveAll(filepath.Join(rootDir, kubernetesDir)); err != nil {
		return err
	}
	return nodeservices.Clear(rootDir)
}

// requireWorkerImage refuses an image without the worker image's marker.
func requireWorkerImage(rootDir string) error {
	info, err := os.Stat(filepath.Join(rootDir, workerImageMarker))
	if err != nil {
		return fmt.Errorf("worker stage runs only on a worker image: %w", err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("worker stage runs only on a worker image: %s is not a regular file", workerImageMarker)
	}
	return nil
}

// stageDocument reads the document once, and parses it only after this
// worker's launch binding proves it is the document the worker launched with.
// It renders every output before writing the first.
func stageDocument(ctx context.Context, rootDir, documentPath, tokenPath, attestationAPIURL string) error {
	data, err := readDocument(documentPath)
	if err != nil {
		return err
	}
	err = credrelease.VerifyLaunchBinding(ctx, attestationAPIURL, filepath.Join(rootDir, armtls.NodeJournal), data)
	if errors.Is(err, credrelease.ErrLaunchFileNotBound) {
		return fmt.Errorf("--document %s is not the document this worker launched with: %w", documentPath, err)
	}
	if err != nil {
		return fmt.Errorf("check this worker's launch binding: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return err
	}
	token, err := readBootstrapToken(tokenPath)
	if err != nil {
		return err
	}
	name, err := nodeName(rootDir)
	if err != nil {
		return err
	}
	kubelet, err := renderKubelet(rootDir, doc.Kubernetes, token, name)
	if err != nil {
		return err
	}
	router, err := nodeservices.RouterOutputs(doc.Router)
	if err != nil {
		return err
	}
	err = nodeservices.Prepare(rootDir, nodeservices.FloorInputs{
		CDS:           doc.CDS,
		ClusterRanges: []string{doc.Kubernetes.PodCIDR, doc.Kubernetes.ServiceCIDR},
		Placeholders:  workerValues(name, doc.Kubernetes),
		Outputs:       router,
	})
	if err != nil {
		return err
	}
	return kubelet.write(rootDir)
}

func readDocument(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("--document: %w", err)
	}
	defer f.Close()
	data, err := readutil.ReadAll(f, launchconfig.MaxDocumentSize)
	if err != nil {
		return nil, fmt.Errorf("--document %s: %w", path, err)
	}
	return data, nil
}

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
	var document string
	cmd := &cobra.Command{
		Use:   "stage",
		Short: "Stage this worker's measured document into its NRI floor",
		Long: `Read the worker document the initrd staged, confirm through the node-local
attestation API that this worker's launch binding commits the document,
then publish the CDS pin and router settings under /run/c8s-node and write
the NRI floor with the document's CDS and pod and Service ranges. Every
output is removed first, and again if any step fails.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if err := stage(cmd.Context(), "", document, launchconfig.DefaultAttestationAPIURL); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "worker document staged")
			return nil
		},
	}
	cmd.Flags().StringVar(&document, "document", stagedLaunchFile, "the worker document: the measured launch file the initrd stages here")
	return cmd
}

// stage removes every output, then publishes them from the document at path.
// On any error it removes them again, so nothing usable is left behind. Off a
// worker image it touches nothing. rootDir rebases the outputs and the marker
// for tests.
func stage(ctx context.Context, rootDir, path, attestationAPIURL string) error {
	if err := requireWorkerImage(rootDir); err != nil {
		return err
	}
	if err := nodeservices.Clear(rootDir); err != nil {
		return fmt.Errorf("remove stale outputs: %w", err)
	}
	if err := stageDocument(ctx, rootDir, path, attestationAPIURL); err != nil {
		return errors.Join(err, nodeservices.Clear(rootDir))
	}
	return nil
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
func stageDocument(ctx context.Context, rootDir, path, attestationAPIURL string) error {
	data, err := readDocument(path)
	if err != nil {
		return err
	}
	err = credrelease.VerifyLaunchBinding(ctx, attestationAPIURL, filepath.Join(rootDir, armtls.NodeJournal), data)
	if errors.Is(err, credrelease.ErrLaunchFileNotBound) {
		return fmt.Errorf("--document %s is not the document this worker launched with: %w", path, err)
	}
	if err != nil {
		return fmt.Errorf("check this worker's launch binding: %w", err)
	}
	doc, err := Parse(data)
	if err != nil {
		return err
	}
	router, err := nodeservices.RouterOutputs(doc.Router)
	if err != nil {
		return err
	}
	return nodeservices.Prepare(rootDir, nodeservices.FloorInputs{
		CDS:           doc.CDS,
		ClusterRanges: []string{doc.Kubernetes.PodCIDR, doc.Kubernetes.ServiceCIDR},
		Outputs:       router,
	})
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

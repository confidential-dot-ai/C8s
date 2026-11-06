package worker

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/credrelease"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	nriimagepolicy "github.com/confidential-dot-ai/c8s/internal/cmds/nri-image-policy"
	"github.com/confidential-dot-ai/c8s/internal/readutil"
	"github.com/confidential-dot-ai/c8s/pkg/armtls"
)

// stagedLaunchFile is where the measured initrd stages the launch file,
// read-only, once its digest matched the launch's init data.
const stagedLaunchFile = "/run/confai/operator-pubkey"

// primaryIPv4 is a package var so tests can fake the host's routes.
var primaryIPv4 = launchconfig.PrimaryIPv4

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
the NRI floor with the document's CDS, pod and Service ranges and cluster
DNS, publish the node's primary IPv4 for the NRI inventory, and write
the kubelet's configuration, bootstrap kubeconfig and static pods under
/run/kubernetes. The node name is derived from this boot's ID. Every output
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

// clearOutputs removes the kubelet's inputs, the node address, then the
// floor, the reverse of the order stage writes them, so an interrupted clear
// leaves no kubelet input without its floor.
func clearOutputs(rootDir string) error {
	if err := os.RemoveAll(filepath.Join(rootDir, kubernetesDir)); err != nil {
		return err
	}
	if err := nodeservices.ClearNodeIP(rootDir); err != nil {
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
	return writeOutputs(rootDir, doc, token)
}

// writeOutputs checks the floor it writes before writing the node address and
// the kubelet's inputs, the outputs clearOutputs removes first.
func writeOutputs(rootDir string, doc *Document, token string) error {
	name, err := nodeName(rootDir)
	if err != nil {
		return err
	}
	address, err := primaryIPv4()
	if err != nil {
		return fmt.Errorf("resolve node address: %w", err)
	}
	kubelet, err := renderKubelet(rootDir, doc.Kubernetes, token, name, address)
	if err != nil {
		return err
	}
	outputs, err := routerOutputs(doc)
	if err != nil {
		return err
	}
	err = nodeservices.Prepare(rootDir, nodeservices.FloorInputs{
		CDS:           doc.CDS,
		ClusterRanges: []string{doc.Kubernetes.PodCIDR, doc.Kubernetes.ServiceCIDR},
		Resolver:      doc.Kubernetes.ClusterDNS,
		Placeholders:  workerValues(name, doc.Kubernetes),
		Outputs:       outputs,
	})
	if err != nil {
		return err
	}
	if err := checkFloor(rootDir); err != nil {
		return err
	}
	if err := nodeservices.PublishNodeAddress(rootDir, address); err != nil {
		return err
	}
	return kubelet.write(rootDir)
}

// checkFloor loads the staged floor as the NRI plugin will, so a floor the
// plugin would refuse, or run under a server's rules, stops the worker here.
func checkFloor(rootDir string) error {
	data, err := os.ReadFile(filepath.Join(rootDir, nriimagepolicy.DefaultConfigPath))
	if err != nil {
		return err
	}
	if err := nriimagepolicy.CheckWorkerConfig(data); err != nil {
		return fmt.Errorf("staged NRI floor: %w", err)
	}
	return nil
}

// The files the router reads beside its settings, as on a server.
const (
	operatorKeysOutput = "operator-pubkey"
	tlsSANOutput       = "tls-san"
)

// routerOutputs are the files the router reads under /run/c8s-node, as on a
// server: its settings, the operator keys it verifies routes under and its
// front-door name.
func routerOutputs(doc *Document) (map[string][]byte, error) {
	outputs, err := nodeservices.RouterOutputs(doc.Router)
	if err != nil {
		return nil, err
	}
	keys, err := doc.operatorKeys()
	if err != nil {
		return nil, err
	}
	outputs[operatorKeysOutput] = keys
	outputs[tlsSANOutput] = []byte(doc.TLSSAN + "\n")
	return outputs, nil
}

// stagedPublicNames are the files stage publishes under /run/c8s-node.
func stagedPublicNames() ([]string, error) {
	router, err := nodeservices.RouterOutputs(nil)
	if err != nil {
		return nil, err
	}
	return append(slices.Collect(maps.Keys(router)), nodeservices.CDSOutput, operatorKeysOutput, tlsSANOutput), nil
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

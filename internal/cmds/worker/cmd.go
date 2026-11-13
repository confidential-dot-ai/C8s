package worker

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/confidential-dot-ai/c8s/internal/cmds/cmdsutil"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/fileutil"
)

// NewCmd returns the worker command group.
func NewCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "worker",
		Short: "Worker documents: the launch files of nodes whose Kubernetes control plane runs outside every TEE",
	}
}

// draft is a worker document as `worker new` takes it: the blocks from flags,
// and the CDS pin and the API server's CA from the files they name.
type draft struct {
	out               string
	cds               cmdsutil.CDS
	cdsPinPath        string
	tlsSAN            string
	router            nodeservices.Router
	kubernetes        Kubernetes
	caCertificatePath string
}

// NewNewCmd returns `worker new`, run by whoever drafts a worker document.
func NewNewCmd() *cobra.Command {
	var d draft
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Write a worker document",
		Long: `Write a worker document: the CDS a worker pins, the router's settings, and the
API server, CA, pod and Service ranges and cluster DNS address it joins its
Kubernetes cluster with. The document is checked under the rules a worker
parses it with, then written to --out, or to stdout without one.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			data, err := d.render()
			if err != nil {
				return err
			}
			if d.out == "" {
				_, err := cmd.OutOrStdout().Write(data)
				return err
			}
			if err := fileutil.WriteNew(d.out, data, 0o644); err != nil {
				return fmt.Errorf("--out: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote worker document %s\n", d.out)
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVar(&d.out, "out", "", "file to write the document to, which must not exist (default stdout)")
	f.StringVar(&d.cds.Address, "cds-address", "", "<host>:<port> the cluster's CDS serves on, the host a DNS name its clients resolve or an IPv4 address")
	f.StringVar(&d.cds.Chain, "cds-chain", "", "<seq>:<hash> of one entry of the CDS replica set's chain the worker pins (docs/cds-ha.md)")
	f.StringVar(&d.cdsPinPath, "cds-pin", "", "measurements document pinning the cluster's CDS VM to its configuration, as 'c8s cds config new' writes it")
	f.StringVar(&d.tlsSAN, "tls-san", "", "DNS name of the router's front-door certificate, one the pinned CDS configuration lets a leaf carry")
	nodeservices.BindRouterFlags(f, &d.router)
	f.StringVar(&d.kubernetes.APIServer, "api-server", "", "<host>:<port> of the cluster's Kubernetes API server, the host a DNS name or an IPv4 address")
	f.StringVar(&d.caCertificatePath, "ca-certificate", "", "PEM file holding the one CA certificate the API server's serving certificate chains to")
	f.StringVar(&d.kubernetes.PodCIDR, "pod-cidr", "", "the cluster's pod range, an IPv4 CIDR")
	f.StringVar(&d.kubernetes.ServiceCIDR, "service-cidr", "", "the cluster's Service range, an IPv4 CIDR")
	f.StringVar(&d.kubernetes.ClusterDNS, "cluster-dns", "", "the cluster DNS Service's IPv4 address, inside --service-cidr")
	cmdsutil.RequireFlags(cmd,
		"cds-address",
		"cds-pin",
		"tls-san",
		"api-server",
		"ca-certificate",
		"pod-cidr",
		"service-cidr",
		"cluster-dns",
	)
	return cmd
}

// render returns the document's YAML, which Parse accepts.
func (d draft) render() ([]byte, error) {
	pin, err := os.ReadFile(d.cdsPinPath)
	if err != nil {
		return nil, fmt.Errorf("--cds-pin: %w", err)
	}
	ca, err := os.ReadFile(d.caCertificatePath)
	if err != nil {
		return nil, fmt.Errorf("--ca-certificate: %w", err)
	}
	doc := Document{
		SchemaVersion: SchemaVersion,
		CDS:           d.cds,
		TLSSAN:        d.tlsSAN,
		Kubernetes:    d.kubernetes,
	}
	doc.CDS.Measurements = string(pin)
	if !d.router.Empty() {
		doc.Router = &d.router
	}
	doc.Kubernetes.CACertificate = string(ca)
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("render worker document: %w", err)
	}
	if _, err := Parse(data); err != nil {
		return nil, err
	}
	return data, nil
}

// NewFloorCmd returns `worker floor`, run when a worker image is built.
func NewFloorCmd() *cobra.Command {
	var floorTemplatePath, renderDir, staticPodDir, out string
	cmd := &cobra.Command{
		Use:   "floor",
		Short: "Build a worker image's NRI floor",
		Long: `Build a worker image's NRI floor from the image's floor template, its
digests filled in, and the allowlist seed 'c8s node-image render' wrote to
--render-dir. The floor keeps the template's settings and entries, adds the
chart's router entry and an entry pinning each static pod template in
--static-pods, and leaves the mesh's resolver and cluster ranges to worker
stage. It refuses a template key it does not know, a template entry whose
container holds no platform role, and a router entry that leaves its launch
open, takes a mount the control plane fills, or names a file under
/run/c8s-node that worker stage does not publish.`,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			template, err := os.ReadFile(floorTemplatePath)
			if err != nil {
				return err
			}
			seed, err := os.ReadFile(filepath.Join(renderDir, "allowlist-seed.json"))
			if err != nil {
				return err
			}
			staticPods, err := readTemplates(staticPodDir)
			if err != nil {
				return err
			}
			floor, err := Floor(template, seed, staticPods)
			if err != nil {
				return err
			}
			return os.WriteFile(out, floor, 0o644)
		},
	}
	f := cmd.Flags()
	f.StringVar(&floorTemplatePath, "floor-template", "", "the worker image's NRI floor template, its digests filled in")
	f.StringVar(&renderDir, "render-dir", "", "the --output-dir of 'c8s node-image render'")
	f.StringVar(&staticPodDir, "static-pods", "", "the worker image's static pod templates, as stage reads them")
	f.StringVar(&out, "out", "", "file to write the worker's floor to")
	cmdsutil.RequireFlags(cmd, "floor-template", "render-dir", "static-pods", "out")
	return cmd
}

// readTemplates are the files in dir by name, which must all be regular, as
// stage requires.
func readTemplates(dir string) (map[string][]byte, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("--static-pods: %w", err)
	}
	templates := map[string][]byte{}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return nil, fmt.Errorf("--static-pods: %s is not a regular file", entry.Name())
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		templates[entry.Name()] = data
	}
	return templates, nil
}

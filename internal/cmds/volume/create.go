package volume

import (
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/resource"

	pkgallowlist "github.com/confidential-dot-ai/c8s/pkg/allowlist"
)

type createConfig struct {
	name      string
	source    string
	out       string
	path      string
	escrowOut string
	node      string
	size      string
	sizeBytes uint64
	workDir   string
	mutable   bool
	dryRun    bool

	// run executes the build tools. Not a flag: tests set it so the whole
	// create flow is exercised without erofs-utils and cryptsetup installed.
	run Runner
}

func newCreateCmd(o *options) *cobra.Command {
	var cfg createConfig
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Build an encrypted volume and store its key",
		Long: `Build an encrypted image at --out and store its key at --path in the CDS
secret store.

By default the volume is immutable: --source is packaged into an erofs image
with a dm-verity tree inside the encryption, and every read is checked against
the root hash in the key blob.

With --mutable the volume is a writable ext4 of --size bytes, preloaded from
--source when one is given. A mutable volume has no integrity protection: the
host can flip bits or roll it back, and c8s cannot detect that.

The image is written as ciphertext and can travel by any means, including
through the untrusted host. Attach it to the node as a raw block device whose
disk serial is c8s-vol-<name>. On QEMU/KVM, cold-plug virtio-blk at VM launch
or hot-attach scsi-hd on a virtio-scsi controller provisioned at launch.
'c8s volume attach' requires a Linux node with LIO support and is unsupported
on the c8s node image. See docs/volumes.md for attachment recipes.

The key is generated here and exists in exactly two places: the CDS process, and
the escrow file. A CDS restart empties the store, and without the escrow file
the volume is unopenable — keep it somewhere durable and access-controlled.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(cmd, o, cfg)
		},
	}
	f := cmd.Flags()
	f.StringVar(&cfg.name, "name", "", "volume name; forms the device serial c8s-vol-<name> (required, max 12 chars)")
	f.StringVar(&cfg.source, "source", "", "directory whose contents become the volume (required for immutable, optional preload for mutable)")
	f.StringVar(&cfg.out, "out", "", "where to write the encrypted image; must not exist (required)")
	f.StringVar(&cfg.path, "path", "", "secret-store path for the key, e.g. /tenant-a/volumes/weights (required)")
	f.StringVar(&cfg.escrowOut, "escrow-out", "", "where to write the key blob you must keep (required)")
	f.StringVar(&cfg.node, "node", "", "node holding the device; emitted as a nodeSelector on the printed annotations")
	f.BoolVar(&cfg.mutable, "mutable", false, "build a writable ext4 volume instead of an immutable, verified one")
	f.StringVar(&cfg.size, "size", "", "mutable filesystem size, e.g. 50Gi (default: inferred from --source; required without one)")
	f.StringVar(&cfg.workDir, "work-dir", "", "directory for build intermediates (default: a temp dir); they are removed either way")
	f.BoolVar(&cfg.dryRun, "dry-run", false, "build the image and write escrow, but do not call CDS")
	return cmd
}

func runCreate(cmd *cobra.Command, o *options, cfg createConfig) error {
	path, err := validateCreate(&cfg)
	if err != nil {
		return err
	}
	if !cfg.dryRun {
		if err := o.Validate(); err != nil {
			return err
		}
	}

	key, err := GenerateKey()
	if err != nil {
		return err
	}
	var blob Blob
	var size uint64
	var verity Verity
	if cfg.mutable {
		size, err = BuildMutable(cmd.Context(), MutableBuildConfig{
			Source: cfg.source, Out: cfg.out, Key: key, Size: cfg.sizeBytes, WorkDir: cfg.workDir, Run: cfg.run,
		})
		if err != nil {
			return err
		}
		blob, err = NewMutableBlob(key)
	} else {
		verity, err = Build(cmd.Context(), BuildConfig{
			Source: cfg.source, Out: cfg.out, Key: key, WorkDir: cfg.workDir, Run: cfg.run,
		})
		if err != nil {
			return err
		}
		blob, err = NewBlob(key, verity)
	}
	if err != nil {
		return err
	}

	// Escrow before CDS. The image already exists at this point, so a key that
	// reached neither the operator's disk nor the store would leave ciphertext
	// nothing can ever open.
	if err := writeEscrow(cfg.escrowOut, blob); err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	if cfg.dryRun {
		fmt.Fprintf(out, "built %s (%s); key escrowed to %s; CDS not called\n",
			cfg.out, buildSummary(cfg.mutable, size, verity), cfg.escrowOut)
		return nil
	}

	signer, err := o.Signer()
	if err != nil {
		return err
	}
	hc, err := o.HTTPClient(cmd.Context())
	if err != nil {
		return err
	}
	if err := putBlob(cmd.Context(), hc, strings.TrimRight(o.URL, "/"), path, blob, signer); err != nil {
		return err
	}

	printResult(out, cfg, path, size, verity)
	return nil
}

func validateCreate(cfg *createConfig) (string, error) {
	switch {
	case cfg.name == "":
		return "", fmt.Errorf("--name is required")
	case cfg.out == "":
		return "", fmt.Errorf("--out is required")
	case cfg.escrowOut == "":
		return "", fmt.Errorf("--escrow-out is required: it is the only copy of the key outside CDS")
	}
	if !cfg.mutable {
		if cfg.source == "" {
			return "", fmt.Errorf("--source is required for an immutable volume")
		}
		if cfg.size != "" {
			return "", fmt.Errorf("--size is only valid with --mutable: an immutable image sizes itself to its contents")
		}
	}
	if cfg.size != "" {
		sizeBytes, err := parseSize(cfg.size)
		if err != nil {
			return "", err
		}
		cfg.sizeBytes = sizeBytes
	}
	if cfg.mutable && cfg.source == "" && cfg.size == "" {
		return "", fmt.Errorf("--size is required for a mutable volume without --source")
	}
	if err := ValidVolumeName(cfg.name); err != nil {
		return "", fmt.Errorf("--name: %w", err)
	}
	path, err := pkgallowlist.CanonicalSecretPath(cfg.path)
	if err != nil {
		return "", fmt.Errorf("--path: %w", err)
	}
	return path, nil
}

// parseSize reads --size as a byte count or a quantity like 50Gi.
func parseSize(s string) (uint64, error) {
	q, err := resource.ParseQuantity(s)
	if err != nil {
		return 0, fmt.Errorf("--size: %v (want a byte count or a quantity like 50Gi)", err)
	}
	v := q.Value()
	if v <= 0 {
		return 0, fmt.Errorf("--size must be positive")
	}
	return uint64(v), nil
}

// writeEscrow saves the blob, O_EXCL and 0600. It is the whole key: an operator
// who loses it and restarts CDS has ciphertext and nothing that opens it.
func writeEscrow(dest string, blob Blob) error {
	raw, err := blob.Marshal()
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("--escrow-out: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(raw); err != nil {
		return fmt.Errorf("write escrow: %w", err)
	}
	return nil
}

// buildSummary is the one-line description of what a build produced: a size
// for mutable, a block count for immutable.
func buildSummary(mutable bool, size uint64, v Verity) string {
	if mutable {
		return fmt.Sprintf("%s, mutable, read-write", resource.NewQuantity(int64(size), resource.BinarySI))
	}
	return fmt.Sprintf("%d data blocks", v.DataBlocks)
}

func printResult(w io.Writer, cfg createConfig, path string, size uint64, v Verity) {
	fmt.Fprintf(w, "+ %s (%s)\n", cfg.out, buildSummary(cfg.mutable, size, v))
	if cfg.mutable {
		fmt.Fprintf(w, "  mutable volumes have no integrity protection: the host can flip bits or roll back undetected\n")
	}
	fmt.Fprintf(w, "+ key stored at %s\n", path)
	fmt.Fprintf(w, "+ key escrowed to %s — keep it; a CDS restart needs it\n\n", cfg.escrowOut)

	fmt.Fprintf(w, "Attach %s to the node as a raw block device with serial %s%s.\n\n", cfg.out, SerialPrefix, cfg.name)

	fmt.Fprintf(w, "Pod annotations:\n")
	fmt.Fprintf(w, "  confidential.ai/cw: <workload-id>\n")
	fmt.Fprintf(w, "  confidential.ai/c8s-volumes: %q\n", cfg.name+"="+path)
	if cfg.node != "" {
		fmt.Fprintf(w, "\nPod nodeSelector (the device is on one node):\n")
		fmt.Fprintf(w, "  kubernetes.io/hostname: %s\n", cfg.node)
	}

	fmt.Fprintf(w, "\nAllowlist grant for the workload entry (read-only, exact path):\n")
	fmt.Fprintf(w, "  \"secrets\": {\"policy\": \"allow\", \"read\": [%q]}\n", path)
	fmt.Fprintf(w, "\nA subtree grant would cover every volume beneath it, so this names one path.\n")

	fmt.Fprintf(w, "\nAllowlist mount policy for every container in the entry:\n")
	fmt.Fprintf(w, "  \"mounts\": {\"policy\": \"any\"}\n")
	fmt.Fprintf(w, "\nThe webhook mounts this volume into every container, and the entry's mount\npolicy has to admit it. docs/volumes.md — \"The mount policy\" — has the exact\nform.\n")
}

func base64Std(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

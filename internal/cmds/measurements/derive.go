package measurements

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/attestation-go/attestation/teetypes"
	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

func newDeriveCmd() *cobra.Command {
	var tee, out string

	cmd := &cobra.Command{
		Use:   "derive <image-dir|manifest.json>...",
		Short: "Derive a measurements config from confidential-os-builder images",
		Long: "Reads the manifest.json of each built image and writes a measurements config\n" +
			"pinning them. An SNP image contributes one entry per vCPU variant; a TDX image\n" +
			"contributes its MRTD with RTMR[1] and RTMR[2].",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := derive(args, tee)
			if err != nil {
				return err
			}
			doc, err := refvalues.Format(set)
			if err != nil {
				return err
			}
			// Round-trip so derive can only emit what every component loads.
			if _, err := refvalues.Parse(doc); err != nil {
				return fmt.Errorf("derived config is not valid: %w", err)
			}
			if out == "" {
				_, err := cmd.OutOrStdout().Write(doc)
				return err
			}
			return os.WriteFile(out, doc, 0o644)
		},
	}
	cmd.Flags().StringVar(&tee, "tee", "", "platform to derive for (sev-snp or tdx); required when an image is built for both")
	cmd.Flags().StringVar(&out, "out", "", "write to this path instead of stdout")
	return cmd
}

func derive(inputs []string, tee string) (refvalues.ReferenceValues, error) {
	var want teetypes.Family
	if tee != "" {
		f, err := teetypes.ParseFamily(tee)
		if err != nil {
			return refvalues.ReferenceValues{}, fmt.Errorf("--tee %w", err)
		}
		want = f
	}
	var set refvalues.ReferenceValues
	for _, in := range inputs {
		path, name, err := resolveManifest(in)
		if err != nil {
			return refvalues.ReferenceValues{}, err
		}
		family, err := manifestFamily(path, want)
		if err != nil {
			return refvalues.ReferenceValues{}, err
		}
		if set.Family == teetypes.FamilyUnknown {
			set.Family = family
		}
		// One file describes one platform: a cluster mixing SNP and TDX
		// images is not supported.
		if family != set.Family {
			return refvalues.ReferenceValues{}, fmt.Errorf("%s is %s but an earlier input is %s; derive one config per platform", path, family, set.Family)
		}
		images, err := refvalues.FromImageManifest(path, name, family)
		if err != nil {
			return refvalues.ReferenceValues{}, err
		}
		fmt.Fprintf(os.Stderr, "%s: %d %s entr%s from %s\n", name, len(images), family, plural(len(images)), path)
		set.Images = append(set.Images, images...)
	}
	return set, nil
}

func plural(n int) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// resolveManifest accepts a build output directory or the manifest itself and
// names the entry after the directory the image was built into.
func resolveManifest(in string) (path, name string, err error) {
	info, err := os.Stat(in)
	if err != nil {
		return "", "", fmt.Errorf("read image: %w", err)
	}
	path = in
	if info.IsDir() {
		path = filepath.Join(in, "manifest.json")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", "", err
	}
	return path, filepath.Base(filepath.Dir(abs)), nil
}

// manifestFamily resolves the one platform to derive from. A manifest built
// for both carries two sets of values, so the caller has to say which the
// cluster runs.
func manifestFamily(path string, want teetypes.Family) (teetypes.Family, error) {
	families, err := runtimemeasure.ManifestFamilies(path)
	if err != nil {
		return teetypes.FamilyUnknown, err
	}
	if len(families) == 1 {
		if want != teetypes.FamilyUnknown && want != families[0] {
			return teetypes.FamilyUnknown, fmt.Errorf("--tee asks for %s, but image manifest %s is built for %s", want, path, families[0])
		}
		return families[0], nil
	}
	if want == teetypes.FamilyUnknown {
		return teetypes.FamilyUnknown, fmt.Errorf("image manifest %s is built for both platforms; pass --tee %s or --tee %s",
			path, teetypes.FamilySNP, teetypes.FamilyTDX)
	}
	return want, nil
}

package podlaunch

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/c8s/pkg/certutil"
)

func podBundleOptions(t *testing.T) PodBundleOptions {
	t.Helper()
	return PodBundleOptions{
		Dir:                filepath.Join(t.TempDir(), "bundle"),
		ClusterID:          "cluster-one",
		ManifestPath:       writeManifest(t, "tdx"),
		NodeName:           "p-1",
		CDSAddress:         "cds.example.org:8443",
		CDSImagePolicyPath: writePodCDSPin(t),
	}
}

// Every refusal of NewPodBundle leaves no bundle directory behind, except an
// existing one, which it never touches.
func TestNewPodBundleRefuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, o *PodBundleOptions)
		want   string
	}{
		{"no node name", func(_ *testing.T, o *PodBundleOptions) { o.NodeName = "" }, "are required"},
		{"missing CDS policy", func(t *testing.T, o *PodBundleOptions) {
			o.CDSImagePolicyPath = filepath.Join(t.TempDir(), "absent.json")
		}, "--cds-image-policy-file"},
		{"CDS policy is not a pin document", func(t *testing.T, o *PodBundleOptions) {
			o.CDSImagePolicyPath = writeFile(t, "cds.json", "not a policy")
		}, "cds.measurements"},
		{"missing image manifest", func(t *testing.T, o *PodBundleOptions) {
			o.ManifestPath = filepath.Join(t.TempDir(), "absent.json")
		}, "--image-manifest"},
		{"launch key is not a key", func(t *testing.T, o *PodBundleOptions) {
			o.LaunchKeyPath = writeFile(t, "pod.key", "not a key")
		}, "--launch-key"},
		{"node name the document refuses", func(_ *testing.T, o *PodBundleOptions) { o.NodeName = "P_1" }, "rendered launch document for P_1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := podBundleOptions(t)
			tc.change(t, &opts)
			if err := NewPodBundle(opts); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			requireAbsent(t, opts.Dir)
		})
	}

	opts := podBundleOptions(t)
	if err := os.Mkdir(opts.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := NewPodBundle(opts); err == nil || !strings.Contains(err.Error(), "create bundle directory") {
		t.Fatalf("got %v, want an existing directory refused", err)
	}
	requirePresent(t, opts.Dir)
}

// An existing launch key signs the document and is not copied into the bundle.
func TestNewPodBundleWithExistingLaunchKey(t *testing.T) {
	key, pub := testKey(t)
	keyPEM, err := certutil.MarshalECKeyPEM(key)
	if err != nil {
		t.Fatal(err)
	}
	opts := podBundleOptions(t)
	opts.LaunchKeyPath = writeFile(t, "existing.key", string(keyPEM))
	if err := NewPodBundle(opts); err != nil {
		t.Fatal(err)
	}
	requireAbsent(t, filepath.Join(opts.Dir, podKeyFile))
	doc, _ := readBundleDocument(t, opts.Dir, podDir)
	if doc.PodOperatorPublicKey != pub {
		t.Fatalf("document key = %q, want the existing launch key", doc.PodOperatorPublicKey)
	}
	stageBundleNode(t, opts.Dir, podDir)
}

func writeSNPManifest(t *testing.T, smps ...int) string {
	t.Helper()
	variants := make([]string, 0, len(smps))
	for i, smp := range smps {
		variants = append(variants, `{"smp":`+strconv.Itoa(smp)+`,"measurement":{"snp_launch_digest":"`+
			strings.Repeat(strconv.Itoa(4+i)+strconv.Itoa(4+i), 48)+`","algorithm":"sha384"}}`)
	}
	return writeFile(t, "manifest.json", `{"snp_variants":[`+strings.Join(variants, ",")+`]}`)
}

func TestImageFromManifest(t *testing.T) {
	tdx := writeManifest(t, "tdx")
	snp := writeManifest(t, "snp")
	for _, tc := range []struct {
		name    string
		path    string
		vcpus   int
		want    Image
		wantErr string
	}{
		{name: "tdx", path: tdx, want: Image{Platform: "tdx", Measurement: strings.Repeat("11", 48), RTMRs: map[int]string{1: strings.Repeat("22", 48), 2: strings.Repeat("33", 48)}}},
		{name: "tdx with vcpus", path: tdx, vcpus: 4, wantErr: "--vcpus applies to SNP manifests only"},
		{name: "snp smp4", path: snp, vcpus: 4, want: Image{Platform: "snp", Measurement: strings.Repeat("44", 48)}},
		{name: "snp smp8", path: snp, vcpus: 8, want: Image{Platform: "snp", Measurement: strings.Repeat("55", 48)}},
		{name: "snp without vcpus", path: snp, wantErr: "--vcpus is required"},
		{name: "snp without that vcpu count", path: snp, vcpus: 16, wantErr: "--vcpus 16"},
		{name: "single-variant snp without vcpus", path: writeSNPManifest(t, 2), want: Image{Platform: "snp", Measurement: strings.Repeat("44", 48)}},
		{name: "missing manifest", path: filepath.Join(t.TempDir(), "absent.json"), wantErr: "--image-manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ImageFromManifest(tc.path, tc.vcpus)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("got %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("image = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestWriteNewRefusesExistingFile(t *testing.T) {
	path := writeFile(t, "pod.key", "kept")
	if err := writeNew(path, []byte("replaced"), 0o600); err == nil {
		t.Fatal("writeNew replaced an existing file")
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "kept" {
		t.Fatalf("existing file = %q, %v", got, err)
	}
}

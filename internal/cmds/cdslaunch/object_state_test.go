package cdslaunch

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/confidential-dot-ai/attestation-go/refvalues"
	"github.com/confidential-dot-ai/c8s/internal/cdsconfig"
)

func objectStateSettings(t *testing.T) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf(
		`bucket: cds-object-state-test
key: clusters/acme/current
region: us-east-2
expectedBucketOwner: "123456789012"
recoveryAuthority: %s
maxBytes: 2097152
workers: 3
queueCapacity: 8
`,
		base64.StdEncoding.EncodeToString(public),
	)
}

func TestNewBindsObjectStateSettingsToTheLaunchPin(t *testing.T) {
	out := filepath.Join(
		t.TempDir(),
		"cds",
	)
	settings := objectStateSettings(t)
	args := append(
		inputs(
			t,
			out,
		),
		"--object-state-file",
		writeInput(
			t,
			"object-state.yaml",
			settings,
		),
	)
	if err := run(
		t,
		args...,
	); err != nil {
		t.Fatal(err)
	}
	cfg := parseWritten(
		t,
		out,
	)
	want, err := cdsconfig.ParseObjectState([]byte(settings))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HA != nil || cfg.ObjectState == nil || cfg.ObjectState.StorageDigest() != want.StorageDigest() ||
		!bytes.Equal(
			cfg.ObjectState.RecoveryAuthority,
			want.RecoveryAuthority,
		) {
		t.Fatal("the generated config changed storage or recovery authority")
	}
	if cfg.ObjectState.MaxBytes != 2<<20 || cfg.ObjectState.Workers != 3 || cfg.ObjectState.QueueCapacity != 8 {
		t.Fatal("the generated config changed admission bounds")
	}
	configuration, err := os.ReadFile(filepath.Join(
		out,
		cdsconfig.ConfigFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	pinBytes, err := os.ReadFile(filepath.Join(
		out,
		cdsconfig.PinFile,
	))
	if err != nil {
		t.Fatal(err)
	}
	pin, err := refvalues.Parse(pinBytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(pin.Images) != 1 || !bytes.Equal(
		pin.Images[0].LaunchFile,
		configuration,
	) {
		t.Fatal("the CDS pin did not bind the object-state configuration")
	}
}

func TestNewRefusesInvalidObjectStateFilesWithoutOutputs(t *testing.T) {
	valid := objectStateSettings(t)
	for name, settings := range map[string]string{
		"empty":      "",
		"null":       "null",
		"credential": valid + "stateEncryptionKey: forbidden-plaintext\n",
		"wrapped":    "objectState:\n    bucket: cds-state\n",
		"oversized": valid + "#" + strings.Repeat(
			"x",
			16<<10,
		),
	} {
		t.Run(
			name,
			func(t *testing.T) {
				out := filepath.Join(
					t.TempDir(),
					"cds",
				)
				args := append(
					inputs(
						t,
						out,
					),
					"--object-state-file",
					writeInput(
						t,
						"object-state.yaml",
						settings,
					),
				)
				err := run(
					t,
					args...,
				)
				if err == nil || !strings.Contains(
					err.Error(),
					"--object-state-file",
				) {
					t.Fatal("invalid object-state input was not refused at its flag")
				}
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Fatal("a refused object-state input wrote outputs")
				}
			},
		)
	}
}

func TestNewObjectStateRefusesMixedModesAndMissingNodePins(t *testing.T) {
	for _, name := range []string{
		"peer mode",
		"missing node pins",
		"empty flag",
		"missing file",
	} {
		t.Run(
			name,
			func(t *testing.T) {
				out := filepath.Join(
					t.TempDir(),
					"cds",
				)
				args := inputs(
					t,
					out,
				)
				path := writeInput(
					t,
					"object-state.yaml",
					objectStateSettings(t),
				)
				switch name {
				case "peer mode":
					args = append(
						args,
						"--replica",
						"cds-1.acme.example",
						"--voters",
						"3",
					)
				case "missing node pins":
					args = withoutNodePins(args)
				case "empty flag":
					path = ""
				case "missing file":
					path += ".absent"
				}
				args = append(
					args,
					"--object-state-file",
					path,
				)
				if err := run(
					t,
					args...,
				); err == nil {
					t.Fatal("an unsafe object-state launch was accepted")
				}
				if _, err := os.Stat(out); !os.IsNotExist(err) {
					t.Fatal("a refused launch wrote outputs")
				}
			},
		)
	}
}

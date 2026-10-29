package keys

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/pkg/certutil"
	"github.com/confidential-dot-ai/c8s/pkg/operatorauth"
)

// signLaunchSuffix is appended to the values file path to name its
// signature file. `c8s launch-config stage` (internal/cmds/launchconfig)
// looks for exactly this name next to the document on the opkeydata disk.
const signLaunchSuffix = ".sig"

// newSignLaunchCmd returns the `c8s keys sign-launch` subcommand.
func newSignLaunchCmd() *cobra.Command {
	var keyPath string
	var force bool
	cmd := &cobra.Command{
		Use:   "sign-launch <launch.yaml>",
		Short: "Sign a launch configuration with the operator private key",
		Long: `Sign a launch configuration for opkeydata, writing the detached
signature to <launch.yaml>.sig next to it. The document must parse as a
launch configuration. See docs/operator.md,
"Authenticated launch configuration", for the schema and how
'c8s launch-config stage' verifies it on the guest.`,
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if keyPath == "" {
				return fmt.Errorf("--key is required: the operator private key PEM")
			}
			return runSignLaunch(cmd, keyPath, args[0], force)
		},
	}
	cmd.Flags().StringVar(&keyPath, "key", "", "operator private key PEM (c8s keys new --out)")
	cmd.Flags().BoolVar(&force, "force", false, "replace an existing signature (after editing the document)")
	return cmd
}

// readLaunchDocument returns the bytes of a file that a node would accept as
// its launch configuration.
func readLaunchDocument(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if _, err := launchconfig.Parse(data); err != nil {
		return nil, fmt.Errorf("not a launch configuration: %w", err)
	}
	return data, nil
}

func runSignLaunch(cmd *cobra.Command, keyPath, launchPath string, force bool) error {
	key, err := certutil.LoadECPrivateKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("load operator key: %w", err)
	}
	data, err := readLaunchDocument(launchPath)
	if err != nil {
		return err
	}
	line, err := operatorauth.SignDetached(key, data)
	if err != nil {
		return err
	}
	sigPath := launchPath + signLaunchSuffix
	if force {
		if err := os.WriteFile(sigPath, []byte(line+"\n"), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", sigPath, err)
		}
	} else if err := writeNew(sigPath, []byte(line+"\n"), 0o644); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%w (pass --force to replace the signature of an edited document)", err)
		}
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", sigPath)
	return nil
}

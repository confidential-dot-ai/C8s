// The _linux suffix is deliberate, not incidental: nothing here needs Linux
// to compile, but these commands write to fixed root-owned host paths
// (/run/c8s-node, /etc/nri/conf.d, /var/run/nri-image-policy) and are run
// only by the node image's units after signed-launch staging: rke2-role.sh
// calls `prepare`, nri-node-ip.service calls `node-ip` and c8s-join.service
// calls `join`. Keeping
// them out of the operator's macOS and Windows builds means the CLI cannot
// offer a host-mutating subcommand where no staged launch document can exist.
package main

import (
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/join"
	"github.com/confidential-dot-ai/c8s/internal/cmds/launchconfig"
	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
)

func init() {
	staged := func() (*launchconfig.Document, error) {
		return launchconfig.LoadStaged(launchconfig.DefaultStagedPath)
	}
	cmd := &cobra.Command{Use: "node-services", Short: "Prepare the image's authenticated bootstrap inputs"}
	cmd.AddCommand(&cobra.Command{Use: "prepare", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := staged()
		if err != nil {
			return err
		}
		return nodeservices.Prepare("", doc)
	}})
	cmd.AddCommand(&cobra.Command{Use: "node-ip", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := staged()
		if err != nil {
			return err
		}
		return nodeservices.PublishNodeIP("", doc)
	}})
	// join enrolls an agent in-process with the designated server address from
	// the authenticated document; a document that fails LoadStaged enrolls
	// nothing.
	cmd.AddCommand(&cobra.Command{Use: "join", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := staged()
		if err != nil {
			return err
		}
		cfg, err := nodeservices.JoinConfig(doc)
		if err != nil {
			return err
		}
		return join.RunJoin(cmd.Context(), cfg)
	}})
	rootCmd.AddCommand(cmd)
}

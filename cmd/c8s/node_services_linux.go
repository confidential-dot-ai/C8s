// Linux only: this command writes fixed root-owned guest paths (/run/c8s-node,
// /run/c8s-pod) and runs only from the pod image's units after
// `launch-config stage`, so the operator's macOS and Windows builds do not
// offer it.
package main

import (
	"github.com/spf13/cobra"

	"github.com/confidential-dot-ai/c8s/internal/cmds/nodeservices"
	"github.com/confidential-dot-ai/c8s/internal/podlaunch"
)

func init() {
	cmd := &cobra.Command{Use: "node-services", Short: "Prepare a pod CVM's authenticated bootstrap inputs"}
	cmd.AddCommand(&cobra.Command{Use: "prepare", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		doc, err := podlaunch.LoadStaged(podlaunch.DefaultStagedPath)
		if err != nil {
			return err
		}
		return nodeservices.PreparePod("", doc)
	}})
	rootCmd.AddCommand(cmd)
}

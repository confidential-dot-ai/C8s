//go:build linux

package main

import "github.com/confidential-dot-ai/c8s/internal/cmds/armtlsmesh"

func init() {
	rootCmd.AddCommand(wrapFlagBinary(
		"armtls-mesh [flags] | armtls-mesh iptables-sync | armtls-mesh iptables-cleanup",
		"Run the ARmTLS L4 mesh proxy or its iptables side commands",
		armtlsmesh.Run,
	))
}

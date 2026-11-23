package main

import "github.com/confidential-dot-ai/confidential-kubernetes/internal/cmds/verify"

func init() {
	rootCmd.AddCommand(verify.NewCmd(verify.Defaults{
		Use:   "verify [target]",
		Short: "Verify a c8s component's TEE attestation",
		Kind:  "auto",
		Mode:  "auto",
	}))
}

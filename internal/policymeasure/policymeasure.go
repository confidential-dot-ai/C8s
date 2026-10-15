// Package policymeasure names the journal of the allowlist policies a TDX
// node extends into RTMR[3], so the node's measured consumers can send the
// list with their evidence and verifiers can replay it.
package policymeasure

// JournalName is the journal file in the NRI plugin's runtime directory, a
// tmpfs that lives exactly as long as the register.
const JournalName = "measured-policies"

// Where readers beside the measurer find the journal. They assume the default
// runtime directory (nriImagePolicy.hostPaths.runtimeDir).
const (
	// NodeJournal is the path on the node, and in pods that mount the runtime
	// directory at its host path.
	NodeJournal = "/var/run/nri-image-policy/" + JournalName
	// SidecarJournal is the path in sidecars the NRI plugin mounts the runtime
	// directory into (workloadclaims.SidecarSocketDir).
	SidecarJournal = "/run/c8s/workload-claims/" + JournalName
)

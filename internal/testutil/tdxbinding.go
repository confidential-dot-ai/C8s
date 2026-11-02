package testutil

import (
	"crypto/sha512"

	"github.com/confidential-dot-ai/attestation-go/runtimemeasure"
)

// TDXLaunchBinding is the MRCONFIGID a TDX launcher sets for file.
func TDXLaunchBinding(file []byte) []byte {
	d := sha512.Sum384(file)
	return d[:]
}

// RTMR3ExtendedWithFileDigest is zero extended once with SHA-384(file), what
// RTMR[3] holds after an initrd measures file into it.
func RTMR3ExtendedWithFileDigest(file []byte) []byte {
	reg := runtimemeasure.Extend(runtimemeasure.Zero, sha512.Sum384(file))
	return reg[:]
}

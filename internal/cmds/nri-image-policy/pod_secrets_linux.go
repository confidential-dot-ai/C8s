//go:build linux

package nriimagepolicy

import "os"

// openVerifiedPodSecretRoot opens the pod's secret emptyDir beneath the
// kubelet root, requires it RAM-backed and makes it root-owned and read-only
// for the containers that mount it.
func openVerifiedPodSecretRoot(source string) (*os.Root, error) {
	root, err := openPodCredentialDirectory(kubeletRoot, source)
	if err != nil {
		return nil, err
	}
	if err := root.Chown(".", 0, 0); err != nil {
		root.Close()
		return nil, err
	}
	if err := root.Chmod(".", 0o755); err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

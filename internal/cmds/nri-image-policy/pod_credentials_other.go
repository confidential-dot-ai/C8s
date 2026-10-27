//go:build !linux

package nriimagepolicy

import (
	"errors"
	"os"
)

func openPodCredentialRoot(string) (*os.Root, error) {
	return nil, errors.New("pod credential publication requires Linux")
}
func samePodCredentialRoot(*os.Root, string) error {
	return errors.New("pod credential publication requires Linux")
}

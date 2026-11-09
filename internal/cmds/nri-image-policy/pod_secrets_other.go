//go:build !linux

package nriimagepolicy

import (
	"errors"
	"os"
)

func openVerifiedPodSecretRoot(string) (*os.Root, error) {
	return nil, errors.New("pod secret publication requires Linux")
}

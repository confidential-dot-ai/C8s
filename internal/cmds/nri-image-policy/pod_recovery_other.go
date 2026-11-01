//go:build !linux

package nriimagepolicy

import (
	"errors"
	"os"
)

var podProcessBirth = func(uint32) (uint64, error) { return 0, errors.New("pod recovery requires Linux process identity") }
var podProcessIdentity = func(uint32, string) (uint64, error) {
	return 0, errors.New("pod recovery requires Linux process identity")
}

func podRootIdentity(*os.Root) (fileID, error) {
	return fileID{}, errors.New("pod recovery requires Linux credential custody")
}
func openRetainedPodCredentialRoot(string, fileID) (*os.Root, error) {
	return nil, errors.New("pod recovery requires Linux credential custody")
}

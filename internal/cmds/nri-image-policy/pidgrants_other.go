//go:build !linux

package nriimagepolicy

import "errors"

var errNoPIDNamespace = errors.New("shared PID namespaces require Linux")

func InitializePIDNamespaceProof() error                  { return errNoPIDNamespace }
func PIDNamespaceIdentity(string) (uint64, uint64, error) { return 0, 0, errNoPIDNamespace }
func ProvePIDNamespace(
	string,
	uint32,
) (uint64, uint64, error) {
	return 0, 0, errNoPIDNamespace
}
func EnsurePIDNamespace(
	string,
	string,
	uint32,
) (string, uint64, uint64, error) {
	return "", 0, 0, errNoPIDNamespace
}
func RemovePIDNamespace(
	string,
	string,
) error {
	return errNoPIDNamespace
}

package getcert

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// GuestIssuerBinding reads the public CA binding retained after withdrawal.
// The caller serializes it with credential publication and owns the verified
// guest volume. An empty result means no issuer record exists; malformed or
// unprotected records are errors. No credential private key is read.
func GuestIssuerBinding(root *os.Root) (string, error) {
	if root == nil {
		return "", errors.New("guest issuer binding requires a volume root")
	}
	if err := requireGuestRoot(root); err != nil {
		return "", err
	}
	info, err := root.Lstat(issuerRecordName)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() != 65 {
		return "", errors.New("guest issuer binding is not a protected fingerprint record")
	}
	bound, err := loadIssuerRecord(credentialVolume{root: root})
	if err != nil {
		return "", err
	}
	raw, err := hex.DecodeString(string(bound))
	if err != nil || hex.EncodeToString(raw) != string(bound) {
		return "", fmt.Errorf("guest issuer binding is not a canonical fingerprint")
	}
	return string(bound), nil
}

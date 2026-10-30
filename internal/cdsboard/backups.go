// Sealed backups: the leader appends one object per backup, and no replica
// deletes one, so a cluster of another history cannot take the live
// cluster's backups off the board.

package cdsboard

import (
	"context"
	"crypto/rand"
	"fmt"
	"regexp"
)

const backupsDir = "backups"

// caFingerprint accepts the SHA-256 fingerprint of a mesh CA certificate.
var caFingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// BackupName names one sealed backup: the mesh CA of the cluster whose state
// it holds, and the version and log index of that state.
type BackupName struct {
	CASHA256 string
	Version  uint64
	Index    uint64
}

// AppendBackup writes one sealed backup under a key no other backup takes.
func (c *Client) AppendBackup(ctx context.Context, name BackupName, sealed []byte) error {
	key, err := name.unusedKey(rand.Text())
	if err != nil {
		return err
	}
	return c.Put(ctx, key, sealed)
}

// unusedKey is the object one backup lies in: the history it belongs to, the
// state it holds, and a mark no other backup carries, so a plain Put
// overwrites no backup a store with no create-only write already holds.
func (n BackupName) unusedKey(mark string) (string, error) {
	if !caFingerprint.MatchString(n.CASHA256) {
		return "", fmt.Errorf("a backup names its mesh CA by 64 hexadecimal characters of SHA-256, and %q is none", n.CASHA256)
	}
	return fmt.Sprintf("%s/%s-%d-%d-%s.sealed", backupsDir, n.CASHA256, n.Version, n.Index, mark), nil
}

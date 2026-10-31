// Sealed backups: the leader appends one object per backup, and no replica
// deletes one, so a cluster of another history cannot take the live
// cluster's backups off the board.

package cdsboard

import (
	"cmp"
	"context"
	"crypto/rand"
	"fmt"
	"regexp"
	"slices"
	"strconv"
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

// ListedBackup is one backup the board holds: the key it lies at, and what
// that key says about the state it holds. The key is whoever writes to the
// board's word, so it says which backups to consider and nothing more; the
// backup itself is checked when it opens.
type ListedBackup struct {
	Key  string
	Name BackupName
}

// Backups are the backups the board holds, oldest state first. An object
// under backups/ whose key names no state is passed over.
func (c *Client) Backups(ctx context.Context) ([]ListedBackup, error) {
	objects, err := c.List(ctx, backupsDir)
	if err != nil {
		return nil, err
	}
	listed := make([]ListedBackup, 0, len(objects))
	for _, object := range objects {
		name, named := backupNameOf(object.Key)
		if !named {
			continue
		}
		listed = append(listed, ListedBackup{
			Key:  object.Key,
			Name: name,
		})
	}
	slices.SortStableFunc(listed, byTheStateTheyHold)
	return listed, nil
}

// byTheStateTheyHold orders two backups as their keys say the cluster moved:
// the version it had applied, the log index inside that version, and then the
// mesh CA it served under, so backups of two mesh CAs at one state keep an
// order of their own.
func byTheStateTheyHold(a, b ListedBackup) int {
	return cmp.Or(
		cmp.Compare(a.Name.Version, b.Name.Version),
		cmp.Compare(a.Name.Index, b.Name.Index),
		cmp.Compare(a.Name.CASHA256, b.Name.CASHA256),
	)
}

// markSize is how long the mark unusedKey gives a backup is: the length of
// rand.Text's answer.
const markSize = 26

// backupKey names the parts unusedKey writes: the mesh CA of the cluster
// whose state the backup holds, that state's version and log index, and the
// mark that makes the key one no other backup takes.
var backupKey = regexp.MustCompile(
	fmt.Sprintf(`^%s/([0-9a-f]{64})-([0-9]+)-([0-9]+)-[A-Z2-7]{%d}\.sealed$`, backupsDir, markSize),
)

// backupNameOf is what a board key says about the backup lying under it, and
// nothing for a key no backup lies under. Every key this client lists is one
// under its own cluster's path.
func backupNameOf(key string) (BackupName, bool) {
	parts := backupKey.FindStringSubmatch(key)
	if parts == nil {
		return BackupName{}, false
	}
	version, versionErr := strconv.ParseUint(parts[2], 10, 64)
	index, indexErr := strconv.ParseUint(parts[3], 10, 64)
	if versionErr != nil || indexErr != nil {
		return BackupName{}, false
	}
	return BackupName{
		CASHA256: parts[1],
		Version:  version,
		Index:    index,
	}, true
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

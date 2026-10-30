package cdsboard

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// A backup is one new object under the cluster's own path, and no backup
// replaces another.
func TestAppendBackupWritesOneNewObjectPerBackup(t *testing.T) {
	board := startBoard(t)
	client := testClient(t, board)
	name := BackupName{
		CASHA256: strings.Repeat("ab", 32),
		Version:  4,
		Index:    90,
	}
	sealed := [][]byte{[]byte("one sealed state"), []byte("the state the log reached since")}
	for _, state := range sealed {
		if err := client.AppendBackup(context.Background(), name, state); err != nil {
			t.Fatalf("AppendBackup = %v", err)
		}
	}
	objects, err := client.List(context.Background(), "backups")
	if err != nil {
		t.Fatal(err)
	}
	if len(objects) != len(sealed) {
		t.Fatalf("the board holds %d backups, and the cluster appended %d", len(objects), len(sealed))
	}
	for _, object := range objects {
		stored, held := board.Object("boards/" + testClusterID + "/" + object.Key)
		if !held || !bytes.Equal(stored, sealed[0]) && !bytes.Equal(stored, sealed[1]) {
			t.Fatalf("the object under %q is no state the cluster sealed", object.Key)
		}
	}
}

func TestABackupLiesUnderTheMeshCAVersionAndIndexOfTheStateItHolds(t *testing.T) {
	name := BackupName{
		CASHA256: strings.Repeat("ab", 32),
		Version:  4,
		Index:    90,
	}
	key, err := name.unusedKey("mark")
	if err != nil {
		t.Fatal(err)
	}
	want := "backups/" + name.CASHA256 + "-4-90-mark.sealed"
	if key != want {
		t.Fatalf("the backup lies under %q, want %q", key, want)
	}
	if _, err := (BackupName{CASHA256: "../decrees/genesis"}).unusedKey("mark"); err == nil {
		t.Fatal("a backup named by something that is no mesh CA fingerprint took a key")
	}
}

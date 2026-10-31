package cdsboard

import (
	"bytes"
	"context"
	"crypto/rand"
	"slices"
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

// The board lists the backups of one cluster, oldest state first: the
// operator reads which states they could restore from, and names one. Every
// field comes from the object key, which is whoever can write to the board's
// word, so an object that is no backup of this cluster is passed over.
func TestTheBoardListsTheBackupsOfOneCluster(t *testing.T) {
	board := startBoard(t)
	client := testClient(t, board)
	ca := strings.Repeat("ab", 32)
	for _, name := range []BackupName{
		{CASHA256: ca, Version: 7, Index: 400},
		{CASHA256: ca, Version: 4, Index: 90},
		{CASHA256: ca, Version: 4, Index: 95},
	} {
		if err := client.AppendBackup(context.Background(), name, []byte("one sealed state")); err != nil {
			t.Fatalf("AppendBackup = %v", err)
		}
	}
	board.Put("boards/"+testClusterID+"/backups/not-a-backup.json", []byte("{}"))
	board.Put("boards/other-prod/backups/"+ca+"-9-900-mark.sealed", []byte("another cluster's backup"))

	listed, err := client.Backups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	held := make([][2]uint64, 0, len(listed))
	for _, backup := range listed {
		if backup.Name.CASHA256 != ca {
			t.Fatalf("the board lists %+v", backup)
		}
		if _, named := backupNameOf(backup.Key); !named {
			t.Fatalf("the listed key %q names no backup", backup.Key)
		}
		held = append(held, [2]uint64{backup.Name.Version, backup.Name.Index})
	}
	want := [][2]uint64{{4, 90}, {4, 95}, {7, 400}}
	if !slices.Equal(held, want) {
		t.Fatalf("the board lists %v, want %v oldest state first", held, want)
	}
}

// A key is the board's word about a backup, so only the keys a cluster's
// leader writes name one.
func TestOnlyAKeyABackupLiesUnderNamesAState(t *testing.T) {
	ca := strings.Repeat("ab", 32)
	mark := rand.Text()
	for name, key := range map[string]string{
		"a decree":                    "decrees/5kx7.json",
		"another suffix":              "backups/" + ca + "-4-90-" + mark + ".json",
		"no mark":                     "backups/" + ca + "-4-90.sealed",
		"a shorter mark":              "backups/" + ca + "-4-90-MARK.sealed",
		"no mesh CA":                  "backups/4-90-" + mark + ".sealed",
		"a mesh CA in upper case":     "backups/" + strings.ToUpper(ca) + "-4-90-" + mark + ".sealed",
		"a version that is no number": "backups/" + ca + "-four-90-" + mark + ".sealed",
		"a version past uint64":       "backups/" + ca + "-99999999999999999999-90-" + mark + ".sealed",
		"a path of its own":           "backups/nested/" + ca + "-4-90-" + mark + ".sealed",
	} {
		t.Run(name, func(t *testing.T) {
			if held, named := backupNameOf(key); named {
				t.Fatalf("the key %q names backup %+v", key, held)
			}
		})
	}
	key, err := BackupName{CASHA256: ca, Version: 4, Index: 90}.unusedKey(mark)
	if err != nil {
		t.Fatal(err)
	}
	named, is := backupNameOf(key)
	if !is || named != (BackupName{CASHA256: ca, Version: 4, Index: 90}) {
		t.Fatalf("the key a backup lies under names %+v, %v", named, is)
	}
}

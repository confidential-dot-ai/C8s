package podstatus

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/confidential-dot-ai/c8s/internal/fileutil"
	"github.com/confidential-dot-ai/c8s/internal/podassign"
)

const assignmentDir = "/run/c8s-pod/assignment"
const assignmentRecordName = "accepted.json"

type fileAssignmentStore struct {
	root *os.Root
	lock *os.File
}

// openAssignmentStore holds an exclusive lock for the service lifetime. The
// root is pinned and RAM-backed; process restarts preserve it, power-off does not.
func openAssignmentStore() (*fileAssignmentStore, error) {
	return openAssignmentStoreAt(assignmentDir)
}

func openAssignmentStoreAt(path string) (*fileAssignmentStore, error) {
	if err := os.MkdirAll(path, 0700); err != nil {
		return nil, err
	}
	root, err := openAssignmentRoot(path)
	if err != nil {
		return nil, err
	}
	if err := fileutil.RequireRAMBackedRoot(root); err != nil {
		root.Close()
		return nil, err
	}
	store, err := lockAssignmentStore(root)
	if err != nil {
		root.Close()
		return nil, err
	}
	return store, nil
}

func openAssignmentRoot(path string) (*os.Root, error) {
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
		root.Close()
		return nil, fmt.Errorf("assignment directory is not protected by root ownership: %s", path)
	}
	return root, nil
}

func lockAssignmentStore(root *os.Root) (*fileAssignmentStore, error) {
	lock, err := root.OpenFile("service.lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("assignment service already running: %w", err)
	}
	return &fileAssignmentStore{root: root, lock: lock}, nil
}

func (s *fileAssignmentStore) Close() error { return errors.Join(s.lock.Close(), s.root.Close()) }

func (s *fileAssignmentStore) Load() (*assignmentRecord, error) {
	info, err := s.root.Lstat(assignmentRecordName)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return nil, errors.New("assignment record must be a private regular file")
	}
	f, err := s.root.Open(assignmentRecordName)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, podassign.MaxBody+16385))
	if err != nil {
		return nil, err
	}
	if len(data) > podassign.MaxBody+16384 {
		return nil, errors.New("assignment record exceeds size limit")
	}
	var record assignmentRecord
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return nil, fmt.Errorf("invalid assignment record: %w", err)
	}
	if err := dec.Decode(new(any)); err != io.EOF {
		return nil, errors.New("trailing assignment record data")
	}
	return &record, nil
}

func (s *fileAssignmentStore) Commit(record *assignmentRecord) error {
	// The lifetime lock excludes another service, and the handler lock excludes
	// another request. Never replace an existing accepted record, even if corrupt.
	if _, err := s.root.Lstat(assignmentRecordName); !errors.Is(err, os.ErrNotExist) {
		if err != nil {
			return err
		}
		return errors.New("assignment already recorded")
	}
	data, err := json.Marshal(record)
	if err != nil {
		return err
	}
	// Atomic rename is the within-boot durability boundary on this verified RAM
	// filesystem. WriteAtomicRoot returns success only after that rename.
	return fileutil.WriteAtomicRoot(s.root, assignmentRecordName, data, 0600)
}

package fileutil

import (
	"fmt"
	"os"
	"path/filepath"
)

// NewFile is one member of a file set written together.
type NewFile struct {
	Name string
	Data []byte
	Mode os.FileMode
}

// WriteNewDir creates dir, which must not exist, and writes files into it,
// each of which must not exist either. A failed write removes dir again, so
// no caller leaves half a set behind.
func WriteNewDir(dir string, mode os.FileMode, files []NewFile) error {
	if err := os.Mkdir(dir, mode); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	if err := writeAll(dir, files); err != nil {
		os.RemoveAll(dir)
		return err
	}
	return nil
}

func writeAll(dir string, files []NewFile) error {
	for _, file := range files {
		if err := WriteNew(filepath.Join(dir, file.Name), file.Data, file.Mode); err != nil {
			return err
		}
	}
	return nil
}

// WriteNew writes data to path, which must not exist. A failed write removes
// path again.
func WriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(path)
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

// Package store writes the daemon's files atomically with the permissions
// ARCHITECTURE.md 4.4 and 6.1 require: a temporary file in the same
// directory, fsync, rename. A reader sees the old file or the new one.
package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// WriteFile replaces path with data, mode perm.
func WriteFile(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(perm); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// WriteJSON replaces path with v encoded as JSON.
func WriteJSON(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFile(path, append(data, '\n'), perm)
}

// ReadJSON decodes path into v; a missing file leaves v unchanged.
func ReadJSON(path string, v any) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// EnsureDir creates dir with perm and enforces perm on an existing one, so
// a directory created looser by someone else is tightened. A symlink in its
// place is refused; run as root, the directory is made root's.
func EnsureDir(dir string, perm os.FileMode) error {
	if err := os.MkdirAll(dir, perm); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s 不是目录", dir)
	}
	if os.Geteuid() == 0 {
		if err := os.Lchown(dir, 0, 0); err != nil {
			return err
		}
	}
	return os.Chmod(dir, perm)
}

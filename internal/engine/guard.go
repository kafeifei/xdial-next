package engine

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"
)

// The second line of defense, ARCHITECTURE.md 2.7: whatever slips past the
// classification table still meets a security policy that refuses every
// feature sing-box asks about, and a file manager that only reaches the
// directories XDial names. They back up the table; they do not replace it.

type denyAll struct{}

func (denyAll) CheckFeature(_ context.Context, feature string) error {
	return fmt.Errorf("XDial 不允许 %s", feature)
}

// errOutside is returned for any path outside the allowed directories.
var errOutside = errors.New("XDial 不允许 sing-box 读写这个路径")

type restrictedFiles struct {
	allowed []string // absolute, symlinks resolved
}

func (m *restrictedFiles) check(name string) (string, error) {
	path, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	// Resolve the longest existing prefix, so a symlink inside an allowed
	// directory cannot lead out of it.
	existing := path
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return "", errOutside
		}
		existing = parent
	}
	resolved, err := filepath.EvalSymlinks(existing)
	if err != nil {
		return "", errOutside
	}
	rest, err := filepath.Rel(existing, path)
	if err != nil {
		return "", errOutside
	}
	full := filepath.Join(resolved, rest)
	for _, dir := range m.allowed {
		if full == dir || strings.HasPrefix(full, dir+string(filepath.Separator)) {
			return full, nil
		}
	}
	return "", errOutside
}

func (m *restrictedFiles) BasePath(name string) string { return name }

func (m *restrictedFiles) TempPath() string {
	if len(m.allowed) > 0 {
		return m.allowed[0]
	}
	return os.TempDir()
}

func (m *restrictedFiles) OpenFile(name string, flag int, perm os.FileMode) (*os.File, error) {
	path, err := m.check(name)
	if err != nil {
		return nil, err
	}
	return os.OpenFile(path, flag, perm)
}

func (m *restrictedFiles) Create(name string) (*os.File, error) {
	return m.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
}

func (m *restrictedFiles) CreateTemp(pattern string) (*os.File, error) {
	if len(m.allowed) == 0 {
		return nil, errOutside
	}
	return os.CreateTemp(m.allowed[0], pattern)
}

func (m *restrictedFiles) Chown(name string) error {
	_, err := m.check(name)
	return err
}

func (m *restrictedFiles) Mkdir(path string, perm os.FileMode) error {
	full, err := m.check(path)
	if err != nil {
		return err
	}
	return os.Mkdir(full, perm)
}

func (m *restrictedFiles) MkdirAll(path string, perm os.FileMode) error {
	full, err := m.check(path)
	if err != nil {
		return err
	}
	return os.MkdirAll(full, perm)
}

func (m *restrictedFiles) Remove(path string) error {
	full, err := m.check(path)
	if err != nil {
		return err
	}
	return os.Remove(full)
}

func (m *restrictedFiles) RemoveAll(path string) error {
	full, err := m.check(path)
	if err != nil {
		return err
	}
	return os.RemoveAll(full)
}

func (m *restrictedFiles) Rename(oldPath, newPath string) error {
	from, err := m.check(oldPath)
	if err != nil {
		return err
	}
	to, err := m.check(newPath)
	if err != nil {
		return err
	}
	return os.Rename(from, to)
}

// guard attaches the policy and the file manager. allowed lists the only
// directories sing-box may touch, such as tailscale state; a check passes
// none, so every file access fails.
func guard(ctx context.Context, allowed ...string) context.Context {
	files := &restrictedFiles{}
	for _, dir := range allowed {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			files.allowed = append(files.allowed, resolved)
		}
	}
	ctx = service.ContextWith[adapter.SecurityPolicy](ctx, denyAll{})
	return service.ContextWith[filemanager.Manager](ctx, files)
}

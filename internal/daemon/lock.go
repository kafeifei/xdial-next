package daemon

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/kafeifei/xdial-next/internal/cli"
)

// connectionLock is the machine-wide lock of 6.1: one identity connected at
// a time. It is a flock on a file in a directory only root can enter, so no
// other user can take or hold it; the engine and the resolver session
// inherit the descriptor, so the lock is held until the daemon, its engine
// and the resolver key are all gone, however each ends.
type connectionLock struct{ file *os.File }

func acquireConnectionLock(dir, path string) (*connectionLock, error) {
	if err := ensureOwnDir(dir); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := ownedOnly(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("%s：%w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, cli.Errorf(cli.CodeEngineBusy, "", "另一个 XDial 身份正连着，或者它的引擎还没退出")
		}
		return nil, err
	}
	return &connectionLock{file: f}, nil
}

// ensureOwnDir creates dir as this process's, mode 0700, or checks that an
// existing one is: a real directory, owned by this process's user, that
// nobody else can enter.
func ensureOwnDir(dir string) error {
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s 不是本用户专属的目录（%v）", dir, info.Mode())
	}
	return nil
}

// ownedOnly checks that f is a regular file of this process's user that
// nobody else can read or write.
func ownedOnly(f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || !ok || st.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("不是本用户专属的普通文件（%v）", info.Mode())
	}
	return nil
}

// release drops this process's hold; children that inherited it keep the
// lock until they exit.
func (l *connectionLock) release() {
	if l != nil {
		l.file.Close()
	}
}

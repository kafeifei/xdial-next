package daemon

import (
	"errors"
	"os"
	"syscall"

	"github.com/kafeifei/xdial-next/internal/cli"
)

// connectionLock is the machine-wide lock of 6.1: one identity connected at
// a time. It is a flock on a file every identity opens; the engine and the
// resolver session inherit the descriptor, so the lock is held until the
// daemon, its engine and the resolver key are all gone, however each ends.
type connectionLock struct{ file *os.File }

func acquireConnectionLock(path string) (*connectionLock, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, err
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

// release drops this process's hold; children that inherited it keep the
// lock until they exit.
func (l *connectionLock) release() {
	if l != nil {
		l.file.Close()
	}
}

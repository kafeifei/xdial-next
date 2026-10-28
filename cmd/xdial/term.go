package main

import (
	"bufio"
	"os"
	"syscall"
	"unsafe"
)

func termios(fd uintptr, request uintptr, t *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, request, uintptr(unsafe.Pointer(t))); errno != 0 {
		return errno
	}
	return nil
}

func isTerminal(f *os.File) bool {
	var t syscall.Termios
	return termios(f.Fd(), ioctlGet, &t) == nil
}

// readHidden reads one line from a terminal with echo turned off, for
// secret values, and restores the terminal afterwards.
func readHidden(f *os.File) ([]byte, error) {
	var saved syscall.Termios
	if err := termios(f.Fd(), ioctlGet, &saved); err != nil {
		return nil, err
	}
	quiet := saved
	quiet.Lflag &^= syscall.ECHO
	if err := termios(f.Fd(), ioctlSet, &quiet); err != nil {
		return nil, err
	}
	defer func() { _ = termios(f.Fd(), ioctlSet, &saved) }()
	line, err := bufio.NewReader(f).ReadBytes('\n')
	if err != nil && len(line) == 0 {
		return nil, err
	}
	return line, nil
}

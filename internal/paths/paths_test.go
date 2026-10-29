package paths

import (
	"path/filepath"
	"testing"
)

func TestPathsAreAbsolute(t *testing.T) {
	l := Layout{ID: Debug}
	for _, p := range []string{l.Data(), l.Bin(), l.Config(), l.Secrets(), l.Plist(), l.Socket(), l.DaemonLog()} {
		if !filepath.IsAbs(p) {
			t.Errorf("%s is not absolute", p)
		}
	}
	if l.Socket() != "/var/run/com.kafeifei.xdial.debug/api.sock" {
		t.Errorf("socket %s", l.Socket())
	}
	if l.Data() != "/Library/Application Support/com.kafeifei.xdial.debug" {
		t.Errorf("data %s", l.Data())
	}
}

func TestConnectionLockIsShared(t *testing.T) {
	release, debug := Layout{ID: Release}, Layout{ID: Debug}
	if release.ConnectionLock() != debug.ConnectionLock() || release.ConnectionLock() != "/var/run/com.kafeifei.xdial.connection.lock" {
		t.Errorf("lock %s / %s", release.ConnectionLock(), debug.ConnectionLock())
	}
}

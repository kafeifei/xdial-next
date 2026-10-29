package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/kafeifei/xdial-next/internal/cli"
)

func TestStageBinaryRefusesACLs(t *testing.T) {
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	dir := t.TempDir()
	src := filepath.Join(dir, "xdial")
	if err := os.WriteFile(src, []byte("binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	if out, err := exec.Command("/bin/chmod", "+a", "everyone allow write", src).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v %s", err, out)
	}
	if _, err := stageBinary(src, bin); !cli.Is(err, cli.CodeInputPermission) {
		t.Errorf("a file with an ACL was installed: %v", err)
	}
	if out, err := exec.Command("/bin/chmod", "-N", src).CombinedOutput(); err != nil {
		t.Fatalf("chmod -N: %v %s", err, out)
	}
	if _, err := stageBinary(src, bin); err != nil {
		t.Errorf("the same file without the ACL was refused: %v", err)
	}
	aclLister = "/nonexistent/ls"
	defer func() { aclLister = "/bin/ls" }()
	if _, err := stageBinary(src, bin); !cli.Is(err, cli.CodeInputPermission) {
		t.Errorf("a source whose ACL could not be checked was installed: %v", err)
	}
}

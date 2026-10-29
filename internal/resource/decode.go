package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/sagernet/sing-box/common/srs"
)

// DecodeCommand is the hidden subcommand that turns a binary rule set into
// source format in a process of its own, ARCHITECTURE.md 3.4: a malformed
// file that slips past the preflight takes down only that process.
const DecodeCommand = "__rule-set-decode"

// MaxBinarySize caps a downloaded binary rule set before decompression.
const MaxBinarySize = 16 << 20

// RunDecodeChild reads one binary rule set from stdin, which the daemon has
// already passed through Preflight, and writes it in source format to
// stdout. It exits non-zero, with the reason on stderr, if it cannot.
func RunDecodeChild(stdin io.Reader, stdout, stderr io.Writer) int {
	if privileged() {
		fmt.Fprintln(stderr, "decode: refusing to run as root")
		return 1
	}
	data, err := io.ReadAll(io.LimitReader(stdin, MaxBinarySize+1))
	if err != nil || len(data) > MaxBinarySize {
		fmt.Fprintln(stderr, "decode: input too large or unreadable")
		return 1
	}
	// Preflight again: the child must not depend on its caller for the
	// bounds that keep it from exhausting memory.
	if err := Preflight(data); err != nil {
		fmt.Fprintln(stderr, "decode:", err)
		return 1
	}
	compat, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		fmt.Fprintln(stderr, "decode:", err)
		return 1
	}
	out, err := json.Marshal(compat)
	if err != nil {
		fmt.Fprintln(stderr, "decode:", err)
		return 1
	}
	if len(out) > config.RuleSetMaxSize {
		fmt.Fprintln(stderr, "decode: source too large")
		return 1
	}
	_, err = stdout.Write(out)
	if err != nil {
		return 1
	}
	return 0
}

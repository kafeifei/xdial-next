// Command xdial is the XDial command line.
//
// In M0 it only reports its own build, which gives CI, review and the VM e2e
// run something real to exercise. The command grammar and the JSON
// conventions are architecture samples settled in M1.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/kafeifei/xdial-next/internal/buildinfo"
)

const usage = "usage: xdial version [--json]"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes one command and returns the process exit code: 0 on success,
// 1 when the command fails, 2 for usage errors.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	switch args[0] {
	case "version":
		return runVersion(args[1:], stdout, stderr)
	default:
		fmt.Fprintf(stderr, "xdial: unknown command %q\n%s\n", args[0], usage)
		return 2
	}
}

type versionInfo struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	GoVersion string `json:"goVersion"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("version", flag.ContinueOnError)
	flags.SetOutput(stderr)
	asJSON := flags.Bool("json", false, "print as JSON")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "xdial version: unexpected argument %q\n", flags.Arg(0))
		return 2
	}

	info := versionInfo{
		Version:   buildinfo.Version,
		Revision:  buildinfo.Revision(),
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	if *asJSON {
		if err := json.NewEncoder(stdout).Encode(info); err != nil {
			fmt.Fprintln(stderr, "xdial version:", err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stdout, "xdial %s (%s, %s, %s/%s)\n", info.Version, info.Revision, info.GoVersion, info.OS, info.Arch)
	return 0
}

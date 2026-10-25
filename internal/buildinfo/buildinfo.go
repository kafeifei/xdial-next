// Package buildinfo reports which binary is running: the release version
// stamped at link time and the VCS revision Go records during the build.
package buildinfo

import "runtime/debug"

// Version is set at link time for releases:
//
//	-ldflags "-X github.com/kafeifei/xdial-next/internal/buildinfo.Version=v0.1.0"
var Version = "dev"

// Revision returns the commit the binary was built from, with a "-dirty"
// suffix for uncommitted changes, or "unknown" when Go recorded none.
func Revision() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	var revision string
	var dirty bool
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			revision = setting.Value
		case "vcs.modified":
			dirty = setting.Value == "true"
		}
	}
	if revision == "" {
		return "unknown"
	}
	if dirty {
		revision += "-dirty"
	}
	return revision
}

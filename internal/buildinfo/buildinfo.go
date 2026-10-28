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

// SingBox returns the sing-box module version linked into this binary.
func SingBox() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, dep := range info.Deps {
		if dep.Path == "github.com/sagernet/sing-box" {
			if dep.Replace != nil {
				return dep.Replace.Version
			}
			return dep.Version
		}
	}
	return "unknown"
}

// Identity is the daemon identity this build installs and talks to,
// ARCHITECTURE.md 6.1. Development builds are Debug; releases set it at
// link time:
//
//	-ldflags "-X github.com/kafeifei/xdial-next/internal/buildinfo.Identity=com.kafeifei.xdial"
var Identity = "com.kafeifei.xdial.debug"

//go:build !(with_gvisor && with_utls && ts_omit_peerapiserver && ts_omit_c2n && ts_omit_debug && ts_omit_portmapper && ts_omit_logtail && ts_omit_netlog && ts_omit_ssh && ts_omit_webclient && ts_omit_drive && ts_omit_taildrop)

package engine

import "testing"

// Compiled only when a required build tag is missing, which would build
// tailscale with peerapi, C2N or its own logs, ARCHITECTURE.md 2.6.
func TestBuiltWithRequiredTags(t *testing.T) {
	t.Fatal("built without the tags in .github/build-tags.txt; run tests through make or set GOFLAGS")
}

package engine

import (
	"os"
	"strings"
	"testing"
)

// requiredTags are the build tags ARCHITECTURE.md 2.3 and 2.6 require.
// .github/build-tags.txt must list exactly these, and missingtags_test.go
// fails the build of the tests when any is absent.
var requiredTags = []string{
	"with_gvisor", "with_utls",
	"ts_omit_peerapiserver", "ts_omit_c2n", "ts_omit_debug", "ts_omit_portmapper",
	"ts_omit_logtail", "ts_omit_netlog", "ts_omit_ssh", "ts_omit_webclient",
	"ts_omit_drive", "ts_omit_taildrop",
}

func TestBuildTagsFile(t *testing.T) {
	data, err := os.ReadFile("../../.github/build-tags.txt")
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(string(data)), ",")
	if strings.Join(got, ",") != strings.Join(requiredTags, ",") {
		t.Errorf(".github/build-tags.txt lists %v, ARCHITECTURE.md requires %v", got, requiredTags)
	}
}

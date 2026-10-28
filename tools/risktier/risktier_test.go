package main

import (
	"os"
	"strings"
	"testing"
)

func TestGlobToRegexp(t *testing.T) {
	cases := []struct {
		glob, path string
		want       bool
	}{
		{"docs/**", "docs/plan.md", true},
		{"docs/**", "docs/agent/loop.md", true},
		{"docs/**", "docsx/plan.md", false},
		{"**/*.md", "README.md", true},
		{"**/*.md", "a/b/c.md", true},
		{"**/*_test.go", "cmd/xdial/main_test.go", true},
		{"**/*_test.go", "cmd/xdial/main.go", false},
		{"go.mod", "go.mod", true},
		{"go.mod", "tools/go.mod", false},
		{"*.go", "a/b.go", false},
		{"a?c", "abc", true},
		{"a?c", "a/c", false},
		{"v1.0", "v1x0", false},
		{"**/CLAUDE.md", "docs/claude.md", true},
	}
	for _, c := range cases {
		pattern, err := globToRegexp(c.glob)
		if err != nil {
			t.Fatalf("globToRegexp(%q): %v", c.glob, err)
		}
		if got := pattern.MatchString(c.path); got != c.want {
			t.Errorf("%q matching %q = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
}

// TestRepositoryRules pins the tiers the real rules give to typical changes,
// so a rule edit that moves them shows up in review.
func TestRepositoryRules(t *testing.T) {
	data, err := os.ReadFile("../../.github/risk-tiers.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRules(data)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		paths string
		want  string
	}{
		{"docs/incidents/README.md", tierLow},
		{"README.md docs/incidents/README.md", tierLow},
		// The default is high: a path nobody listed waits for the owner.
		// e2e scripts run on the host that drives the test VM.
		{"e2e/run.sh", tierHigh},
		{"pkg/daemon/api.go", tierHigh},
		{"main.go", tierHigh},
		{".golangci.yaml", tierHigh},
		// Product code under cmd/ and internal/ carries the CLI surface, the
		// configuration format and the daemon, so even its tests are high.
		{"cmd/xdial/main.go", tierHigh},
		{"cmd/xdial/main_test.go", tierHigh},
		{"internal/config/parse.go", tierHigh},
		{"ARCHITECTURE.md", tierHigh},
		{"", tierHigh},
		{"docs/agent/loop.md", tierHigh},
		{"docs/agent/review-filters.md README.md", tierHigh},
		{".github/workflows/ci.yml", tierHigh},
		{".github/risk-tiers.json", tierHigh},
		{"tools/risktier/risktier_test.go", tierHigh},
		{"AGENTS.md", tierHigh},
		{"go.sum", tierHigh},
		{"scripts/check-deps.sh", tierHigh},
		{"Makefile", tierHigh},
		// A rename lists both paths, so moving a high-risk file under docs/
		// stays high.
		{"docs/AGENTS.md AGENTS.md", tierHigh},
		{"docs/review-filters.md docs/agent/review-filters.md", tierHigh},
		// Agents load instruction files from any directory.
		{"docs/CLAUDE.md", tierHigh},
		{"cmd/xdial/AGENTS.md", tierHigh},
		{".claude/settings.json", tierHigh},
		{".codex/hooks.json", tierHigh},
		{".mcp.json", tierHigh},
		{"go.work", tierHigh},
		{"docs/claude.md", tierHigh},
		{"docs/.claude/rules/x.md", tierHigh},
		{"AGENTS.override.md", tierHigh},
		{"internal/sub/go.mod", tierHigh},
		{".gitattributes", tierHigh},
		{"docs/plan.md", tierHigh},
	}
	for _, c := range cases {
		got, _ := r.classify(strings.Fields(c.paths))
		if got != c.want {
			t.Errorf("classify(%q) = %s, want %s", c.paths, got, c.want)
		}
	}
}

func TestParseRulesRejects(t *testing.T) {
	for _, data := range []string{
		`{"default": "urgent"}`,
		`{"default": "medium", "hgih": ["x"]}`,
		`not json`,
	} {
		if _, err := parseRules([]byte(data)); err == nil {
			t.Errorf("parseRules(%s) succeeded, want an error", data)
		}
	}
}

func TestReadPaths(t *testing.T) {
	paths, err := readPaths(strings.NewReader("a.go\n\n  docs/b.md \n"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(paths, ",") != "a.go,docs/b.md" {
		t.Errorf("readPaths = %q", paths)
	}
}

func TestMediumIsAnAllowList(t *testing.T) {
	r, err := parseRules([]byte(`{"default": "high", "high": ["secret/**"], "medium": ["app/ui/**"], "low": ["docs/**"]}`))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		paths string
		want  string
	}{
		{"app/ui/view.swift", tierMedium},
		{"app/ui/view.swift docs/a.md", tierMedium},
		{"docs/a.md", tierLow},
		{"app/ui/view.swift other.go", tierHigh},
		{"app/ui/view.swift secret/x", tierHigh},
		{"app/model.swift", tierHigh},
	}
	for _, c := range cases {
		if got, _ := r.classify(strings.Fields(c.paths)); got != c.want {
			t.Errorf("classify(%q) = %s, want %s", c.paths, got, c.want)
		}
	}
}

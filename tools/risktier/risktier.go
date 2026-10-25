package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	tierLow    = "low"
	tierMedium = "medium"
	tierHigh   = "high"
)

type rules struct {
	Description string   `json:"description"`
	Default     string   `json:"default"`
	High        []string `json:"high"`
	Low         []string `json:"low"`

	high, low []*regexp.Regexp
}

func parseRules(data []byte) (*rules, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var r rules
	if err := decoder.Decode(&r); err != nil {
		return nil, err
	}
	switch r.Default {
	case tierLow, tierMedium, tierHigh:
	default:
		return nil, fmt.Errorf("default tier %q is not low, medium or high", r.Default)
	}
	var err error
	if r.high, err = compileGlobs(r.High); err != nil {
		return nil, err
	}
	if r.low, err = compileGlobs(r.Low); err != nil {
		return nil, err
	}
	return &r, nil
}

// classify returns the tier of a change set with one reason per path. Any
// path matching a high pattern makes it high; it is low only when every path
// matches a low pattern; anything else, an empty change set included, gets
// the default tier.
func (r *rules) classify(paths []string) (string, []string) {
	reasons := make([]string, 0, len(paths))
	high := false
	allLow := len(paths) > 0
	for _, path := range paths {
		switch {
		case matchAny(r.high, path):
			high = true
			allLow = false
			reasons = append(reasons, "high:  "+path)
		case matchAny(r.low, path):
			reasons = append(reasons, "low:   "+path)
		default:
			allLow = false
			reasons = append(reasons, "other: "+path)
		}
	}
	switch {
	case high:
		return tierHigh, reasons
	case allLow:
		return tierLow, reasons
	default:
		return r.Default, reasons
	}
}

func readPaths(input io.Reader) ([]string, error) {
	var paths []string
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		if path := strings.TrimSpace(scanner.Text()); path != "" {
			paths = append(paths, path)
		}
	}
	return paths, scanner.Err()
}

func matchAny(patterns []*regexp.Regexp, path string) bool {
	for _, pattern := range patterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

func compileGlobs(globs []string) ([]*regexp.Regexp, error) {
	patterns := make([]*regexp.Regexp, 0, len(globs))
	for _, glob := range globs {
		pattern, err := globToRegexp(glob)
		if err != nil {
			return nil, fmt.Errorf("pattern %q: %w", glob, err)
		}
		patterns = append(patterns, pattern)
	}
	return patterns, nil
}

// globToRegexp translates a path glob: "**/" matches any number of leading
// directories, "**" matches anything, "*" and "?" stay within one segment.
// Matching ignores case, because macOS file systems do and tools find
// claude.md as readily as CLAUDE.md there.
func globToRegexp(glob string) (*regexp.Regexp, error) {
	var b strings.Builder
	b.WriteString("(?i)^")
	for i := 0; i < len(glob); {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			b.WriteString("(?:.*/)?")
			i += 3
		case strings.HasPrefix(glob[i:], "**"):
			b.WriteString(".*")
			i += 2
		case glob[i] == '*':
			b.WriteString("[^/]*")
			i++
		case glob[i] == '?':
			b.WriteString("[^/]")
			i++
		default:
			r, size := utf8.DecodeRuneInString(glob[i:])
			b.WriteString(regexp.QuoteMeta(string(r)))
			i += size
		}
	}
	b.WriteString("$")
	return regexp.Compile(b.String())
}

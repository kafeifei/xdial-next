package daemon

import (
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
)

// scrubber replaces secret values in text the engine writes, as they are
// and in the encodings errors commonly carry them in, ARCHITECTURE.md 4.3.
// It is a backstop: an error that carries only part of a value is not
// caught, which is why callers get error codes, not engine text.
type scrubber struct {
	replacer *strings.Replacer
}

// minScrubLength skips values too short to replace without mangling
// unrelated text; such values are not credentials in practice.
const minScrubLength = 4

func newScrubber(secrets map[string]Secret) *scrubber {
	type pair struct{ from, to string }
	var pairs []pair
	for name, s := range secrets {
		if len(s.Value) < minScrubLength {
			continue
		}
		to := "<secret:" + name + ">"
		for _, form := range []string{
			s.Value,
			url.QueryEscape(s.Value),
			url.PathEscape(s.Value),
			base64.StdEncoding.EncodeToString([]byte(s.Value)),
			base64.RawURLEncoding.EncodeToString([]byte(s.Value)),
			strings.Trim(quote(s.Value), `"`),
		} {
			if len(form) >= minScrubLength {
				pairs = append(pairs, pair{form, to})
			}
		}
	}
	// Longer forms first, so a value inside another is not split.
	sort.Slice(pairs, func(i, j int) bool { return len(pairs[i].from) > len(pairs[j].from) })
	var args []string
	for _, p := range pairs {
		args = append(args, p.from, p.to)
	}
	return &scrubber{replacer: strings.NewReplacer(args...)}
}

func (s *scrubber) scrub(text string) string { return s.replacer.Replace(text) }

func quote(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	return `"` + b.String() + `"`
}

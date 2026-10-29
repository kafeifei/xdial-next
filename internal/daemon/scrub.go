package daemon

import (
	"encoding/base64"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// scrubber replaces secret values in text the engine writes, as they are
// and in the encodings errors commonly carry them in, ARCHITECTURE.md 4.3.
// It is a backstop: an error that carries only part of a value is not
// caught, which is why callers get error codes, not engine text.
type scrubber struct {
	replacer *strings.Replacer
	forms    []string // every form of every secret, longest first
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
	forms := make([]string, len(pairs))
	for i, p := range pairs {
		forms[i] = p.from
	}
	return &scrubber{replacer: strings.NewReplacer(args...), forms: forms}
}

func (s *scrubber) scrub(text string) string { return s.replacer.Replace(text) }

// safeCut returns where to cut text to keep at most limit bytes without
// splitting any form of any secret: at limit, or earlier at the start of
// an occurrence that would straddle it, on a character boundary. What is
// kept then holds only whole secrets, which scrubbing replaces whole.
func (s *scrubber) safeCut(text string, limit int) int {
	if len(text) <= limit {
		return len(text)
	}
	cut := limit
	for moved := true; moved; {
		moved = false
		for _, f := range s.forms {
			// An occurrence straddles cut if it starts in [cut-len+1, cut).
			from := max(0, cut-len(f)+1)
			window := text[from:min(len(text), cut+len(f)-1)]
			for i := strings.Index(window, f); i >= 0; {
				start := from + i
				if start < cut && start+len(f) > cut {
					cut, moved = start, true
					break
				}
				next := strings.Index(window[i+1:], f)
				if next < 0 {
					break
				}
				i += 1 + next
			}
		}
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
			moved = true
		}
	}
	return cut
}

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

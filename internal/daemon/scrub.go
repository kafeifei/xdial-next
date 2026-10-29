package daemon

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// scrubber masks secret values in text the engine writes, as they are and
// in the encodings errors commonly carry them in, ARCHITECTURE.md 4.3. It
// is a backstop: an error that carries only part of a value is not caught,
// which is why callers get error codes, not engine text.
//
// It masks every place any form occurs, overlapping occurrences included,
// as one span each: replacing matches one at a time, left to right, would
// leave the end of a secret that overlaps another one showing.
type scrubber struct {
	forms []secretForm
}

type secretForm struct {
	text, name string
	// period is the smallest shift at which text overlaps itself.
	period int
}

// minScrubLength skips values too short to mask without mangling
// unrelated text; such values are not credentials in practice.
const minScrubLength = 4

// MaxSecretLength bounds a secret's value. Its longest form then stays
// far below the 64 KiB the engine cuts a VPN server's text at, so a
// secret that starts in what the daemon keeps of that text always ends
// before the cut and is masked whole, 3.5.
const MaxSecretLength = 8 << 10

func newScrubber(secrets map[string]Secret) *scrubber {
	s := &scrubber{}
	seen := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(secrets)) {
		value := secrets[name].Value
		if len(value) < minScrubLength {
			continue
		}
		for _, form := range forms(value) {
			if len(form) >= minScrubLength && !seen[form] {
				seen[form] = true
				s.forms = append(s.forms, secretForm{form, name, period(form)})
			}
		}
	}
	return s
}

// forms are the ways a value shows in text: as it is, URL and base64
// encoded, and inside quotes as Go, encoding/json, JSON.stringify and
// other writers escape it.
func forms(value string) []string {
	goJSON, _ := json.Marshal(value)
	return []string{
		value,
		url.QueryEscape(value),
		url.PathEscape(value),
		base64.StdEncoding.EncodeToString([]byte(value)),
		base64.RawURLEncoding.EncodeToString([]byte(value)),
		strings.Trim(strconv.Quote(value), `"`),
		strings.Trim(string(goJSON), `"`),
		escape(value, true),
		escape(value, false),
	}
}

// escape escapes quotes and backslashes and, with control, control
// characters as JSON.stringify does; everything else stays as it is.
func escape(value string, control bool) string {
	var b strings.Builder
	for _, r := range value {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case control && r == '\n':
			b.WriteString(`\n`)
		case control && r == '\r':
			b.WriteString(`\r`)
		case control && r == '\t':
			b.WriteString(`\t`)
		case control && r == '\b':
			b.WriteString(`\b`)
		case control && r == '\f':
			b.WriteString(`\f`)
		case control && r < 0x20:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// period is the smallest shift at which text overlaps itself, from its
// prefix function; len(text) when it does not.
func period(text string) int {
	prefix := make([]int, len(text))
	for i := 1; i < len(text); i++ {
		k := prefix[i-1]
		for k > 0 && text[i] != text[k] {
			k = prefix[k-1]
		}
		if text[i] == text[k] {
			k++
		}
		prefix[i] = k
	}
	return len(text) - prefix[len(text)-1]
}

type span struct {
	start, end int
	name       string
}

// spans returns where forms occur in text, overlapping occurrences merged
// into one span, in order. Occurrences one period apart overlap, so a run
// of them is followed a period at a time rather than searched for again.
// What it keeps is, for each position, the furthest end of a run starting
// there: it grows with the text, not with how many occurrences there are.
func (s *scrubber) spans(text string) []span {
	var end, owner []int32
	for i, f := range s.forms {
		m := len(f.text)
		for from := 0; from+m <= len(text); {
			j := strings.Index(text[from:], f.text)
			if j < 0 {
				break
			}
			start := from + j
			stop := start + m
			for stop+f.period <= len(text) && text[stop:stop+f.period] == text[stop-f.period:stop] {
				stop += f.period
			}
			if end == nil {
				end, owner = make([]int32, len(text)), make([]int32, len(text))
			}
			if int32(stop) > end[start] {
				end[start], owner[start] = int32(stop), int32(i)
			}
			from = stop - m + 1
		}
	}
	var merged []span
	for start, e := range end {
		if e == 0 {
			continue
		}
		if n := len(merged); n > 0 && start < merged[n-1].end {
			merged[n-1].end = max(merged[n-1].end, int(e))
			continue
		}
		merged = append(merged, span{start, int(e), s.forms[owner[start]].name})
	}
	return merged
}

// scrub masks every span with the name of the secret it starts with.
func (s *scrubber) scrub(text string) string {
	spans := s.spans(text)
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(text[last:sp.start])
		b.WriteString("<secret:" + sp.name + ">")
		last = sp.end
	}
	b.WriteString(text[last:])
	return b.String()
}

// safeCut returns where to cut text to keep at most limit bytes without
// splitting a span: at limit, or earlier at the start of the span that
// would straddle it, on a character boundary.
func (s *scrubber) safeCut(text string, limit int) int {
	if len(text) <= limit {
		return len(text)
	}
	cut := limit
	for _, sp := range s.spans(text) {
		if sp.start < cut && sp.end > cut {
			cut = sp.start
			break
		}
	}
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return cut
}

package daemon

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"sort"
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
	for name, secret := range secrets {
		if len(secret.Value) < minScrubLength {
			continue
		}
		jsonForm, _ := json.Marshal(secret.Value)
		seen := map[string]bool{}
		for _, form := range []string{
			secret.Value,
			url.QueryEscape(secret.Value),
			url.PathEscape(secret.Value),
			base64.StdEncoding.EncodeToString([]byte(secret.Value)),
			base64.RawURLEncoding.EncodeToString([]byte(secret.Value)),
			strings.Trim(string(jsonForm), `"`),
			strings.Trim(strconv.Quote(secret.Value), `"`),
		} {
			if len(form) >= minScrubLength && !seen[form] {
				seen[form] = true
				s.forms = append(s.forms, secretForm{form, name})
			}
		}
	}
	return s
}

type span struct {
	start, end int
	name       string
}

// spans returns where forms occur in text, overlapping occurrences merged
// into one span, in order.
func (s *scrubber) spans(text string) []span {
	var all []span
	for _, f := range s.forms {
		for i := 0; i <= len(text)-len(f.text); {
			j := strings.Index(text[i:], f.text)
			if j < 0 {
				break
			}
			start := i + j
			all = append(all, span{start, start + len(f.text), f.name})
			i = start + 1
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].start < all[j].start })
	var merged []span
	for _, sp := range all {
		if n := len(merged); n > 0 && sp.start < merged[n-1].end {
			merged[n-1].end = max(merged[n-1].end, sp.end)
			continue
		}
		merged = append(merged, sp)
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

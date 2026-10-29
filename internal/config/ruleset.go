package config

import (
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/kafeifei/xdial-next/internal/cli"
)

// Limits on a downloaded rule set in source format, ARCHITECTURE.md 3.4.
// Real lists run long, geosite-cn has some 110,000 suffixes in one rule,
// so lists may hold more than in a configuration written by hand; the size
// and the count of values bound what parsing costs the root daemon.
const (
	RuleSetMaxSize    = 16 << 20
	maxRuleSetValues  = 600_000
	maxRuleSetList    = 300_000
	MaxRuleSetVersion = 5 // sing-box's RuleSetVersionCurrent, checked by a test
)

// CheckRuleSetSource parses a rule set in sing-box's source format,
// {"version": N, "rules": [...]}, and checks its rules against the same
// classification as an inline rule set, with longer lists. It returns the
// rules, or every problem found. Nothing from the document is echoed in a
// problem beyond its path: the content is remote input.
func CheckRuleSetSource(data []byte) ([]*Value, []cli.Problem) {
	root, err := parseWithin(data, RuleSetMaxSize, maxRuleSetValues)
	if err != nil {
		return nil, []cli.Problem{{Code: cli.CodeConfigSyntax, Message: err.Error()}}
	}
	w := &walker{}
	if root.Kind != KindObject {
		return nil, []cli.Problem{{Code: cli.CodeConfigValue, Message: "规则集应该是一个 JSON 对象"}}
	}
	spec := map[string]*Spec{
		"version": req(intRange(1, MaxRuleSetVersion)),
		"rules":   req(&Spec{shape: shapeArray, elem: headlessRuleSpecWithin(0, maxRuleSetList), maxItems: maxRulesPerSet}),
	}
	for _, f := range root.Fields {
		s, ok := spec[f.Key]
		if !ok {
			w.problem(cli.CodeConfigUnknownKey, f.Key, "", "没有登记的键 %q", f.Key)
			continue
		}
		w.field(f.Value, s, f.Key, root)
	}
	for _, key := range sortedKeys(spec) {
		if root.Get(key) == nil {
			w.problem(cli.CodeConfigValue, key, "", "缺少必填的 %s", key)
		}
	}
	// sing-box refuses an inline rule set without rules; one that matched
	// nothing would also be a remote's way of switching rules off unseen.
	if rules := root.Get("rules"); rules != nil && rules.Kind == KindArray && len(rules.Items) == 0 {
		w.problem(cli.CodeConfigValue, "rules", "", "规则集是空的")
	}
	if w.dropped > 0 {
		w.problems = append(w.problems, cli.Problem{Code: cli.CodeConfigMore, Message: fmt.Sprintf("还有 %d 处问题没有列出", w.dropped)})
	}
	if w.failed() {
		for i, p := range w.problems {
			path := p.Path
			// The last segment of an unknown key's path is the key itself,
			// whatever it looks like, even "domain[123]".
			if p.Code == cli.CodeConfigUnknownKey {
				if i := strings.LastIndex(path, "."); i >= 0 {
					path = path[:i] + ".<未登记的键>"
				} else {
					path = "<未登记的键>"
				}
			}
			w.problems[i].Path = trustedPath(path)
		}
		return nil, w.problems
	}
	return root.Get("rules").Items, nil
}

// trustedPath keeps of a problem's path only what XDial itself names:
// indexes and the keys the classification knows. A key the remote made up
// is cut off, so the path never carries remote text.
func trustedPath(path string) string {
	var kept []string
	for _, seg := range strings.Split(path, ".") {
		if seg == "<未登记的键>" {
			kept = append(kept, seg)
			break
		}
		m := pathSegment.FindStringSubmatch(seg)
		if m == nil || !ruleSetKeys()[m[1]] {
			kept = append(kept, "<未登记的键>")
			break
		}
		kept = append(kept, seg)
	}
	return strings.Join(kept, ".")
}

var pathSegment = regexp.MustCompile(`^([a-z_]+)(\[\d+\])*$`)

var ruleSetKeys = sync.OnceValue(func() map[string]bool {
	keys := map[string]bool{"version": true, "rules": true}
	var walk func(*Spec)
	walk = func(s *Spec) {
		for k, f := range s.fields {
			keys[k] = true
			walk(f)
		}
		for _, v := range s.variants {
			for k, f := range v {
				keys[k] = true
				walk(f)
			}
		}
		if s.elem != nil {
			walk(s.elem)
		}
	}
	walk(headlessRuleSpecWithin(0, maxRuleSetList))
	return keys
})

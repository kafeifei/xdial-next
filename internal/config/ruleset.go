package config

import (
	"fmt"

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
	if w.dropped > 0 {
		w.problems = append(w.problems, cli.Problem{Code: cli.CodeConfigMore, Message: fmt.Sprintf("还有 %d 处问题没有列出", w.dropped)})
	}
	if w.failed() {
		return nil, w.problems
	}
	return root.Get("rules").Items, nil
}

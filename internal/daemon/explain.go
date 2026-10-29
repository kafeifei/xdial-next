package daemon

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
)

// SchemaExplain is the output of explain, ARCHITECTURE.md 3.7.
const SchemaExplain = "xdial.explain/v1"

// explain says where a target goes in a scenario of the stored
// configuration, with remote content from the cache. Asked about the
// scenario running, a domain is resolved through the system, which is
// sing-box's DNS, so rules on addresses answer as they would for the
// traffic; content other than what the engine runs is pointed out.
func (d *Daemon) explain(params json.RawMessage) reply {
	var p struct {
		Target   string `json:"target"`
		Scenario string `json:"scenario"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	target, err := engine.ParseTarget(p.Target)
	if err != nil {
		return reply{err: cli.Errorf(cli.CodeUsage, "例如 xdial explain https://example.com", "%v", err)}
	}
	d.mu.Lock()
	cfg, c, scenario := d.cfg, d.conn, p.Scenario
	if scenario == "" {
		scenario = d.state.Scenario
	}
	secrets := maps.Clone(d.secrets)
	d.mu.Unlock()
	if cfg == nil {
		return reply{err: cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")}
	}
	scenario = defaultScenario(cfg, scenario)
	if findScenario(cfg, scenario) == nil {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "用 xdial config export 查看有哪些场景", "场景 %q 不存在", scenario)}
	}
	source := &subscriptionSource{d: d, cfg: cfg, secrets: secrets, content: map[string]*engine.Subscription{}}
	ruleSets := map[string]time.Time{}
	opts := engine.Options{
		Scenario: scenario, StateDirectory: d.opts.Layout.Tailscale(), Selections: d.selections(),
		RuleSet: func(o *config.Object) ([]*config.Value, bool) {
			url, err := remoteURL(cfg, o, secrets)
			if err != nil {
				return nil, false
			}
			meta, rules, ok := d.cachedRules(o, url)
			if ok {
				ruleSets[o.ID] = meta.ChangedAt
			}
			return rules, ok
		},
		Subscription: source.get,
	}
	// The system resolver is the connection's DNS: it answers for the
	// scenario running, not for another one.
	running := c != nil && c.scenario == scenario
	var addresses []netip.Addr
	if _, err := netip.ParseAddr(target.Host); err != nil && running {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		addresses, _ = net.DefaultResolver.LookupNetIP(ctx, "ip", target.Host)
		cancel()
	}
	e, err := engine.Explain(cfg, opts, target, addresses)
	if err != nil {
		return reply{err: cli.Errorf(cli.CodeInternal, "", "%v", err)}
	}
	if running {
		// Content other than what the engine was compiled with: an update
		// since, even one that landed while the connection came up.
		names := map[string]string{"rule_set": "规则集", "subscription": "订阅"}
		var newer []string
		for key, at := range contentVersions(ruleSets, source.changed) {
			if compiled, ok := c.content[key]; !ok || !compiled.Equal(at) {
				kind, id, _ := strings.Cut(key, ":")
				newer = append(newer, names[kind]+" "+id)
			}
		}
		if len(newer) > 0 {
			slices.Sort(newer)
			e.Notes = append(e.Notes, fmt.Sprintf("%s 和运行中的引擎用的不是同一份：以上是按缓存里的内容的结果，下一次连接或切场景才生效（3.4）", strings.Join(newer, "、")))
		}
	}
	return reply{schema: SchemaExplain, result: e}
}

func findScenario(cfg *config.Config, id string) *config.Scenario {
	for _, s := range cfg.Scenarios {
		if s.ID == id {
			return s
		}
	}
	return nil
}

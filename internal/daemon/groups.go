package daemon

import (
	"encoding/json"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
)

// Groups as they run, ARCHITECTURE.md 3.6.
const (
	SchemaGroupSelect = "xdial.group.select/v1"
	SchemaLineTest    = "xdial.line.test/v1"
	// lineTestTimeout bounds a whole line test; each line has 10 seconds.
	lineTestTimeout = 2 * time.Minute
)

// selections returns a copy of the members picked by hand.
func (d *Daemon) selections() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.state.Selections)
}

// GroupSelection is what group select returns.
type GroupSelection struct {
	Group  string `json:"group"`
	Member string `json:"member"`
	// Applied says the running engine switched; otherwise the choice takes
	// effect the next time the group is compiled.
	Applied bool `json:"applied"`
}

// groupSelect picks a member of a selector group: kept with the state, so
// reloads and restarts compile it as the group's default, and sent to the
// running engine, which switches without a reload.
func (d *Daemon) groupSelect(params json.RawMessage) reply {
	var p struct {
		Group  string `json:"group"`
		Member string `json:"member"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.ctl.Lock()
	defer d.ctl.Unlock()
	d.mu.Lock()
	cfg, c, state := d.cfg, d.conn, d.state
	d.mu.Unlock()
	var group *config.Object
	if cfg != nil {
		group = cfg.Line(p.Group)
	}
	if group == nil || group.Kind != "group" || group.Type != "selector" {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "只有 selector 组可以手选", "%q 不是 selector 组", p.Group)}
	}
	if !memberOf(group, p.Member, c) {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "用 xdial status 查看组的成员", "%q 不是组 %s 的成员", p.Member, p.Group)}
	}
	next := state
	next.Selections = maps.Clone(state.Selections)
	if next.Selections == nil {
		next.Selections = map[string]string{}
	}
	next.Selections[p.Group] = p.Member
	if err := d.persist(next); err != nil {
		return reply{err: cli.Errorf(cli.CodeInternal, "", "保存选择失败：%v", err)}
	}
	result := GroupSelection{Group: p.Group, Member: p.Member}
	if c != nil {
		if _, running := c.engine.groupStatus()[p.Group]; running {
			if err := c.engine.send(engine.Command{Select: &engine.SelectCommand{Group: p.Group, Member: p.Member}}); err == nil {
				result.Applied = waitGroup(c, p.Group, p.Member)
			}
		}
	}
	d.events.add("group_selected", map[string]any{"group": p.Group, "member": p.Member, "applied": result.Applied})
	return reply{schema: SchemaGroupSelect, result: result}
}

// memberOf reports whether member may be picked in group: one of its ids,
// or a node a subscription member brings, as the running group lists it
// or by its tag when not connected.
func memberOf(group *config.Object, member string, c *connection) bool {
	for _, m := range config.Members(group) {
		if m.Subscription == "" && m.ID == member {
			return true
		}
		if m.Subscription != "" && strings.HasPrefix(member, engine.NodeTag(m.Subscription, "")) {
			if c == nil {
				return true
			}
		}
	}
	if c != nil {
		if g, ok := c.engine.groupStatus()[group.ID]; ok {
			return slices.ContainsFunc(g.Members, func(m engine.MemberStatus) bool { return m.Tag == member })
		}
	}
	return false
}

// waitGroup waits briefly for the engine to report member in use.
func waitGroup(c *connection, group, member string) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if c.engine.groupStatus()[group].Now == member {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// lineTest measures lines, and every member of groups, through the
// running engine.
func (d *Daemon) lineTest(params json.RawMessage) reply {
	var p struct {
		IDs []string `json:"ids"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	c := d.conn
	d.mu.Unlock()
	if c == nil {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "先 xdial connect", "测速要经过运行中的引擎，现在没有连接")}
	}
	tags := p.IDs
	if len(tags) == 0 {
		for tag := range c.engine.groupStatus() {
			tags = append(tags, tag)
		}
		slices.Sort(tags)
	}
	if len(tags) == 0 {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "写出要测的线路 id", "当前场景没有线路组")}
	}
	result, err := c.engine.urlTest(tags, lineTestTimeout)
	if err != nil {
		return reply{err: cli.Errorf(cli.CodeEngineFailed, "", "%v", err)}
	}
	return reply{schema: SchemaLineTest, result: map[string]any{"results": result.Results}}
}

package daemon

import (
	"encoding/json"
	"errors"
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
	// lineTestTimeout bounds waiting for a line test, which the engine
	// ends within engine.TestDeadline.
	lineTestTimeout = engine.TestDeadline + 15*time.Second
)

// selections returns a copy of the members picked by hand.
func (d *Daemon) selections() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return maps.Clone(d.state.Selections)
}

// dropSelections forgets the members picked by hand of groups, which no
// longer have them: a member that comes back later does not bring the
// choice back over the group's default, 3.6. Callers hold d.ctl.
func (d *Daemon) dropSelections(groups []string) {
	d.mu.Lock()
	next := d.state
	d.mu.Unlock()
	next.Selections = maps.Clone(next.Selections)
	dropped := false
	for _, g := range groups {
		if _, ok := next.Selections[g]; ok {
			delete(next.Selections, g)
			dropped = true
		}
	}
	if !dropped {
		return
	}
	if err := d.persist(next); err != nil {
		d.events.add("state_write_failed", map[string]any{"error": err.Error()})
		return
	}
	d.events.add("selections_dropped", map[string]any{"groups": groups})
}

// staleSelections are the groups in selections cfg leaves without their
// member: gone, no longer selectors, or no longer naming it. A node of a
// subscription the group still names stays: whether the node is still
// there shows when the group is compiled.
func staleSelections(cfg *config.Config, selections map[string]string) []string {
	var stale []string
	for id, member := range selections {
		g := cfg.Line(id)
		if g == nil || g.Kind != "group" || g.Type != "selector" || !memberOf(g, member, nil) {
			stale = append(stale, id)
		}
	}
	slices.Sort(stale)
	return stale
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
		if _, running := c.groups[p.Group]; running {
			if err := c.engine.send(engine.Command{Select: &engine.SelectCommand{Group: p.Group, Member: p.Member}}); err == nil {
				result.Applied = waitGroup(c, p.Group, p.Member)
			}
		}
	}
	d.events.add("group_selected", map[string]any{"group": p.Group, "member": p.Member, "applied": result.Applied})
	return reply{schema: SchemaGroupSelect, result: result}
}

// memberOf reports whether member may be picked in group: one of the
// members the running engine compiled it with, or, when it does not run
// the group, one of its ids or a node of a subscription it names.
func memberOf(group *config.Object, member string, c *connection) bool {
	if c != nil {
		if members, ok := c.groups[group.ID]; ok {
			return slices.Contains(members, member)
		}
	}
	for _, m := range config.Members(group) {
		if m.Subscription == "" && m.ID == member {
			return true
		}
		if m.Subscription != "" && strings.HasPrefix(member, engine.NodeTag(m.Subscription, "")) {
			return true
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
		tags = slices.Sorted(maps.Keys(c.groups))
	}
	if len(tags) == 0 {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "写出要测的线路 id", "当前场景没有线路组")}
	}
	// Only what the engine runs: an unknown id would come back in the
	// answer, as long as the caller wrote it.
	var unknown []string
	for _, tag := range tags {
		if _, found := slices.BinarySearch(c.outbounds, tag); !found {
			unknown = append(unknown, tag)
		}
	}
	if len(unknown) > 0 {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "用 xdial status 查看当前连接的线路和组", "当前连接里没有 %d 个线路：%s", len(unknown), truncate(strings.Join(unknown, " "), 200))}
	}
	result, err := c.engine.urlTest(tags, lineTestTimeout)
	if err == nil && result.Error != "" {
		err = errors.New(result.Error)
	}
	if err != nil {
		return reply{err: cli.Errorf(cli.CodeEngineFailed, "", "%v", err)}
	}
	return reply{schema: SchemaLineTest, result: map[string]any{"results": result.Results}}
}

package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/store"
	"github.com/kafeifei/xdial-next/internal/subscription"
)

// Subscriptions, ARCHITECTURE.md 1.5. They are downloaded like remote rule
// sets, 3.4, then parsed by a child running as nobody; every node and rule
// that comes back is checked again here, and the whole is constructed by
// sing-box once before it replaces the cache.
const (
	SchemaSubscriptionList   = "xdial.subscription.list/v1"
	SchemaSubscriptionUpdate = "xdial.subscription.update/v1"
	SchemaSubscriptionShow   = "xdial.subscription.show/v1"
	// defaultUserAgent asks for Clash format: most providers choose the
	// format by User-Agent, and Clash carries the rules.
	defaultUserAgent = "clash.meta"
)

type cachedSubscription struct {
	Fingerprint  string               `json:"fingerprint"`
	FetchedAt    time.Time            `json:"fetched_at"`
	ChangedAt    time.Time            `json:"changed_at"`
	ETag         string               `json:"etag,omitempty"`
	LastModified string               `json:"last_modified,omitempty"`
	Content      subscription.Content `json:"content"`
}

func (d *Daemon) subscriptionDir() string {
	return filepath.Join(d.opts.Layout.Resources(), "subscriptions")
}

func (d *Daemon) subscriptionPath(id, fp string) string {
	return filepath.Join(d.subscriptionDir(), id+"."+fp[:16]+".json")
}

func userAgent(o *config.Object) string {
	if v := o.Value.Get("user_agent"); v != nil {
		return v.String
	}
	return defaultUserAgent
}

// subscriptionFingerprint ties a cache to the url and the User-Agent, which
// decides the format the provider returns.
func subscriptionFingerprint(o *config.Object, url string) string {
	return fingerprint(url, "subscription\n"+userAgent(o))
}

// cachedSubscription reads the cache of a subscription and returns its
// content for compiling, checked again, or false.
func (d *Daemon) cachedSubscription(o *config.Object, url string) (*cachedSubscription, *engine.Subscription, bool) {
	fp := subscriptionFingerprint(o, url)
	var c cachedSubscription
	if err := store.ReadJSON(d.subscriptionPath(o.ID, fp), &c); err != nil || c.Fingerprint != fp {
		return nil, nil, false
	}
	content, dropped, err := checkContent(&c.Content)
	if err != nil || dropped > 0 {
		return nil, nil, false
	}
	return &c, content, true
}

// subscriptionMeta reads what the cache says about a subscription without
// checking its content again, for listing and for deciding whether to
// download; compiling checks it.
func (d *Daemon) subscriptionMeta(o *config.Object, url string) (*cachedSubscription, bool) {
	fp := subscriptionFingerprint(o, url)
	var c cachedSubscription
	if err := store.ReadJSON(d.subscriptionPath(o.ID, fp), &c); err != nil || c.Fingerprint != fp {
		return nil, false
	}
	return &c, true
}

// checkContent checks what a parse child returned: every node against the
// node allow list, every rule against the headless rule classification. It
// keeps what passes and counts what does not, under "node:invalid" and
// "rule:invalid", so nothing is left out unseen.
func checkContent(c *subscription.Content) (*engine.Subscription, int, error) {
	out := &engine.Subscription{}
	dropped := 0
	var nodes []subscription.Node
	for _, n := range c.Nodes {
		v, err := config.Parse(n.Outbound)
		if err != nil || len(config.CheckNode(v)) > 0 {
			dropped++
			continue
		}
		nodes = append(nodes, n)
		out.Nodes = append(out.Nodes, engine.SubscriptionNode{Name: n.Name, Outbound: v})
	}
	raw := make([][]byte, len(c.Rules))
	for i, r := range c.Rules {
		raw[i] = r.Rule
	}
	checked, ok := config.CheckRules(raw)
	if !ok {
		return nil, 0, cli.Errorf(cli.CodeResourceTooLarge, "", "订阅规则里的正则合计超出上限")
	}
	var rules []subscription.Rule
	for i, r := range c.Rules {
		if checked[i] == nil {
			dropped++
			continue
		}
		rules = append(rules, r)
		out.Rules = append(out.Rules, engine.SubscriptionRule{Policy: r.Policy, Rule: checked[i]})
	}
	if dropped > 0 {
		if c.Unsupported == nil {
			c.Unsupported = map[string]int{}
		}
		c.Unsupported["node:invalid"] += len(c.Nodes) - len(nodes)
		c.Unsupported["rule:invalid"] += len(c.Rules) - len(rules)
		c.Nodes, c.Rules = nodes, rules
	}
	if len(out.Nodes) == 0 {
		return nil, dropped, cli.Errorf(cli.CodeResourceInvalid, "", "订阅里没有可用的节点")
	}
	return out, dropped, nil
}

type subscriptionResult struct {
	ID          string         `json:"id"`
	Changed     bool           `json:"changed"`
	Nodes       int            `json:"nodes"`
	Rules       int            `json:"rules"`
	Unsupported map[string]int `json:"unsupported"`
	FetchedAt   time.Time      `json:"fetched_at"`
}

// downloadSubscription downloads, parses and checks one subscription into
// the cache. Downloads run one at a time.
func (d *Daemon) downloadSubscription(cfg *config.Config, o *config.Object, secrets map[string]Secret) (subscriptionResult, error) {
	d.res.Lock()
	defer d.res.Unlock()
	result := subscriptionResult{ID: o.ID, Unsupported: map[string]int{}}
	err := func() error {
		url, err := remoteURL(cfg, o, secrets)
		if err != nil {
			return err
		}
		fp := subscriptionFingerprint(o, url)
		// Only content that still passes the checks may answer a 304.
		var old cachedSubscription
		if c, _, ok := d.cachedSubscription(o, url); ok {
			old = *c
		}
		hasOld := old.Fingerprint == fp
		req, err := d.fetchRequest(cfg, o, url, secrets)
		if err != nil {
			return err
		}
		req.MaxBytes, req.UserAgent = subscription.MaxSize, userAgent(o)
		if hasOld {
			req.ETag, req.LastModified = old.ETag, old.LastModified
		}
		fetched, body, err := d.fetch(req)
		if err != nil {
			return err
		}
		now := time.Now()
		if fetched.NotModified && hasOld {
			old.FetchedAt = now
			result.Nodes, result.Rules, result.Unsupported, result.FetchedAt = len(old.Content.Nodes), len(old.Content.Rules), old.Content.Unsupported, now
			return d.writeSubscription(o.ID, &old)
		}
		content, err := d.parseSubscription(body)
		if err != nil {
			return err
		}
		compiled, _, err := checkContent(content)
		if err != nil {
			return err
		}
		if err := d.checkSubscriptionUsable(compiled); err != nil {
			return err
		}
		entry := &cachedSubscription{Fingerprint: fp, FetchedAt: now, ChangedAt: now, ETag: fetched.ETag, LastModified: fetched.LastModified, Content: *content}
		newContent, _ := json.Marshal(content)
		oldContent, _ := json.Marshal(old.Content)
		result.Changed = !hasOld || !bytes.Equal(newContent, oldContent)
		if !result.Changed {
			entry.ChangedAt = old.ChangedAt
		}
		result.Nodes, result.Rules, result.FetchedAt = len(content.Nodes), len(content.Rules), now
		if content.Unsupported != nil {
			result.Unsupported = content.Unsupported
		}
		return d.writeSubscription(o.ID, entry)
	}()
	var e *cli.Error
	if err != nil && !errors.As(err, &e) {
		e = cli.Errorf(cli.CodeInternal, "", "%v", err)
	}
	d.mu.Lock()
	if d.attempts == nil {
		d.attempts = map[string]resourceAttempt{}
	}
	d.attempts["subscription:"+o.ID] = resourceAttempt{at: time.Now(), err: e}
	d.mu.Unlock()
	if e != nil {
		d.events.add("subscription_update_failed", map[string]any{"id": o.ID, "code": e.Code, "error": e.Message})
		return result, e
	}
	d.events.add("subscription_updated", map[string]any{"id": o.ID, "changed": result.Changed, "nodes": result.Nodes, "rules": result.Rules, "unsupported": result.Unsupported})
	if result.Changed {
		go d.resumeAfterFetch()
	}
	return result, nil
}

func (d *Daemon) writeSubscription(id string, c *cachedSubscription) error {
	if err := store.EnsureDir(d.subscriptionDir(), 0o700); err != nil {
		return err
	}
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return err
	}
	return store.WriteFile(d.subscriptionPath(id, c.Fingerprint), data.Bytes(), 0o600)
}

// parseSubscription runs one parse child: the downloaded body in, Content
// out. Callers hold d.res.
func (d *Daemon) parseSubscription(body []byte) (*subscription.Content, error) {
	ctx, cancel := context.WithTimeout(context.Background(), decodeTimeout)
	defer cancel()
	cmd, err := d.child(ctx, subscription.ParseCommand)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = bytes.NewReader(body)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: 2 * subscription.MaxSize}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 512}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, cli.Errorf(cli.CodeResourceTooLarge, "", "订阅 %s 内没有解析完", decodeTimeout)
		}
		// The child's reason is its own fixed wording, never the content.
		return nil, cli.Errorf(cli.CodeResourceInvalid, "", "%s", truncate(strings.TrimSpace(stderr.String()), 200))
	}
	var c subscription.Content
	if err := json.Unmarshal(stdout.Bytes(), &c); err != nil {
		return nil, cli.Errorf(cli.CodeResourceInvalid, "", "订阅解析的结果读不出来")
	}
	return &c, nil
}

// checkSubscriptionUsable has sing-box construct every node and a rule set
// of every rule, in a check child running as nobody.
func (d *Daemon) checkSubscriptionUsable(s *engine.Subscription) error {
	outbounds := []any{map[string]any{"type": "direct", "tag": config.Direct}}
	for i, n := range s.Nodes {
		outbounds = append(outbounds, n.Outbound.With("tag", config.String(fmt.Sprintf("n%d", i))))
	}
	route := map[string]any{}
	if len(s.Rules) > 0 {
		rules := make([]*config.Value, len(s.Rules))
		for i, r := range s.Rules {
			rules[i] = r.Rule
		}
		route["rule_set"] = []any{map[string]any{"type": "inline", "tag": "r", "rules": rules}}
		route["rules"] = []any{map[string]any{"rule_set": []string{"r"}, "action": "route", "outbound": config.Direct}}
	}
	compiled, err := json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"outbounds": outbounds,
		"dns":       map[string]any{"servers": []any{map[string]any{"type": "udp", "tag": "d", "server": "192.0.2.53"}}},
		"route":     route,
	})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), decodeTimeout)
	defer cancel()
	cmd, err := d.child(ctx, engine.CheckCommand)
	if err != nil {
		return err
	}
	if err := engine.CheckWith(ctx, cmd, compiled); err != nil {
		if errors.Is(err, engine.ErrCheckUnavailable) {
			return cli.Errorf(cli.CodeInternal, "", "%v", err)
		}
		return cli.Errorf(cli.CodeResourceInvalid, "", "sing-box 不接受订阅里的节点或规则")
	}
	return nil
}

// collectSubscriptions removes cached subscriptions the current
// configuration does not use, as collectRuleSets does. Callers hold d.res.
func (d *Daemon) collectSubscriptions() {
	d.mu.Lock()
	defer d.mu.Unlock()
	cfg, secrets := d.cfg, d.secrets
	if cfg == nil {
		return
	}
	keep := map[string]bool{}
	for _, o := range cfg.Subscriptions {
		if url, err := remoteURL(cfg, o, secrets); err == nil {
			keep[filepath.Base(d.subscriptionPath(o.ID, subscriptionFingerprint(o, url)))] = true
		}
	}
	entries, err := os.ReadDir(d.subscriptionDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || keep[e.Name()] || time.Since(info.ModTime()) < time.Hour {
			continue
		}
		_ = os.Remove(filepath.Join(d.subscriptionDir(), e.Name()))
	}
}

// subscriptionSource answers the compiler's questions about subscriptions
// from the cache, noting the first error, such as an unset url secret.
type subscriptionSource struct {
	d       *Daemon
	cfg     *config.Config
	secrets map[string]Secret
	content map[string]*engine.Subscription
	err     error
}

func (s *subscriptionSource) get(o *config.Object) (*engine.Subscription, bool) {
	if c, ok := s.content[o.ID]; ok {
		return c, c != nil
	}
	url, err := remoteURL(s.cfg, o, s.secrets)
	if err != nil {
		if s.err == nil {
			s.err = err
		}
		s.content[o.ID] = nil
		return nil, false
	}
	_, c, ok := s.d.cachedSubscription(o, url)
	path := s.d.subscriptionPath(o.ID, subscriptionFingerprint(o, url))
	if ok {
		// A cache in use is not collected.
		now := time.Now()
		_ = os.Chtimes(path, now, now)
	} else {
		// Content that no longer passes the checks is dropped, so it is
		// downloaded again rather than trusted for its age.
		s.d.dropInvalid(path, func() bool {
			_, _, ok := s.d.cachedSubscription(o, url)
			return ok
		})
		c = nil
	}
	s.content[o.ID] = c
	return c, ok
}

// SubscriptionInfo is one subscription in subscription list.
type SubscriptionInfo struct {
	ID          string         `json:"id"`
	Name        string         `json:"name,omitempty"`
	DownloadVia string         `json:"download_via"`
	Cached      bool           `json:"cached"`
	Format      string         `json:"format,omitempty"`
	Nodes       int            `json:"nodes"`
	Rules       int            `json:"rules"`
	Policies    []PolicyInfo   `json:"policies"`
	Unsupported map[string]int `json:"unsupported"`
	FetchedAt   *time.Time     `json:"fetched_at,omitempty"`
	ChangedAt   *time.Time     `json:"changed_at,omitempty"`
	NextUpdate  *time.Time     `json:"next_update,omitempty"`
	LastError   *cli.Error     `json:"last_error,omitempty"`
}

// PolicyInfo is a policy a subscription's rules name, with how many rules
// name it, in order of first use: what a scenario's policies map.
type PolicyInfo struct {
	Name  string `json:"name"`
	Rules int    `json:"rules"`
}

func policies(c *subscription.Content) []PolicyInfo {
	out := []PolicyInfo{}
	index := map[string]int{}
	for _, r := range c.Rules {
		i, ok := index[r.Policy]
		if !ok {
			i = len(out)
			index[r.Policy] = i
			out = append(out, PolicyInfo{Name: r.Policy})
		}
		out[i].Rules++
	}
	return out
}

func (d *Daemon) subscriptionList(json.RawMessage) reply {
	d.mu.Lock()
	cfg := d.cfg
	secrets := maps.Clone(d.secrets)
	attempts := maps.Clone(d.attempts)
	d.mu.Unlock()
	list := []SubscriptionInfo{}
	if cfg != nil {
		for _, o := range cfg.Subscriptions {
			info := SubscriptionInfo{ID: o.ID, Name: o.Name, DownloadVia: config.Direct, Policies: []PolicyInfo{}, Unsupported: map[string]int{}}
			if via := o.Value.Get("download_via"); via != nil {
				info.DownloadVia = via.String
			}
			if url, err := remoteURL(cfg, o, secrets); err == nil {
				if c, ok := d.subscriptionMeta(o, url); ok {
					next := c.FetchedAt.Add(updateInterval(o))
					info.Cached, info.Format = true, c.Content.Format
					info.Nodes, info.Rules = len(c.Content.Nodes), len(c.Content.Rules)
					info.Policies = policies(&c.Content)
					if c.Content.Unsupported != nil {
						info.Unsupported = c.Content.Unsupported
					}
					info.FetchedAt, info.ChangedAt, info.NextUpdate = &c.FetchedAt, &c.ChangedAt, &next
				}
			}
			if a, ok := attempts["subscription:"+o.ID]; ok && a.err != nil {
				info.LastError = a.err
			}
			list = append(list, info)
		}
	}
	return reply{schema: SchemaSubscriptionList, result: map[string]any{"subscriptions": list}}
}

// NodeInfo is one node in subscription show: never its credentials.
type NodeInfo struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

func (d *Daemon) subscriptionShow(params json.RawMessage) reply {
	var p struct {
		ID string `json:"id"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	cfg := d.cfg
	secrets := maps.Clone(d.secrets)
	d.mu.Unlock()
	o := findSubscription(cfg, p.ID)
	if o == nil {
		return reply{err: cli.Errorf(cli.CodeConfigConflict, "用 xdial subscription list 查看有哪些订阅", "订阅 %q 不存在", p.ID)}
	}
	url, err := remoteURL(cfg, o, secrets)
	if err != nil {
		return reply{err: err}
	}
	c, ok := d.subscriptionMeta(o, url)
	if !ok {
		return reply{err: cli.Errorf(cli.CodeResourceMissing, "用 xdial subscription update "+o.ID+" 下载", "订阅 %s 还没下载", o.ID)}
	}
	nodes := []NodeInfo{}
	for _, n := range c.Content.Nodes {
		var o struct {
			Type       string `json:"type"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
		}
		_ = json.Unmarshal(n.Outbound, &o)
		nodes = append(nodes, NodeInfo{Name: n.Name, Type: o.Type, Server: o.Server, ServerPort: o.ServerPort})
	}
	return reply{schema: SchemaSubscriptionShow, result: map[string]any{"id": p.ID, "nodes": nodes, "policies": policies(&c.Content)}}
}

func findSubscription(cfg *config.Config, id string) *config.Object {
	if cfg == nil {
		return nil
	}
	for _, o := range cfg.Subscriptions {
		if o.ID == id {
			return o
		}
	}
	return nil
}

// subscriptionUpdate downloads the named subscriptions now, or all of
// them. New content takes effect at the next connect or scenario switch.
func (d *Daemon) subscriptionUpdate(params json.RawMessage) reply {
	var p struct {
		IDs []string `json:"ids"`
	}
	if err := decode(params, &p); err != nil {
		return reply{err: err}
	}
	d.mu.Lock()
	cfg := d.cfg
	secrets := maps.Clone(d.secrets)
	d.mu.Unlock()
	if cfg == nil {
		return reply{err: cli.Errorf(cli.CodeConfigInvalid, "先用 xdial config apply 提交配置", "还没有配置")}
	}
	targets := cfg.Subscriptions
	if len(p.IDs) > 0 {
		targets = nil
		for _, id := range p.IDs {
			o := findSubscription(cfg, id)
			if o == nil {
				return reply{err: cli.Errorf(cli.CodeConfigConflict, "用 xdial subscription list 查看有哪些订阅", "订阅 %q 不存在", id)}
			}
			targets = append(targets, o)
		}
	}
	updated := []subscriptionResult{}
	var failed []string
	var first *cli.Error
	for _, o := range targets {
		r, err := d.downloadSubscription(cfg, o, secrets)
		if err != nil {
			var e *cli.Error
			errors.As(err, &e)
			if first == nil {
				first = e
			}
			failed = append(failed, fmt.Sprintf("%s：%s", o.ID, e.Message))
			continue
		}
		updated = append(updated, r)
	}
	if first != nil {
		e := *first
		e.Message = fmt.Sprintf("%d 个订阅下载失败（%s）；其余 %d 个已更新", len(failed), strings.Join(failed, "；"), len(updated))
		return reply{err: &e}
	}
	sort.Slice(updated, func(i, j int) bool { return updated[i].ID < updated[j].ID })
	return reply{schema: SchemaSubscriptionUpdate, result: map[string]any{"updated": updated}}
}

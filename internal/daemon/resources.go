package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kafeifei/xdial-next/internal/buildinfo"
	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
	"github.com/kafeifei/xdial-next/internal/resource"
	"github.com/kafeifei/xdial-next/internal/store"
)

// Remote rule sets, ARCHITECTURE.md 3.4. The daemon downloads them in a
// child running as nobody, checks what comes back, and keeps the result
// in a private cache that compiling reads. New content takes effect at the
// next connect or scenario switch; an update never reloads by itself.
const (
	fetchTimeout          = 60 * time.Second
	decodeTimeout         = 30 * time.Second
	defaultUpdateInterval = 24 * time.Hour
	minUpdateInterval     = 10 * time.Minute
	resourceCheckInterval = 5 * time.Minute
	resourceRetryDelay    = 10 * time.Minute
	SchemaRuleSetList     = "xdial.rule-set.list/v1"
	SchemaRuleSetUpdate   = "xdial.rule-set.update/v1"
)

// cachedRuleSet is one downloaded rule set on disk: checked content in
// source format, and what the next download needs.
type cachedRuleSet struct {
	// Fingerprint ties the content to the url and format it came from;
	// change either and the cache no longer counts.
	Fingerprint  string          `json:"fingerprint"`
	Rules        int             `json:"rules"`
	FetchedAt    time.Time       `json:"fetched_at"`
	ChangedAt    time.Time       `json:"changed_at"`
	ETag         string          `json:"etag,omitempty"`
	LastModified string          `json:"last_modified,omitempty"`
	Source       json.RawMessage `json:"source"`
}

// resourceAttempt is the last download of one rule set, kept in memory.
type resourceAttempt struct {
	at  time.Time
	err *cli.Error
}

// ruleSetPath is where the content of rule set id downloaded from the url
// and format of fp is kept. One file per fingerprint: a download for a
// configuration that has since changed the url cannot overwrite the cache
// of the new one.
func (d *Daemon) ruleSetPath(id, fp string) string {
	return filepath.Join(d.ruleSetDir(), id+"."+fp[:16]+".json")
}

func (d *Daemon) ruleSetDir() string { return filepath.Join(d.opts.Layout.Resources(), "rule-sets") }

func fingerprint(url, format string) string {
	sum := sha256.Sum256([]byte(format + "\n" + url))
	return hex.EncodeToString(sum[:])
}

// remoteURL is the url of a remote rule set, with a secret reference
// replaced by its value.
func remoteURL(cfg *config.Config, o *config.Object, secrets map[string]Secret) (string, error) {
	for _, use := range cfg.Secrets {
		if use.Path == o.Path+".url" {
			s, ok := secrets[use.Name]
			if !ok {
				return "", cli.Errorf(cli.CodeSecretMissing, "用 xdial secret set "+use.Name+" 设置", "规则集 %s 的 url 用到的凭据 %s 还没设置", o.ID, use.Name)
			}
			return s.Value, nil
		}
	}
	return o.Value.Get("url").String, nil
}

// cachedRules reads the cache of a remote rule set and returns its rules,
// or false when there is none for this url and format.
func (d *Daemon) cachedRules(o *config.Object, url string) (*cachedRuleSet, []*config.Value, bool) {
	fp := fingerprint(url, o.Value.Get("format").String)
	var c cachedRuleSet
	if err := store.ReadJSON(d.ruleSetPath(o.ID, fp), &c); err != nil || c.Fingerprint != fp {
		return nil, nil, false
	}
	rules, problems := config.CheckRuleSetSource(c.Source)
	if len(problems) > 0 {
		return nil, nil, false
	}
	return &c, rules, true
}

// remoteRuleSets are the remote rule sets scenario of cfg routes by.
func remoteRuleSets(cfg *config.Config, scenario string) []*config.Object {
	var out []*config.Object
	seen := map[string]bool{}
	for _, s := range cfg.Scenarios {
		if s.ID != scenario {
			continue
		}
		for _, r := range s.Rules {
			o := cfg.RuleSet(r.RuleSet)
			if o != nil && o.Type == "remote" && !seen[o.ID] {
				seen[o.ID] = true
				out = append(out, o)
			}
		}
	}
	return out
}

// fetchFor downloads what scenario of cfg needs and the cache lacks. A
// request runs it before it takes d.ctl: a download can take minutes, and
// the control sequence must stay free for what cannot wait, such as taking
// the resolver down when the engine dies, 6.3. Failing here changes
// nothing.
func (d *Daemon) fetchFor(cfg *config.Config, scenario string) error {
	if cfg == nil {
		return nil
	}
	d.mu.Lock()
	secrets := maps.Clone(d.secrets)
	d.mu.Unlock()
	for _, o := range remoteRuleSets(cfg, scenario) {
		url, err := remoteURL(cfg, o, secrets)
		if err != nil {
			return err
		}
		// Checked, not just present: content that no longer passes is
		// dropped and downloaded again.
		if _, _, ok := d.cachedRules(o, url); ok {
			continue
		}
		d.dropInvalid(d.ruleSetPath(o.ID, fingerprint(url, o.Value.Get("format").String)), func() bool {
			_, _, ok := d.cachedRules(o, url)
			return ok
		})
		if _, err := d.downloadRuleSet(cfg, o, secrets); err != nil {
			return prefixed(err, fmt.Sprintf("场景 %s 用到的规则集 %s 还没下载，下载失败：", scenario, o.ID))
		}
	}
	// Subscriptions: the compiler says which the scenario reaches and the
	// cache lacks. A downloaded one can reach lines that reach others, so
	// repeat; each round downloads at least one, which bounds the rounds,
	// 1.5.
	source := &subscriptionSource{d: d, cfg: cfg, secrets: secrets, content: map[string]*engine.Subscription{}}
	for round := 0; round <= len(cfg.Subscriptions); round++ {
		result, err := engine.Compile(cfg, engine.Options{Scenario: scenario, Subscription: source.get})
		if err != nil || len(result.MissingSubscriptions) == 0 {
			return nil
		}
		if source.err != nil {
			return source.err
		}
		for _, id := range result.MissingSubscriptions {
			if _, err := d.downloadSubscription(cfg, findSubscription(cfg, id), secrets); err != nil {
				return prefixed(err, fmt.Sprintf("场景 %s 用到的订阅 %s 还没下载，下载失败：", scenario, id))
			}
			delete(source.content, id)
		}
	}
	return nil
}

// cachedRuleSets returns the rules of every remote rule set scenario uses,
// from the cache only; prepare runs it under d.ctl, where nothing is
// downloaded. Without them there is no connection: a rule set that never
// matches would quietly send its traffic elsewhere, 3.4.
func (d *Daemon) cachedRuleSets(cfg *config.Config, scenario string, secrets map[string]Secret) (map[string][]*config.Value, error) {
	content := map[string][]*config.Value{}
	for _, o := range remoteRuleSets(cfg, scenario) {
		url, err := remoteURL(cfg, o, secrets)
		if err != nil {
			return nil, err
		}
		_, rules, ok := d.cachedRules(o, url)
		if !ok {
			d.dropInvalid(d.ruleSetPath(o.ID, fingerprint(url, o.Value.Get("format").String)), func() bool {
				_, _, ok := d.cachedRules(o, url)
				return ok
			})
			d.wakeResources()
			return nil, cli.Errorf(cli.CodeResourceMissing, "用 xdial rule-set update "+o.ID+" 下载", "场景 %s 用到的规则集 %s 还没下载", scenario, o.ID)
		}
		// A cache in use is not collected, 3.4.
		now := time.Now()
		_ = os.Chtimes(d.ruleSetPath(o.ID, fingerprint(url, o.Value.Get("format").String)), now, now)
		content[o.ID] = rules
	}
	return content, nil
}

// dropInvalid removes a cached file whose content no longer passes the
// checks, so the background loop downloads it again instead of trusting
// its age. It never waits for d.res, which a download may hold for
// minutes while the caller holds d.ctl; when a download is running it
// leaves the file to that download.
func (d *Daemon) dropInvalid(path string, valid func() bool) {
	if !d.res.TryLock() {
		// Left to the background loop, which downloads it again however
		// fresh the file looks.
		d.mu.Lock()
		if d.invalid == nil {
			d.invalid = map[string]bool{}
		}
		d.invalid[path] = true
		d.mu.Unlock()
		d.wakeResources()
		return
	}
	defer d.res.Unlock()
	if _, err := os.Stat(path); err == nil && !valid() {
		if err := os.Remove(path); err != nil {
			// Still there: the mark stays, and the background loop
			// downloads it again.
			d.mu.Lock()
			if d.invalid == nil {
				d.invalid = map[string]bool{}
			}
			d.invalid[path] = true
			d.mu.Unlock()
			return
		}
		d.events.add("cache_dropped", map[string]any{"file": filepath.Base(path)})
	}
	d.unmark(path)
}

// cacheComplete reports whether the cache holds, checked, every remote rule
// set scenario of cfg uses. It looks at the cache only, so whatever else
// preparing may fail on says nothing about it.
func (d *Daemon) cacheComplete(cfg *config.Config, scenario string) bool {
	if cfg == nil {
		return false
	}
	d.mu.Lock()
	secrets := maps.Clone(d.secrets)
	d.mu.Unlock()
	complete := true
	for _, o := range remoteRuleSets(cfg, scenario) {
		url, err := remoteURL(cfg, o, secrets)
		if err != nil {
			return false
		}
		if _, _, ok := d.cachedRules(o, url); !ok {
			// As when compiling: a refused file is dropped or marked, so
			// the background loop downloads it again however fresh.
			d.dropInvalid(d.ruleSetPath(o.ID, fingerprint(url, o.Value.Get("format").String)), func() bool {
				_, _, ok := d.cachedRules(o, url)
				return ok
			})
			complete = false
		}
	}
	// Subscriptions: what the compiler reaches through the cache only.
	// subscriptionSource.get drops or marks a refused cache, as above.
	source := &subscriptionSource{d: d, cfg: cfg, secrets: secrets, content: map[string]*engine.Subscription{}}
	result, err := engine.Compile(cfg, engine.Options{Scenario: scenario, Subscription: source.get})
	if err != nil || source.err != nil || len(result.MissingSubscriptions) > 0 {
		complete = false
	}
	if !complete {
		d.wakeResources()
	}
	return complete
}

// markedInvalid reports whether compiling found path's content refused
// while a download held d.res. The mark stays until the file is replaced
// by a download or removed, so a failed download does not forget it.
func (d *Daemon) markedInvalid(path string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.invalid[path]
}

func (d *Daemon) unmark(path string) {
	d.mu.Lock()
	delete(d.invalid, path)
	d.mu.Unlock()
}

// ruleSetMeta reads what the cache says about a rule set without checking
// its content again, for listing and for deciding whether to download.
func (d *Daemon) ruleSetMeta(o *config.Object, url string) (*cachedRuleSet, bool) {
	fp := fingerprint(url, o.Value.Get("format").String)
	var c cachedRuleSet
	if err := store.ReadJSON(d.ruleSetPath(o.ID, fp), &c); err != nil || c.Fingerprint != fp {
		return nil, false
	}
	return &c, true
}

func prefixed(err error, prefix string) error {
	var e *cli.Error
	if !errors.As(err, &e) {
		return err
	}
	out := *e
	out.Message = prefix + e.Message
	return &out
}

// downloadResult is what one download of a rule set changed.
type downloadResult struct {
	ID        string    `json:"id"`
	Changed   bool      `json:"changed"`
	Rules     int       `json:"rules"`
	FetchedAt time.Time `json:"fetched_at"`
}

// downloadRuleSet downloads one remote rule set into the cache. Downloads
// run one at a time.
func (d *Daemon) downloadRuleSet(cfg *config.Config, o *config.Object, secrets map[string]Secret) (downloadResult, error) {
	d.res.Lock()
	defer d.res.Unlock()
	result := downloadResult{ID: o.ID}
	err := func() error {
		url, err := remoteURL(cfg, o, secrets)
		if err != nil {
			return err
		}
		format := o.Value.Get("format").String
		// Only content that still passes the checks may answer a 304; a
		// cache that does not is downloaded in full.
		old, _, hasOld := d.cachedRules(o, url)
		req, err := d.fetchRequest(cfg, o, url, secrets)
		if err != nil {
			return err
		}
		if format == "binary" {
			req.MaxBytes = resource.MaxBinarySize
		} else {
			req.MaxBytes = config.RuleSetMaxSize
		}
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
			result.FetchedAt, result.Rules = now, old.Rules
			return d.writeRuleSet(o.ID, old)
		}
		source := body
		if format == "binary" {
			// Limits on what is inside the content are resource.invalid;
			// resource.too_large is for the size of a download or of the
			// compiled configuration, 3.4.
			if err := resource.Preflight(body); err != nil {
				return cli.Errorf(cli.CodeResourceInvalid, "", "%v", err)
			}
			if source, err = d.decode(body); err != nil {
				return err
			}
		}
		// Compact, so the size checked is the size kept and an unchanged
		// download compares equal to what is cached.
		var compact bytes.Buffer
		if err := json.Compact(&compact, source); err != nil {
			return invalidContent(o, []cli.Problem{{Code: cli.CodeConfigSyntax}})
		}
		source = compact.Bytes()
		rules, problems := config.CheckRuleSetSource(source)
		if len(problems) > 0 {
			return invalidContent(o, problems)
		}
		// What passes XDial's checks must also be what sing-box accepts, or
		// a download could replace a good cache with one no connection
		// can start from.
		if err := d.checkUsable(source); err != nil {
			return err
		}
		entry := &cachedRuleSet{
			Fingerprint: fingerprint(url, format), Rules: len(rules), FetchedAt: now, ChangedAt: now,
			ETag: fetched.ETag, LastModified: fetched.LastModified, Source: source,
		}
		result.Changed = !hasOld || !bytes.Equal(old.Source, source)
		if !result.Changed {
			entry.ChangedAt = old.ChangedAt
		}
		result.Rules, result.FetchedAt = len(rules), now
		return d.writeRuleSet(o.ID, entry)
	}()
	var e *cli.Error
	if err != nil && !errors.As(err, &e) {
		e = cli.Errorf(cli.CodeInternal, "", "%v", err)
	}
	d.mu.Lock()
	if d.attempts == nil {
		d.attempts = map[string]resourceAttempt{}
	}
	d.attempts["rule_set:"+o.ID] = resourceAttempt{at: time.Now(), err: e}
	d.mu.Unlock()
	if e != nil {
		d.events.add("rule_set_update_failed", map[string]any{"id": o.ID, "code": e.Code, "error": e.Message})
		return result, e
	}
	d.events.add("rule_set_updated", map[string]any{"id": o.ID, "changed": result.Changed, "rules": result.Rules})
	if result.Changed {
		go d.resumeAfterFetch()
	}
	return result, nil
}

// invalidContent reports what in a downloaded rule set failed the checks
// by code and path only: the content is remote input and is not echoed.
func invalidContent(o *config.Object, problems []cli.Problem) error {
	e := cli.Errorf(cli.CodeResourceInvalid, "", "规则集 %s 下载的内容有 %d 处不符合要求", o.ID, len(problems))
	for _, p := range problems {
		e.Problems = append(e.Problems, cli.Problem{Code: p.Code, Path: p.Path, Object: "rule_set " + o.ID, Message: "这里不符合规则集的格式或上限"})
	}
	return e
}

func (d *Daemon) writeRuleSet(id string, c *cachedRuleSet) error {
	if err := store.EnsureDir(d.ruleSetDir(), 0o700); err != nil {
		return err
	}
	// json.Marshal would escape <, > and & inside Source, growing it past
	// the limit it was checked against and making an unchanged download
	// compare as changed.
	var data bytes.Buffer
	enc := json.NewEncoder(&data)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(c); err != nil {
		return err
	}
	path := d.ruleSetPath(id, c.Fingerprint)
	if err := store.WriteFile(path, data.Bytes(), 0o600); err != nil {
		return err
	}
	// Only checked content is written: a mark for downloading it again
	// is done with.
	d.unmark(path)
	return nil
}

// checkUsable has sing-box construct a configuration routing by the rules
// of source, in a check child running as nobody.
func (d *Daemon) checkUsable(source []byte) error {
	var doc struct {
		Rules json.RawMessage `json:"rules"`
	}
	if err := json.Unmarshal(source, &doc); err != nil {
		return cli.Errorf(cli.CodeResourceInvalid, "", "规则集读不出来")
	}
	compiled, err := json.Marshal(map[string]any{
		"log":       map[string]any{"disabled": true},
		"outbounds": []any{map[string]any{"type": "direct", "tag": config.Direct}},
		"route": map[string]any{
			"rule_set": []any{map[string]any{"type": "inline", "tag": "r", "rules": doc.Rules}},
			"rules":    []any{map[string]any{"rule_set": []string{"r"}, "action": "route", "outbound": config.Direct}},
		},
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
		return cli.Errorf(cli.CodeResourceInvalid, "", "sing-box 不接受下载的规则集")
	}
	return nil
}

// collectRuleSets removes cached files the current configuration does not
// use, once they have not been used for an hour: a configuration being
// applied may use one that is not current yet. It decides and removes
// under d.mu, which publishing a configuration also takes, so it never
// acts on a configuration that has just been replaced; it is a handful of
// small file operations. Callers hold d.res.
func (d *Daemon) collectRuleSets() {
	d.mu.Lock()
	defer d.mu.Unlock()
	cfg, secrets := d.cfg, d.secrets
	if cfg == nil {
		return
	}
	keep := map[string]bool{}
	for _, o := range cfg.RuleSets {
		if o.Type != "remote" {
			continue
		}
		if url, err := remoteURL(cfg, o, secrets); err == nil {
			keep[filepath.Base(d.ruleSetPath(o.ID, fingerprint(url, o.Value.Get("format").String)))] = true
		}
	}
	entries, err := os.ReadDir(d.ruleSetDir())
	if err != nil {
		return
	}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || keep[e.Name()] || time.Since(info.ModTime()) < time.Hour {
			continue
		}
		_ = os.Remove(filepath.Join(d.ruleSetDir(), e.Name()))
	}
}

// fetchRequest is the request for one download: the physical interface
// and DNS, and the line chain of download_via compiled on its own.
func (d *Daemon) fetchRequest(cfg *config.Config, o *config.Object, url string, secrets map[string]Secret) (resource.FetchRequest, error) {
	physical, err := d.sys.PhysicalDNS()
	if err != nil {
		return resource.FetchRequest{}, cli.Errorf(cli.CodeResourceDownload, "", "读不到物理网络的 DNS：%v", err)
	}
	physical = usablePhysical(physical)
	if len(physical) == 0 {
		return resource.FetchRequest{}, cli.Errorf(cli.CodeResourceDownload, "连上网络后再试", "物理网络还没有 DNS 服务器")
	}
	iface, err := d.sys.PhysicalInterface()
	if err != nil || iface == "" {
		return resource.FetchRequest{}, cli.Errorf(cli.CodeResourceDownload, "连上网络后再试", "找不到物理网络的接口")
	}
	req := resource.FetchRequest{
		URL: url, Timeout: fetchTimeout.Milliseconds(), Interface: iface, DNS: physical[0].String(),
		Via: resource.Direct, UserAgent: "xdial/" + buildinfo.Version,
	}
	if via := o.Value.Get("download_via"); via != nil && via.String != config.Direct {
		opts, err := engine.CompileDownload(cfg, via.String, iface, engine.Options{
			PhysicalDNS: physical[0],
			Secret:      func(u config.SecretUse) string { return secrets[u.Name].Value },
		})
		if err != nil {
			return resource.FetchRequest{}, cli.Errorf(cli.CodeInternal, "", "编译下载线路失败：%v", err)
		}
		req.Via, req.Options = via.String, opts
	}
	return req, nil
}

// child prepares a hidden subcommand of the daemon's own binary, run as
// nobody with no supplementary groups and nothing inherited but its pipes.
// A root daemon that cannot find nobody runs no child at all; the child
// checks again that it is not root.
func (d *Daemon) child(ctx context.Context, sub string) (*exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, d.opts.Executable, sub)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.Dir = "/"
	if os.Geteuid() == 0 {
		uid, gid, ok := nobody()
		if !ok {
			return nil, cli.Errorf(cli.CodeInternal, "", "找不到 nobody 账户，下载和转换不能降权运行")
		}
		// An empty group list with NoSetGroups unset clears the
		// supplementary groups.
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: uid, Gid: gid, Groups: []uint32{}}}
	}
	return cmd, nil
}

// nobody is the unprivileged account downloads and decoding run as. macOS
// writes its ids as -2.
func nobody() (uint32, uint32, bool) {
	u, err := user.Lookup("nobody")
	if err != nil {
		return 0, 0, false
	}
	uid, err1 := strconv.ParseInt(u.Uid, 10, 64)
	gid, err2 := strconv.ParseInt(u.Gid, 10, 64)
	if err1 != nil || err2 != nil {
		return 0, 0, false
	}
	return uint32(uid), uint32(gid), true
}

// fetch runs one download child.
func (d *Daemon) fetch(req resource.FetchRequest) (resource.FetchResult, []byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout+5*time.Second)
	defer cancel()
	in, err := json.Marshal(req)
	if err != nil {
		return resource.FetchResult{}, nil, err
	}
	cmd, err := d.child(ctx, resource.FetchCommand)
	if err != nil {
		return resource.FetchResult{}, nil, err
	}
	cmd.Stdin = bytes.NewReader(in)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return resource.FetchResult{}, nil, err
	}
	if err := cmd.Start(); err != nil {
		return resource.FetchResult{}, nil, cli.Errorf(cli.CodeInternal, "", "下载子进程起不来：%v", err)
	}
	r := bufio.NewReader(io.LimitReader(stdout, 64<<10+req.MaxBytes+1))
	line, lineErr := r.ReadBytes('\n')
	var result resource.FetchResult
	var body []byte
	if lineErr == nil && json.Unmarshal(line, &result) != nil {
		lineErr = errors.New("unreadable result line")
		result = resource.FetchResult{}
	}
	if lineErr == nil && result.Code == "" && !result.NotModified {
		if result.Size < 0 || result.Size > req.MaxBytes {
			lineErr = errors.New("size out of range")
		} else {
			body = make([]byte, result.Size)
			_, lineErr = io.ReadFull(r, body)
		}
	}
	_, _ = io.Copy(io.Discard, stdout)
	waitErr := cmd.Wait()
	switch {
	case lineErr != nil && result.Code == "":
		if ctx.Err() != nil {
			return result, nil, cli.Errorf(cli.CodeResourceDownload, "", "下载超时")
		}
		return result, nil, cli.Errorf(cli.CodeInternal, "", "下载子进程没有给出结果：%v", waitErr)
	case result.Code != "":
		if _, ok := cli.Lookup(result.Code); !ok {
			result.Code = cli.CodeResourceDownload
		}
		// The child runs as nobody with remote input in hand: its word is
		// taken for the code, and the message is cut short.
		if len(result.Message) > 300 {
			result.Message = strings.ToValidUTF8(result.Message[:300], "") + "…"
		}
		return result, nil, cli.Errorf(result.Code, "", "%s", result.Message)
	}
	return result, body, nil
}

// decode runs one decode child: binary in, source format out. Callers hold
// d.res, so only one runs at a time.
func (d *Daemon) decode(binary []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), decodeTimeout)
	defer cancel()
	cmd, err := d.child(ctx, resource.DecodeCommand)
	if err != nil {
		return nil, err
	}
	cmd.Stdin = bytes.NewReader(binary)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &limitedWriter{w: &stdout, n: config.RuleSetMaxSize}
	cmd.Stderr = &limitedWriter{w: &stderr, n: 256}
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, cli.Errorf(cli.CodeResourceInvalid, "", "binary 规则集 %s 内没有转换完", decodeTimeout)
		}
		if strings.Contains(stderr.String(), "too large") {
			return nil, cli.Errorf(cli.CodeResourceInvalid, "", "binary 规则集转换成 source 后超过 %d 字节", config.RuleSetMaxSize)
		}
		return nil, cli.Errorf(cli.CodeResourceInvalid, "", "binary 规则集转换失败")
	}
	return stdout.Bytes(), nil
}

// limitedWriter fails once more than n bytes come through.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if len(p) > l.n {
		return 0, errors.New("output too large")
	}
	l.n -= len(p)
	return l.w.Write(p)
}

// updateInterval is how often a rule set is downloaded again.
func updateInterval(o *config.Object) time.Duration {
	interval := defaultUpdateInterval
	if v := o.Value.Get("update_interval"); v != nil {
		if parsed, err := time.ParseDuration(v.String); err == nil {
			interval = parsed
		}
	}
	return max(interval, minUpdateInterval)
}

// resourceLoop keeps remote rule sets fresh: on start, after every apply,
// and every resourceCheckInterval it downloads those missing from the
// cache or older than their interval. A rule set that just failed waits
// resourceRetryDelay before the next try.
func (d *Daemon) resourceLoop(ctx context.Context) {
	ticker := time.NewTicker(resourceCheckInterval)
	defer ticker.Stop()
	for {
		d.refreshResources()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-d.resWake:
		}
	}
}

func (d *Daemon) wakeResources() {
	select {
	case d.resWake <- struct{}{}:
	default:
	}
}

// refreshResources downloads remote rule sets and subscriptions missing
// from the cache or past their interval.
func (d *Daemon) refreshResources() {
	d.mu.Lock()
	cfg := d.cfg
	secrets := maps.Clone(d.secrets)
	attempts := maps.Clone(d.attempts)
	d.mu.Unlock()
	if cfg == nil {
		return
	}
	now := time.Now()
	for _, o := range cfg.RuleSets {
		if o.Type != "remote" {
			continue
		}
		if a, ok := attempts["rule_set:"+o.ID]; ok && a.err != nil && now.Sub(a.at) < resourceRetryDelay {
			continue
		}
		url, err := remoteURL(cfg, o, secrets)
		if err != nil {
			continue
		}
		marked := d.markedInvalid(d.ruleSetPath(o.ID, fingerprint(url, o.Value.Get("format").String)))
		if c, ok := d.ruleSetMeta(o, url); ok && now.Sub(c.FetchedAt) < updateInterval(o) && !marked {
			continue
		}
		_, _ = d.downloadRuleSet(cfg, o, secrets)
	}
	for _, o := range cfg.Subscriptions {
		if a, ok := attempts["subscription:"+o.ID]; ok && a.err != nil && now.Sub(a.at) < resourceRetryDelay {
			continue
		}
		url, err := remoteURL(cfg, o, secrets)
		if err != nil {
			continue
		}
		marked := d.markedInvalid(d.subscriptionPath(o.ID, subscriptionFingerprint(o, url)))
		if c, ok := d.subscriptionMeta(o, url); ok && now.Sub(c.FetchedAt) < updateInterval(o) && !marked {
			continue
		}
		_, _ = d.downloadSubscription(cfg, o, secrets)
	}
	d.res.Lock()
	d.collectRuleSets()
	d.collectSubscriptions()
	d.res.Unlock()
}

// RuleSetInfo is one rule set in rule-set list.
type RuleSetInfo struct {
	ID          string     `json:"id"`
	Name        string     `json:"name,omitempty"`
	Type        string     `json:"type"`
	Format      string     `json:"format,omitempty"`
	DownloadVia string     `json:"download_via,omitempty"`
	Cached      bool       `json:"cached"`
	Rules       int        `json:"rules"`
	FetchedAt   *time.Time `json:"fetched_at,omitempty"`
	ChangedAt   *time.Time `json:"changed_at,omitempty"`
	NextUpdate  *time.Time `json:"next_update,omitempty"`
	LastError   *cli.Error `json:"last_error,omitempty"`
}

func (d *Daemon) ruleSetList(json.RawMessage) reply {
	d.mu.Lock()
	cfg := d.cfg
	secrets := maps.Clone(d.secrets)
	attempts := maps.Clone(d.attempts)
	d.mu.Unlock()
	list := []RuleSetInfo{}
	if cfg != nil {
		for _, o := range cfg.RuleSets {
			info := RuleSetInfo{ID: o.ID, Name: o.Name, Type: o.Type}
			if o.Type == "inline" {
				info.Cached = true
				info.Rules = len(o.Value.Get("rules").Items)
				list = append(list, info)
				continue
			}
			info.Format = o.Value.Get("format").String
			info.DownloadVia = config.Direct
			if via := o.Value.Get("download_via"); via != nil {
				info.DownloadVia = via.String
			}
			if url, err := remoteURL(cfg, o, secrets); err == nil {
				if c, ok := d.ruleSetMeta(o, url); ok {
					next := c.FetchedAt.Add(updateInterval(o))
					info.Cached, info.Rules = true, c.Rules
					info.FetchedAt, info.ChangedAt, info.NextUpdate = &c.FetchedAt, &c.ChangedAt, &next
				}
			}
			if a, ok := attempts["rule_set:"+o.ID]; ok && a.err != nil {
				info.LastError = a.err
			}
			list = append(list, info)
		}
	}
	return reply{schema: SchemaRuleSetList, result: map[string]any{"rule_sets": list}}
}

// ruleSetUpdate downloads the named remote rule sets now, or all of them.
// It does not reload: new content takes effect at the next connect or
// scenario switch.
func (d *Daemon) ruleSetUpdate(params json.RawMessage) reply {
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
	var targets []*config.Object
	if len(p.IDs) == 0 {
		for _, o := range cfg.RuleSets {
			if o.Type == "remote" {
				targets = append(targets, o)
			}
		}
	}
	for _, id := range p.IDs {
		o := cfg.RuleSet(id)
		if o == nil {
			return reply{err: cli.Errorf(cli.CodeConfigConflict, "用 xdial rule-set list 查看有哪些规则集", "规则集 %q 不存在", id)}
		}
		if o.Type != "remote" {
			return reply{err: cli.Errorf(cli.CodeConfigConflict, "inline 规则集写在配置里，不用下载", "规则集 %q 不是远程规则集", id)}
		}
		targets = append(targets, o)
	}
	updated := []downloadResult{}
	var failed []string
	var first *cli.Error
	for _, o := range targets {
		r, err := d.downloadRuleSet(cfg, o, secrets)
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
		e.Message = fmt.Sprintf("%d 个规则集下载失败（%s）；其余 %d 个已更新", len(failed), strings.Join(failed, "；"), len(updated))
		return reply{err: &e}
	}
	return reply{schema: SchemaRuleSetUpdate, result: map[string]any{"updated": updated}}
}

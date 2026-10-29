// Package subscription turns what a subscription URL returns into nodes and
// rules, ARCHITECTURE.md 1.5. It understands Clash YAML, sing-box JSON and
// share links. The content is remote input: it is parsed in a child running
// as nobody, and what comes out is checked again by the daemon against the
// same classification as lines and rule sets.
package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ParseCommand is the hidden subcommand that parses one subscription.
const ParseCommand = "__subscription-parse"

// Limits on one subscription, ARCHITECTURE.md 1.5.
const (
	MaxSize     = 16 << 20
	MaxNodes    = 2000
	MaxRules    = 50000
	maxNameLen  = 256
	maxRuleLine = 4096
)

// Content is a parsed subscription, before the daemon's checks.
type Content struct {
	Format string `json:"format"`
	Nodes  []Node `json:"nodes"`
	Rules  []Rule `json:"rules"`
	// Unsupported counts what was left out, by kind and type, such as
	// "node:hysteria2" or "rule:GEOIP". Nothing is dropped unseen.
	Unsupported map[string]int `json:"unsupported,omitempty"`
}

// Node is one proxy of a subscription as sing-box outbound options, with
// no tag: the compiler names it.
type Node struct {
	Name     string          `json:"name"`
	Outbound json.RawMessage `json:"outbound"`
}

// Rule is one rule of a subscription: a sing-box headless rule and the
// policy the subscription sends it to, such as a proxy group's name.
type Rule struct {
	Policy string          `json:"policy"`
	Rule   json.RawMessage `json:"rule"`
}

func (c *Content) skip(kind, typ string) {
	if c.Unsupported == nil {
		c.Unsupported = map[string]int{}
	}
	typ = strings.ToLower(clean(typ))
	if typ == "" {
		typ = "unknown"
	}
	if len(typ) > 32 {
		typ = typ[:32]
	}
	c.Unsupported[kind+":"+typ]++
}

// ErrNoNodes is a subscription with nothing XDial can use.
var ErrNoNodes = errors.New("订阅里没有可用的节点")

// Parse detects the format of data and parses it.
func Parse(data []byte) (*Content, error) {
	if len(data) > MaxSize {
		return nil, fmt.Errorf("订阅超过 %d 字节", MaxSize)
	}
	data = bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF})
	trimmed := bytes.TrimSpace(data)
	var c *Content
	var err error
	switch {
	case len(trimmed) == 0:
		return nil, errors.New("订阅是空的")
	case trimmed[0] == '{':
		c, err = parseSingBox(trimmed)
	case looksLikeLinks(trimmed):
		c, err = parseLinks(trimmed)
	case looksLikeClash(trimmed):
		c, err = parseClash(trimmed)
	default:
		if decoded, ok := decodeBase64(trimmed); ok && looksLikeLinks(decoded) {
			c, err = parseLinks(decoded)
		} else {
			return nil, errors.New("认不出订阅的格式：支持 Clash、sing-box 和分享链接")
		}
	}
	if err != nil {
		return nil, err
	}
	if len(c.Nodes) == 0 {
		return c, ErrNoNodes
	}
	if len(c.Nodes) > MaxNodes {
		return nil, fmt.Errorf("节点超过 %d 个", MaxNodes)
	}
	if len(c.Rules) > MaxRules {
		return nil, fmt.Errorf("规则超过 %d 条", MaxRules)
	}
	dedupe(c.Nodes)
	return c, nil
}

// RunParseChild reads a subscription from stdin and writes its Content as
// JSON to stdout, or the reason it cannot on stderr.
func RunParseChild(stdin io.Reader, stdout, stderr io.Writer) int {
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		fmt.Fprintln(stderr, "订阅解析子进程不能以 root 运行")
		return 1
	}
	data, err := io.ReadAll(io.LimitReader(stdin, MaxSize+1))
	if err != nil {
		fmt.Fprintln(stderr, "读不到订阅内容")
		return 1
	}
	c, err := Parse(data)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(c); err != nil {
		return 1
	}
	return 0
}

// clean makes a name from remote text printable: control characters and
// invalid UTF-8 become spaces, and it is cut to maxNameLen bytes.
func clean(s string) string {
	s = strings.ToValidUTF8(s, " ")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' || unicode.Is(unicode.Bidi_Control, r) {
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > maxNameLen {
		s = s[:maxNameLen]
		for !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// dedupe makes node names unique, numbering repeats in order.
func dedupe(nodes []Node) {
	seen := map[string]int{}
	for i := range nodes {
		name := nodes[i].Name
		if name == "" {
			name = fmt.Sprintf("节点 %d", i+1)
		}
		base := name
		for seen[name] > 0 {
			seen[base]++
			name = fmt.Sprintf("%s (%d)", base, seen[base])
		}
		seen[name]++
		nodes[i].Name = name
	}
}

func decodeBase64(data []byte) ([]byte, bool) {
	s := strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, string(data))
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if out, err := enc.DecodeString(s); err == nil {
			return out, true
		}
	}
	return nil, false
}

func marshal(v any) json.RawMessage {
	out, _ := json.Marshal(v)
	return out
}

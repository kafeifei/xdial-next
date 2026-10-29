// Package config reads, checks and canonicalizes XDial configuration
// (ARCHITECTURE.md sections 1, 2 and 4). It never hands user text to
// sing-box: the strict parser here produces a tree whose keys are exactly
// what the user wrote, every check runs on that tree, and only the canonical
// JSON re-serialized from it moves on.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"unicode/utf8"
)

// Kind is the JSON type of a Value.
type Kind int

const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

func (k Kind) String() string {
	return [...]string{"null", "布尔值", "数字", "字符串", "数组", "对象"}[k]
}

// Value is one node of a parsed document. Object fields keep the order the
// user wrote them in.
type Value struct {
	Kind   Kind
	Bool   bool
	Number string // the literal, validated against the JSON grammar
	String string
	Items  []*Value
	Fields []*Field
	Line   int
	Column int
}

// Field is one key of an object.
type Field struct {
	Key   string
	Value *Value
	Line  int
}

// Get returns the value of key, or nil.
func (v *Value) Get(key string) *Value {
	if v == nil || v.Kind != KindObject {
		return nil
	}
	for _, f := range v.Fields {
		if f.Key == key {
			return f.Value
		}
	}
	return nil
}

// Limits on what the parser accepts, so a hostile document cannot exhaust
// memory or the stack of the root daemon.
const (
	MaxDocumentSize = 4 << 20
	maxDepth        = 64
	maxNodes        = 500_000
)

// SyntaxError is a document that is not JSON with comments.
type SyntaxError struct {
	Line, Column int
	Message      string
}

func (e *SyntaxError) Error() string {
	return fmt.Sprintf("第 %d 行第 %d 列：%s", e.Line, e.Column, e.Message)
}

// DuplicateKeyError is a key that appears twice in one object.
type DuplicateKeyError struct {
	Key  string
	Line int
}

func (e *DuplicateKeyError) Error() string {
	return fmt.Sprintf("第 %d 行：键 %q 重复", e.Line, e.Key)
}

// Parse reads JSON with //, # and /* */ comments and trailing commas. Keys
// are compared exactly; a duplicate key, invalid UTF-8, a byte order mark or
// a document deeper or larger than the limits is an error.
func Parse(data []byte) (*Value, error) {
	if len(data) > MaxDocumentSize {
		return nil, &SyntaxError{Line: 1, Column: 1, Message: fmt.Sprintf("文档超过 %d 字节", MaxDocumentSize)}
	}
	if !utf8.Valid(data) {
		line, column := position(data, invalidUTF8Offset(data))
		return nil, &SyntaxError{Line: line, Column: column, Message: "不是合法的 UTF-8"}
	}
	if bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		return nil, &SyntaxError{Line: 1, Column: 1, Message: "文档以字节顺序标记（BOM）开头"}
	}
	p := &parser{data: data, line: 1, column: 1}
	p.skipSpace()
	if p.err != nil {
		return nil, p.err
	}
	v := p.value(0)
	if p.err != nil {
		return nil, p.err
	}
	p.skipSpace()
	if p.err != nil {
		return nil, p.err
	}
	if p.pos < len(p.data) {
		p.fail("文档结束后还有内容")
		return nil, p.err
	}
	return v, nil
}

type parser struct {
	data   []byte
	nodes  int
	pos    int
	line   int
	column int
	err    error
}

// fail records the first error at the current position; parsing stops at
// the next check of p.err.
func (p *parser) fail(format string, args ...any) {
	if p.err == nil {
		p.err = &SyntaxError{Line: p.line, Column: p.column, Message: fmt.Sprintf(format, args...)}
	}
}

func (p *parser) advance(n int) {
	for i := 0; i < n && p.pos < len(p.data); i++ {
		if p.data[p.pos] == '\n' {
			p.line++
			p.column = 1
		} else if p.data[p.pos]&0xC0 != 0x80 {
			p.column++
		}
		p.pos++
	}
}

func (p *parser) peek() byte {
	if p.pos < len(p.data) {
		return p.data[p.pos]
	}
	return 0
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch c := p.data[p.pos]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.advance(1)
		case c == '#' || (c == '/' && p.pos+1 < len(p.data) && p.data[p.pos+1] == '/'):
			for p.pos < len(p.data) && p.data[p.pos] != '\n' {
				p.advance(1)
			}
		case c == '/' && p.pos+1 < len(p.data) && p.data[p.pos+1] == '*':
			p.advance(2)
			for {
				if p.pos+1 >= len(p.data) {
					p.fail("注释 /* 没有结束")
					return
				}
				if p.data[p.pos] == '*' && p.data[p.pos+1] == '/' {
					p.advance(2)
					break
				}
				p.advance(1)
			}
		default:
			return
		}
	}
}

func (p *parser) value(depth int) *Value {
	if depth > maxDepth {
		p.fail("嵌套超过 %d 层", maxDepth)
		return nil
	}
	if p.nodes++; p.nodes > maxNodes {
		p.fail("值超过 %d 个", maxNodes)
		return nil
	}
	v := &Value{Line: p.line, Column: p.column}
	switch c := p.peek(); {
	case c == '{':
		v.Kind = KindObject
		p.object(v, depth)
	case c == '[':
		v.Kind = KindArray
		p.array(v, depth)
	case c == '"':
		v.Kind = KindString
		v.String = p.str()
	case c == '-' || (c >= '0' && c <= '9'):
		v.Kind = KindNumber
		v.Number = p.number()
	case p.literal("true"):
		v.Kind, v.Bool = KindBool, true
	case p.literal("false"):
		v.Kind = KindBool
	case p.literal("null"):
		v.Kind = KindNull
	case c == 0:
		p.fail("文档意外结束")
	default:
		p.fail("这里应该是一个值")
	}
	return v
}

func (p *parser) literal(word string) bool {
	if !bytes.HasPrefix(p.data[p.pos:], []byte(word)) {
		return false
	}
	p.advance(len(word))
	return true
}

func (p *parser) object(v *Value, depth int) {
	p.advance(1)
	seen := map[string]bool{}
	for {
		p.skipSpace()
		if p.err != nil {
			return
		}
		if p.peek() == '}' {
			p.advance(1)
			return
		}
		if p.peek() != '"' {
			p.fail("这里应该是一个用双引号括起来的键")
			return
		}
		line := p.line
		key := p.str()
		if p.err != nil {
			return
		}
		if seen[key] {
			if p.err == nil {
				p.err = &DuplicateKeyError{Key: key, Line: line}
			}
			return
		}
		seen[key] = true
		p.skipSpace()
		if p.peek() != ':' {
			p.fail("键 %q 后面应该是冒号", key)
			return
		}
		p.advance(1)
		p.skipSpace()
		item := p.value(depth + 1)
		if p.err != nil {
			return
		}
		v.Fields = append(v.Fields, &Field{Key: key, Value: item, Line: line})
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.advance(1)
		case '}':
		default:
			p.fail("对象里的值后面应该是逗号或 }")
			return
		}
	}
}

func (p *parser) array(v *Value, depth int) {
	p.advance(1)
	for {
		p.skipSpace()
		if p.err != nil {
			return
		}
		if p.peek() == ']' {
			p.advance(1)
			return
		}
		item := p.value(depth + 1)
		if p.err != nil {
			return
		}
		v.Items = append(v.Items, item)
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.advance(1)
		case ']':
		default:
			p.fail("数组里的值后面应该是逗号或 ]")
			return
		}
	}
}

// str reads a string literal and returns its value. Escapes follow JSON and
// are decoded by encoding/json; unescaped control characters are rejected as
// JSON requires.
func (p *parser) str() string {
	start := p.pos
	p.advance(1)
	for {
		if p.pos >= len(p.data) {
			p.fail("字符串没有结束")
			return ""
		}
		c := p.data[p.pos]
		switch {
		case c == '"':
			p.advance(1)
			var s string
			if err := json.Unmarshal(p.data[start:p.pos], &s); err != nil {
				p.fail("字符串里有不合法的转义")
				return ""
			}
			return s
		case c == '\\':
			p.advance(2)
		case c < 0x20:
			p.fail("字符串里有没转义的控制字符")
			return ""
		default:
			p.advance(1)
		}
	}
}

func (p *parser) number() string {
	start := p.pos
	digits := func() int {
		n := 0
		for c := p.peek(); c >= '0' && c <= '9'; c = p.peek() {
			p.advance(1)
			n++
		}
		return n
	}
	if p.peek() == '-' {
		p.advance(1)
	}
	switch {
	case p.peek() == '0':
		p.advance(1)
	case digits() == 0:
		p.fail("数字格式不对")
		return ""
	}
	if p.peek() == '.' {
		p.advance(1)
		if digits() == 0 {
			p.fail("数字格式不对")
			return ""
		}
	}
	if c := p.peek(); c == 'e' || c == 'E' {
		p.advance(1)
		if c := p.peek(); c == '+' || c == '-' {
			p.advance(1)
		}
		if digits() == 0 {
			p.fail("数字格式不对")
			return ""
		}
	}
	return string(p.data[start:p.pos])
}

func invalidUTF8Offset(data []byte) int {
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		if r == utf8.RuneError && size == 1 {
			return i
		}
		i += size
	}
	return len(data)
}

func position(data []byte, offset int) (line, column int) {
	line, column = 1, 1
	for _, c := range data[:offset] {
		if c == '\n' {
			line++
			column = 1
		} else if c&0xC0 != 0x80 {
			column++
		}
	}
	return line, column
}

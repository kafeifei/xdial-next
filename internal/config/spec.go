package config

import (
	"fmt"
	"math"
	"net/netip"
	"net/url"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"time"

	"github.com/kafeifei/xdial-next/internal/cli"
)

// Class is how a field may be written, ARCHITECTURE.md 2.4.
type Class int

const (
	// Plain fields are written directly.
	Plain Class = iota
	// Secret fields must be a secret reference.
	Secret
	// MaybeSecret fields take plain text or a secret reference.
	MaybeSecret
	// Generated fields belong to XDial; writing one is rejected.
	Generated
	// Forbidden fields would grant a power section 2.1 withholds.
	Forbidden
)

func (c Class) String() string {
	return [...]string{"普通", "凭据", "可为凭据", "XDial 生成", "禁止"}[c]
}

type shape int

const (
	shapeString shape = iota
	shapeBool
	shapeInt
	shapeDuration
	shapeObject
	shapeArray
	shapeListable // a value or an array of them
	shapeMap      // an object whose keys are data
	shapeUnion    // an object whose fields depend on its "type"
	shapeFlag     // a bool, or an object when more than on/off is needed
)

// Spec says what one field may hold. Specs form a tree mirroring the JSON
// a type accepts; the tree is the classification table of section 2.4.
type Spec struct {
	Class Class
	Note  string // why a Generated or Forbidden field is not writable

	shape          shape
	enum           []string
	min, max       int64
	maxLen         int
	check          func(*Value) string // value domain beyond the shape; "" when fine
	fields         map[string]*Spec
	elem           *Spec
	variants       map[string]map[string]*Spec // shapeUnion, keyed by "type"
	defaultVariant string                      // shapeUnion: the variant of an object without "type"
	maxItems       int                         // arrays; 0 means the default cap
	required       bool                        // the field must be present in its object
	pattern        string                      // JSON Schema pattern, for strings whose check is a regular expression
	minLen         int
	isRegex        bool  // counted against the document's regular expression budget
	alt            *Spec // shapeString: an object that may stand in place of the string

	// Placeholder produces a well-formed stand-in for a secret so the
	// sing-box check never sees the real value, ARCHITECTURE.md 4.5. It may
	// look at the object the field sits in, as ss2022 keys depend on method.
	Placeholder func(parent *Value) string
	// Format checks a secret's real value without ever echoing it.
	Format func(value string, parent *Value) string
	// Ref names the namespace a string field refers to, such as "outbound".
	Ref string
}

// SecretUse is one place a secret reference appears.
type SecretUse struct {
	Name   string
	Path   string
	Object string
	Spec   *Spec
	Parent *Value
	Value  *Value // the {"secret": name} node, replaced on substitution
}

// RefUse is one string field that names another object.
type RefUse struct {
	Namespace string
	Target    string
	Path      string
	Object    string
}

type walker struct {
	// remote checks content from a remote: an unknown key is reported
	// without its name, in the path or the message, 3.4.
	remote bool
	// node checks a subscription node, ARCHITECTURE.md 1.5: credential
	// fields hold their values, and a secret reference is refused.
	node       bool
	problems   []cli.Problem
	dropped    int // problems past maxProblems, reported as a count
	regexInsts int // compiled size of every regular expression so far
	secrets    []SecretUse
	refs       []RefUse
	label      string
}

// maxProblems caps the list a check prints, so a hostile document cannot
// turn a few megabytes into millions of problems.
const maxProblems = 200

func (w *walker) problem(code, path, hint, format string, args ...any) {
	w.problemFor(w.label, code, path, hint, format, args...)
}

func (w *walker) problemFor(object, code, path, hint, format string, args ...any) {
	if len(w.problems) >= maxProblems {
		w.dropped++
		return
	}
	w.problems = append(w.problems, cli.Problem{
		Code: code, Path: path, Object: object, Message: fmt.Sprintf(format, args...), Hint: hint,
	})
}

func (w *walker) failed() bool { return len(w.problems) > 0 }

func joinKey(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

// object checks an object against a field table: every key must be in the
// table with exactly that spelling, and Generated or Forbidden keys are
// rejected as soon as they appear.
func (w *walker) object(v *Value, fields map[string]*Spec, path string) {
	if v.Kind != KindObject {
		w.problem(cli.CodeConfigValue, path, "", "应该是对象，这里是%s", v.Kind)
		return
	}
	for _, f := range v.Fields {
		fieldPath := joinKey(path, f.Key)
		spec, ok := fields[f.Key]
		if !ok {
			if w.remote {
				w.problem(cli.CodeConfigUnknownKey, joinKey(path, unknownKey), "", "没有登记的键")
				continue
			}
			w.problem(cli.CodeConfigUnknownKey, fieldPath, unknownKeyHint(f.Key, fields), "没有登记的键 %q", f.Key)
			continue
		}
		w.field(f.Value, spec, fieldPath, v)
	}
	for _, key := range sortedKeys(fields) {
		if fields[key].required && v.Get(key) == nil {
			w.problem(cli.CodeConfigValue, joinKey(path, key), "", "缺少必填的 %s", key)
		}
	}
}

// unknownKey stands for a key named by a remote in a problem's path.
const unknownKey = "<未登记的键>"

func sortedKeys(fields map[string]*Spec) []string {
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	return sortedStrings(keys)
}

func unknownKeyHint(key string, fields map[string]*Spec) string {
	for name := range fields {
		if strings.EqualFold(name, key) {
			return fmt.Sprintf("键名区分大小写，应该写成 %q", name)
		}
	}
	return "这个类型不支持这个字段，或者第一版还没开放它"
}

func (w *walker) field(v *Value, spec *Spec, path string, parent *Value) {
	switch spec.Class {
	case Generated:
		w.problem(cli.CodeConfigForbiddenKey, path, "删掉这个字段", "这个字段由 XDial 生成，不能写：%s", spec.Note)
		return
	case Forbidden:
		w.problem(cli.CodeConfigForbiddenKey, path, "删掉这个字段", "这个字段不允许写：%s", spec.Note)
		return
	case Secret, MaybeSecret:
		if w.node {
			if _, ok := secretRef(v); ok {
				w.problem(cli.CodeConfigValue, path, "", "订阅节点不能引用凭据")
				return
			}
			if v.Kind == KindString && spec.Format != nil {
				if msg := spec.Format(v.String, parent); msg != "" {
					w.problem(cli.CodeConfigValue, path, "", "%s", msg)
					return
				}
			}
			break
		}
		if name, ok := secretRef(v); ok {
			if !validID(name) {
				w.problem(cli.CodeConfigValue, joinKey(path, "secret"), "", "凭据名 %q 不合法：只能用小写字母、数字和连字符，以字母或数字开头，最长 63 个字符", name)
				return
			}
			w.secrets = append(w.secrets, SecretUse{Name: name, Path: path, Object: w.label, Spec: spec, Parent: parent, Value: v})
			return
		}
		if spec.Class == Secret {
			if v.Kind == KindObject && v.Get("secret") != nil {
				w.problem(cli.CodeConfigValue, path, `写成 {"secret": "<名字>"}，对象里只能有 secret 这一个键`, "凭据引用的格式不对")
			} else {
				w.problem(cli.CodeConfigSecretInline, path, `改成 {"secret": "<名字>"}，再用 xdial secret set <名字> 设置值`, "这是凭据字段，不能写明文")
			}
			return
		}
	}
	w.value(v, spec, path)
}

// secretRef recognizes {"secret": "name"} with nothing else in it.
func secretRef(v *Value) (string, bool) {
	if v.Kind != KindObject || len(v.Fields) != 1 || v.Fields[0].Key != "secret" || v.Fields[0].Value.Kind != KindString {
		return "", false
	}
	return v.Fields[0].Value.String, true
}

func (w *walker) value(v *Value, spec *Spec, path string) {
	if spec.alt != nil && v.Kind == KindObject {
		w.value(v, spec.alt, path)
		return
	}
	switch spec.shape {
	case shapeString:
		if v.Kind != KindString {
			w.problem(cli.CodeConfigValue, path, "", "应该是字符串，这里是%s", v.Kind)
			return
		}
		if spec.maxLen > 0 && len(v.String) > spec.maxLen {
			w.problem(cli.CodeConfigValue, path, "", "太长，最多 %d 字节", spec.maxLen)
			return
		}
		if len(spec.enum) > 0 && !contains(spec.enum, v.String) {
			w.problem(cli.CodeConfigValue, path, "可选的值："+strings.Join(spec.enum, "、"), "不支持的值 %q", v.String)
			return
		}
		if spec.Ref != "" {
			w.refs = append(w.refs, RefUse{Namespace: spec.Ref, Target: v.String, Path: path, Object: w.label})
		}
		if spec.isRegex {
			w.regex(v.String, path)
		}
	case shapeBool:
		if v.Kind != KindBool {
			w.problem(cli.CodeConfigValue, path, "", "应该是 true 或 false，这里是%s", v.Kind)
			return
		}
	case shapeInt:
		n, ok := integer(v)
		if !ok {
			w.problem(cli.CodeConfigValue, path, "", "应该是整数")
			return
		}
		if n < spec.min || n > spec.max {
			w.problem(cli.CodeConfigValue, path, "", "应该在 %d 到 %d 之间", spec.min, spec.max)
			return
		}
	case shapeDuration:
		if v.Kind != KindString {
			w.problem(cli.CodeConfigValue, path, `写成 "30s"、"5m" 这样的时长`, "应该是时长字符串，这里是%s", v.Kind)
			return
		}
		d, err := time.ParseDuration(v.String)
		if err != nil {
			w.problem(cli.CodeConfigValue, path, `写成 "30s"、"5m" 这样的时长`, "时长格式不对")
			return
		}
		// Written durations must be positive: sing-box panics on a negative
		// urltest interval the first time traffic uses the group.
		if d <= 0 {
			w.problem(cli.CodeConfigValue, path, "", "时长必须为正")
			return
		}
	case shapeObject:
		w.object(v, spec.fields, path)
		return
	case shapeArray, shapeListable:
		if v.Kind != KindArray {
			if spec.shape == shapeListable {
				w.field(v, spec.elem, path, nil)
				return
			}
			w.problem(cli.CodeConfigValue, path, "", "应该是数组，这里是%s", v.Kind)
			return
		}
		limit := spec.maxItems
		if limit == 0 {
			limit = defaultMaxItems
		}
		if len(v.Items) > limit {
			w.problem(cli.CodeConfigValue, path, "", "最多 %d 项，这里有 %d 项", limit, len(v.Items))
			return
		}
		for i, item := range v.Items {
			w.field(item, spec.elem, fmt.Sprintf("%s[%d]", path, i), v)
		}
	case shapeMap:
		if v.Kind != KindObject {
			w.problem(cli.CodeConfigValue, path, "", "应该是对象，这里是%s", v.Kind)
			return
		}
		for _, f := range v.Fields {
			if spec.check != nil {
				if msg := spec.check(&Value{Kind: KindString, String: f.Key}); msg != "" {
					w.problem(cli.CodeConfigValue, joinKey(path, f.Key), "", "键 %q 不合法：%s", f.Key, msg)
					continue
				}
			}
			w.field(f.Value, spec.elem, joinKey(path, f.Key), v)
		}
		return
	case shapeUnion:
		w.union(v, spec, path)
		return
	case shapeFlag:
		if v.Kind == KindBool {
			return
		}
		w.object(v, spec.fields, path)
		return
	}
	if spec.check != nil && spec.shape != shapeMap {
		if msg := spec.check(v); msg != "" {
			w.problem(cli.CodeConfigValue, path, "", "%s", msg)
		}
	}
}

func (w *walker) union(v *Value, spec *Spec, path string) {
	if v.Kind != KindObject {
		w.problem(cli.CodeConfigValue, path, "", "应该是对象，这里是%s", v.Kind)
		return
	}
	name := spec.defaultVariant
	if typ := v.Get("type"); typ != nil {
		if typ.Kind != KindString {
			w.problem(cli.CodeConfigValue, joinKey(path, "type"), "", "type 应该是字符串")
			return
		}
		name = typ.String
	} else if name == "" {
		w.problem(cli.CodeConfigValue, joinKey(path, "type"), "", "缺少 type")
		return
	}
	fields, ok := spec.variants[name]
	if !ok {
		names := make([]string, 0, len(spec.variants))
		for name := range spec.variants {
			names = append(names, name)
		}
		w.problem(cli.CodeConfigTypeNotAllowed, joinKey(path, "type"), "可选的类型："+strings.Join(sortedStrings(names), "、"), "类型 %q 不在允许清单里", name)
		return
	}
	w.object(v, fields, path)
}

func integer(v *Value) (int64, bool) {
	if v.Kind != KindNumber {
		return 0, false
	}
	n, err := strconv.ParseInt(v.Number, 10, 64)
	return n, err == nil
}

func contains(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// Spec constructors used by the tables in fields.go.

func str() *Spec                        { return &Spec{shape: shapeString, maxLen: 1024} }
func enum(values ...string) *Spec       { return &Spec{shape: shapeString, enum: values} }
func boolean() *Spec                    { return &Spec{shape: shapeBool} }
func duration() *Spec                   { return &Spec{shape: shapeDuration} }
func intRange(lo, hi int64) *Spec       { return &Spec{shape: shapeInt, min: lo, max: hi} }
func port() *Spec                       { return intRange(1, math.MaxUint16) }
func obj(fields map[string]*Spec) *Spec { return &Spec{shape: shapeObject, fields: fields} }
func listOf(elem *Spec) *Spec           { return &Spec{shape: shapeListable, elem: elem} }
func mapOf(key func(*Value) string, elem *Spec) *Spec {
	return &Spec{shape: shapeMap, check: key, elem: elem}
}
func flag(fields map[string]*Spec) *Spec { return &Spec{shape: shapeFlag, fields: fields} }
func union(defaultVariant string, variants map[string]map[string]*Spec) *Spec {
	return &Spec{shape: shapeUnion, variants: variants, defaultVariant: defaultVariant}
}
func ref(namespace string) *Spec { return &Spec{shape: shapeString, Ref: namespace, maxLen: 63} }

// req marks a spec as a required field.
func req(spec *Spec) *Spec {
	spec.required = true
	return spec
}

func generated(note string) *Spec { return &Spec{Class: Generated, Note: note} }
func forbidden(note string) *Spec { return &Spec{Class: Forbidden, Note: note} }

func checked(spec *Spec, check func(*Value) string) *Spec {
	spec.check = check
	return spec
}

func host() *Spec {
	return checked(&Spec{shape: shapeString, maxLen: 253}, func(v *Value) string {
		if v.String == "" {
			return "不能为空"
		}
		if _, err := netip.ParseAddr(v.String); err == nil {
			return ""
		}
		if !validHostname(v.String) {
			return "不是合法的域名或 IP 地址"
		}
		return ""
	})
}

var hostnameLabel = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		// A leading underscore is allowed for service names such as _sip.
		if hostnameLabel.MatchString(strings.TrimPrefix(label, "_")) {
			continue
		}
		return false
	}
	return true
}

// Regular expressions run inside the root daemon, so their number and size
// are capped, ARCHITECTURE.md 4.1.
const maxRegexLength = 512

// defaultMaxItems caps any array the tables do not size explicitly.
const defaultMaxItems = 1024

func regex() *Spec { return &Spec{shape: shapeString, maxLen: maxRegexLength, isRegex: true} }

// Regular expressions are budgeted by their compiled size, which is what
// both parsing here and matching in sing-box cost; a 512-byte pattern such
// as \pL{1000} repeated compiles to tens of thousands of instructions.
const (
	maxRegexInsts         = 4096
	maxDocumentRegexInsts = 65536
)

func (w *walker) regex(pattern, path string) {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		w.problem(cli.CodeConfigValue, path, "", "不是合法的正则表达式")
		return
	}
	prog, err := syntax.Compile(re.Simplify())
	if err != nil {
		w.problem(cli.CodeConfigValue, path, "", "不是合法的正则表达式")
		return
	}
	n := len(prog.Inst)
	if n > maxRegexInsts {
		w.problem(cli.CodeConfigValue, path, "拆成几条更简单的正则", "正则太复杂：编译后 %d 条指令，单条上限 %d", n, maxRegexInsts)
		return
	}
	before := w.regexInsts
	w.regexInsts += n
	if before <= maxDocumentRegexInsts && w.regexInsts > maxDocumentRegexInsts {
		w.problem(cli.CodeConfigValue, path, "减少正则的数量，能用 domain_suffix 的就不用正则", "整份配置的正则总量超过上限（编译后 %d 条指令）", maxDocumentRegexInsts)
	}
}

func cidr() *Spec {
	return checked(&Spec{shape: shapeString, maxLen: 64}, func(v *Value) string {
		if _, err := netip.ParsePrefix(v.String); err == nil {
			return ""
		}
		if _, err := netip.ParseAddr(v.String); err == nil {
			return ""
		}
		return "不是合法的 IP 网段"
	})
}

func portRange() *Spec {
	return checked(&Spec{shape: shapeString, maxLen: 16}, func(v *Value) string {
		lo, hi, ok := strings.Cut(v.String, ":")
		if !ok {
			return `端口范围写成 "1000:2000"、":3000" 或 "4000:"`
		}
		for _, part := range []string{lo, hi} {
			if part == "" {
				continue
			}
			if n, err := strconv.Atoi(part); err != nil || n < 0 || n > math.MaxUint16 {
				return "端口范围里的端口不合法"
			}
		}
		return ""
	})
}

func httpsURL() *Spec {
	return checked(&Spec{shape: shapeString, maxLen: 2048}, func(v *Value) string { return checkHTTPS(v.String) })
}

func checkHTTPS(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
		return "只能是带主机名的 https 地址，不能带用户名和密码"
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > math.MaxUint16 {
			return "端口不合法"
		}
	}
	return ""
}

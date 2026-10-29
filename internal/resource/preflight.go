package resource

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/bits"
)

// Limits of the bounded preflight a binary rule set passes before sing-box
// decodes it, ARCHITECTURE.md 3.4. sing-box allocates whatever lengths the
// file declares and expands every domain of its tries; these bound both.
const (
	maxInflated      = 32 << 20 // the zlib stream, decompressed
	maxExpanded      = 16 << 20 // every domain the tries expand to, in bytes
	maxDomains       = 1 << 20  // leaves of every trie
	maxDomainLength  = 512      // the longest key of a trie, also its depth
	maxPrefixes      = 1 << 20  // CIDR prefixes the IP sets expand to
	maxLogicalDepth  = 4        // as headless rules, internal/config
	maxBinaryRules   = 20000    // as rules of a rule set, internal/config
	maxBinaryVersion = 5        // sing-box's RuleSetVersionCurrent
)

var srsMagic = []byte("SRS")

// Item types of a default rule in sing-box's binary format.
const (
	itemQueryType = iota
	itemNetwork
	itemDomain
	itemDomainKeyword
	itemDomainRegex
	itemSourceIPCIDR
	itemIPCIDR
	itemSourcePort
	itemSourcePortRange
	itemPort
	itemPortRange
	itemProcessName
	itemProcessPath
	itemPackageName
	itemWIFISSID
	itemWIFIBSSID
	itemAdGuardDomain
	itemProcessPathRegex
	itemNetworkType
	itemNetworkIsExpensive
	itemNetworkIsConstrained
	itemNetworkInterfaceAddress
	itemDefaultInterfaceAddress
	itemPackageNameRegex
	itemFinal = 0xFF
)

// ErrAdGuard is a binary rule set with AdGuard conditions, which the source
// format cannot express: converting would drop them, 3.4.
var ErrAdGuard = errors.New("规则集含 AdGuard 条件，source 格式表达不了")

// errLimit marks a preflight failure caused by size, not by shape.
type errLimit struct{ msg string }

func (e *errLimit) Error() string { return e.msg }

// IsLimit reports whether a preflight error is about size.
func IsLimit(err error) bool {
	var l *errLimit
	return errors.As(err, &l)
}

// Preflight checks a binary rule set without decoding it: every length it
// declares fits in what is left of the file and in the limits above, and
// every trie is a well-formed tree. It returns nil only for a file sing-box
// can decode and expand within those limits.
func Preflight(data []byte) error {
	if len(data) < 4 || !bytes.Equal(data[:3], srsMagic) {
		return errors.New("不是 sing-box 的 binary 规则集")
	}
	if v := data[3]; v < 1 || v > maxBinaryVersion {
		return fmt.Errorf("binary 规则集的版本 %d 不认识", v)
	}
	z, err := zlib.NewReader(bytes.NewReader(data[4:]))
	if err != nil {
		return errors.New("binary 规则集的压缩数据损坏")
	}
	inflated, err := io.ReadAll(io.LimitReader(z, maxInflated+1))
	if err != nil {
		return errors.New("binary 规则集的压缩数据损坏")
	}
	if len(inflated) > maxInflated {
		return &errLimit{fmt.Sprintf("binary 规则集解压后超过 %d 字节", maxInflated)}
	}
	p := &preflight{b: inflated}
	n := p.count(3)
	if p.err == nil && n > maxBinaryRules {
		p.limit("规则超过 %d 条", maxBinaryRules)
	}
	for i := uint64(0); i < n && p.err == nil; i++ {
		p.rule(0)
	}
	if p.err == nil && len(p.b) > 0 {
		p.fail("规则之后还有多余的数据")
	}
	return p.err
}

type preflight struct {
	b        []byte
	err      error
	domains  int
	expanded int
	prefixes int
}

func (p *preflight) fail(format string, args ...any) {
	if p.err == nil {
		p.err = fmt.Errorf("binary 规则集格式不对："+format, args...)
	}
}

func (p *preflight) limit(format string, args ...any) {
	if p.err == nil {
		p.err = &errLimit{fmt.Sprintf("binary 规则集超出上限："+format, args...)}
	}
}

func (p *preflight) byte() byte {
	if p.err != nil {
		return 0
	}
	if len(p.b) == 0 {
		p.fail("数据提前结束")
		return 0
	}
	c := p.b[0]
	p.b = p.b[1:]
	return c
}

func (p *preflight) uvarint() uint64 {
	if p.err != nil {
		return 0
	}
	v, n := binary.Uvarint(p.b)
	if n <= 0 {
		p.fail("长度字段损坏")
		return 0
	}
	p.b = p.b[n:]
	return v
}

// count reads a declared count of elements of at least size bytes each and
// fails unless that many fit in what is left.
func (p *preflight) count(size int) uint64 {
	n := p.uvarint()
	if p.err == nil && n > uint64(len(p.b)/size) {
		p.fail("声明了 %d 个元素，剩下的数据装不下", n)
		return 0
	}
	return n
}

func (p *preflight) skip(n uint64) []byte {
	if p.err != nil {
		return nil
	}
	if n > uint64(len(p.b)) {
		p.fail("声明的长度超过剩下的数据")
		return nil
	}
	s := p.b[:n]
	p.b = p.b[n:]
	return s
}

func (p *preflight) rule(depth int) {
	switch p.byte() {
	case 0:
		p.defaultRule()
	case 1:
		if depth+1 >= maxLogicalDepth {
			p.limit("逻辑规则嵌套超过 %d 层", maxLogicalDepth)
			return
		}
		if mode := p.byte(); mode > 1 {
			p.fail("逻辑规则的模式 %d 不认识", mode)
		}
		n := p.count(3)
		for i := uint64(0); i < n && p.err == nil; i++ {
			p.rule(depth + 1)
		}
		p.byte() // invert
	default:
		p.fail("规则类型不认识")
	}
}

func (p *preflight) defaultRule() {
	for p.err == nil {
		switch item := p.byte(); item {
		case itemQueryType, itemPort, itemSourcePort:
			n := p.count(2)
			p.skip(2 * n)
		case itemNetwork, itemDomainKeyword, itemDomainRegex, itemSourcePortRange, itemPortRange,
			itemProcessName, itemProcessPath, itemProcessPathRegex, itemPackageName, itemPackageNameRegex,
			itemWIFISSID, itemWIFIBSSID:
			n := p.count(1)
			for i := uint64(0); i < n && p.err == nil; i++ {
				p.skip(p.uvarint())
			}
		case itemDomain:
			p.trie()
		case itemSourceIPCIDR, itemIPCIDR:
			p.ipSet()
		case itemAdGuardDomain:
			if p.err == nil {
				p.err = ErrAdGuard
			}
		case itemNetworkType:
			p.skip(p.count(1))
		case itemNetworkIsExpensive, itemNetworkIsConstrained:
		case itemNetworkInterfaceAddress:
			n := p.count(2)
			for i := uint64(0); i < n && p.err == nil; i++ {
				p.byte()
				p.prefixList()
			}
		case itemDefaultInterfaceAddress:
			p.prefixList()
		case itemFinal:
			p.byte() // invert
			return
		default:
			if p.err == nil {
				p.fail("条件类型 %d 不认识", item)
			}
		}
	}
}

func (p *preflight) prefixList() {
	n := p.count(2)
	for i := uint64(0); i < n && p.err == nil; i++ {
		size := p.uvarint()
		if p.err == nil && size != 4 && size != 16 {
			p.fail("地址长度 %d 不对", size)
		}
		p.skip(size)
		if b := p.byte(); p.err == nil && int(b) > 8*int(size) {
			p.fail("前缀长度 %d 超出地址", b)
		}
	}
}

// ipSet checks a set of address ranges and counts the CIDR prefixes they
// expand to when sing-box writes them out.
func (p *preflight) ipSet() {
	if v := p.byte(); p.err == nil && v != 1 {
		p.fail("IP 集合的版本 %d 不认识", v)
		return
	}
	raw := p.skip(8)
	if p.err != nil {
		return
	}
	n := binary.BigEndian.Uint64(raw)
	if n > uint64(len(p.b)/2) {
		p.fail("声明了 %d 个地址段，剩下的数据装不下", n)
		return
	}
	for i := uint64(0); i < n && p.err == nil; i++ {
		from := p.skip(p.uvarint())
		to := p.skip(p.uvarint())
		if p.err != nil {
			return
		}
		if (len(from) != 4 && len(from) != 16) || len(to) != len(from) || bytes.Compare(from, to) > 0 {
			p.fail("地址段不合法")
			return
		}
		p.prefixes += rangePrefixes(from, to, maxPrefixes-p.prefixes+1)
		if p.prefixes > maxPrefixes {
			p.limit("IP 地址段展开后超过 %d 个前缀", maxPrefixes)
		}
	}
}

// rangePrefixes counts the CIDR prefixes covering [from, to], stopping
// once it passes limit.
func rangePrefixes(from, to []byte, limit int) int {
	var lo, hi u128
	lo.set(from)
	hi.set(to)
	width := 8 * len(from)
	count := 0
	for count <= limit {
		// The largest block starting at lo that stays within hi.
		size := lo.trailingZeros(width)
		for size > 0 && lo.addPow(size).minusOne().greater(hi) {
			size--
		}
		count++
		end := lo.addPow(size).minusOne()
		if !end.less(hi) {
			break
		}
		lo = end.plusOne()
	}
	return count
}

// u128 is an address as a 128-bit number; IPv4 uses the low 32 bits.
type u128 struct{ hi, lo uint64 }

func (u *u128) set(b []byte) {
	var buf [16]byte
	copy(buf[16-len(b):], b)
	u.hi = binary.BigEndian.Uint64(buf[:8])
	u.lo = binary.BigEndian.Uint64(buf[8:])
}

func (u u128) trailingZeros(width int) int {
	n := 128
	if u.lo != 0 {
		n = bits.TrailingZeros64(u.lo)
	} else if u.hi != 0 {
		n = 64 + bits.TrailingZeros64(u.hi)
	}
	return min(n, width)
}

// addPow returns u + 2^k, saturating at the top of the space.
func (u u128) addPow(k int) u128 {
	var add u128
	if k >= 128 {
		return u128{^uint64(0), ^uint64(0)}.plusOne() // wraps to zero; callers subtract one
	}
	if k >= 64 {
		add.hi = 1 << (k - 64)
	} else {
		add.lo = 1 << k
	}
	lo, carry := bits.Add64(u.lo, add.lo, 0)
	hi, _ := bits.Add64(u.hi, add.hi, carry)
	return u128{hi, lo}
}

func (u u128) plusOne() u128 {
	lo, carry := bits.Add64(u.lo, 1, 0)
	return u128{u.hi + carry, lo}
}

func (u u128) minusOne() u128 {
	lo, borrow := bits.Sub64(u.lo, 1, 0)
	return u128{u.hi - borrow, lo}
}

func (u u128) less(v u128) bool    { return u.hi < v.hi || (u.hi == v.hi && u.lo < v.lo) }
func (u u128) greater(v u128) bool { return v.less(u) }

// trie checks one domain matcher: a succinct trie of reversed domains.
// Nodes are numbered breadth first; in the label bitmap each node lists one
// 0 bit per child edge and ends with a 1 bit, and labels holds one byte per
// edge. sing-box indexes all three without bounds checks while matching and
// expands every leaf to a full domain when converting, so the shape is
// checked here, and the expansion counted, before it ever sees the file.
func (p *preflight) trie() {
	p.byte() // the set's own version byte, unused by sing-box
	leaves := p.words()
	bitmap := p.words()
	labels := p.skip(p.uvarint())
	if p.err != nil {
		return
	}
	bit := func(words []byte, i int) bool {
		w := i >> 6
		if w >= len(words)/8 {
			return false
		}
		return binary.BigEndian.Uint64(words[8*w:])&(1<<uint(i&63)) != 0
	}
	totalBits := 8 * len(bitmap)
	nodes, edges := 1, 0
	idx := 0
	depth, levelEnd, nextLevel := 0, 1, 0
	for node := 0; node < nodes; node++ {
		if node == levelEnd {
			depth++
			levelEnd += nextLevel
			nextLevel = 0
			if depth > maxDomainLength {
				p.limit("域名超过 %d 个字符", maxDomainLength)
				return
			}
		}
		children := 0
		for ; idx < totalBits && !bit(bitmap, idx); idx++ {
			children++
		}
		if idx >= totalBits {
			p.fail("域名树的位图提前结束")
			return
		}
		idx++ // the 1 bit that ends this node's list
		edges += children
		nodes += children
		nextLevel += children
		if edges > len(labels) {
			p.fail("域名树的标签比边少")
			return
		}
		leaf := bit(leaves, node)
		switch {
		case leaf && node == 0:
			p.fail("域名树含空域名")
			return
		case leaf:
			p.domains++
			p.expanded += depth
			if p.domains > maxDomains || p.expanded > maxExpanded {
				p.limit("域名超过 %d 个或展开后超过 %d 字节", maxDomains, maxExpanded)
				return
			}
		case children == 0 && node != 0:
			p.fail("域名树有不通向任何域名的节点")
			return
		}
		// A prefix label, '\r' or '\n', marks a suffix rule. Node k is the
		// child of edge k-1. The label must end its key, which reversed
		// is the first byte of the domain sing-box writes out, and must
		// not be all of it: a key of the label alone expands to an empty
		// domain, which sing-box indexes and panics on.
		if node > 0 && (labels[node-1] == '\r' || labels[node-1] == '\n') && (children > 0 || depth < 2) {
			p.fail("域名树的后缀标记位置不对")
			return
		}
	}
	if edges != len(labels) {
		p.fail("域名树的标签和边数不一致")
		return
	}
	for ; idx < totalBits; idx++ {
		if bit(bitmap, idx) {
			p.fail("域名树的位图末尾有多余的位")
			return
		}
	}
	if 8*len(leaves) < nodes {
		p.fail("域名树的叶子位图短于节点数")
		return
	}
	for i := nodes; i < 8*len(leaves); i++ {
		if bit(leaves, i) {
			p.fail("域名树的叶子位图末尾有多余的位")
			return
		}
	}
}

// words reads a slice of big-endian uint64 and returns its raw bytes.
func (p *preflight) words() []byte {
	n := p.count(8)
	return p.skip(8 * n)
}

package resource

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func TestLimitsFollowSingBox(t *testing.T) {
	if maxBinaryVersion != C.RuleSetVersionCurrent || config.MaxRuleSetVersion != C.RuleSetVersionCurrent {
		t.Errorf("rule set versions: preflight %d, source %d, sing-box %d", maxBinaryVersion, config.MaxRuleSetVersion, C.RuleSetVersionCurrent)
	}
}

// encode writes rules in sing-box's binary format.
func encode(t *testing.T, version uint8, source string) []byte {
	t.Helper()
	var compat option.PlainRuleSetCompat
	if err := json.Unmarshal([]byte(source), &compat); err != nil {
		t.Fatal(err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := srs.Write(&buf, plain, version); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// raw builds a binary rule set from an inflated body, which tests craft
// by hand.
func raw(body []byte) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{'S', 'R', 'S', 3})
	z := zlib.NewWriter(&buf)
	_, _ = z.Write(body)
	_ = z.Close()
	return buf.Bytes()
}

func uv(n uint64) []byte { return binary.AppendUvarint(nil, n) }

func TestPreflightAcceptsWhatSingBoxWrites(t *testing.T) {
	sources := []string{
		`{"version": 1, "rules": [{"domain": ["a.example"], "domain_suffix": ["b.example", ".c.example"]}]}`,
		`{"version": 3, "rules": [{"domain_suffix": ["example.com", "example.org"], "domain_keyword": ["ads"], "domain_regex": ["^x\\d+\\.example$"]}]}`,
		`{"version": 3, "rules": [{"ip_cidr": ["10.0.0.0/8", "1.2.3.4/32", "2001:db8::/32"], "port": [80, 443], "port_range": ["1000:2000"]}]}`,
		`{"version": 3, "rules": [{"type": "logical", "mode": "and", "rules": [{"domain_suffix": ["x.example"]}, {"port": [443], "invert": true}]}]}`,
		`{"version": 3, "rules": [{"process_name": ["curl"], "network": ["tcp"], "source_port": [1]}, {"domain": ["only.example"], "invert": true}]}`,
	}
	for _, src := range sources {
		for _, version := range []uint8{C.RuleSetVersion1, C.RuleSetVersion2, C.RuleSetVersion3} {
			data := encode(t, version, src)
			if err := Preflight(data); err != nil {
				t.Errorf("v%d %s: %v", version, src, err)
				continue
			}
			var out, errOut bytes.Buffer
			if code := RunDecodeChild(bytes.NewReader(data), &out, &errOut); code != 0 {
				t.Errorf("v%d %s: decode failed: %s", version, src, errOut.String())
				continue
			}
			if _, problems := config.CheckRuleSetSource(out.Bytes()); len(problems) > 0 && !strings.Contains(src, "process_name") {
				t.Errorf("v%d %s: decoded source fails the checks: %v", version, src, problems)
			}
		}
	}
}

func TestPreflightAcceptsAnEmptyRuleSet(t *testing.T) {
	if err := Preflight(encode(t, 3, `{"version": 3, "rules": []}`)); err != nil {
		t.Error(err)
	}
}

func TestPreflightRejects(t *testing.T) {
	big := uv(1 << 40)
	cases := map[string][]byte{
		"magic":           []byte("SRX\x03"),
		"version zero":    append([]byte("SRS\x00"), raw(uv(0))[4:]...),
		"future version":  append([]byte("SRS\x09"), raw(uv(0))[4:]...),
		"not zlib":        []byte("SRS\x03garbage"),
		"rule count":      raw(big),
		"truncated":       raw(append(uv(1), 0)),
		"rule type":       raw(append(uv(1), 7)),
		"item type":       raw(append(uv(1), 0, 0x7E)),
		"string list":     raw(append(append(uv(1), 0, itemDomainKeyword), big...)),
		"string length":   raw(append(append(uv(1), 0, itemDomainKeyword, 1), big...)),
		"uint16 list":     raw(append(append(uv(1), 0, itemPort), big...)),
		"trailing data":   raw(append(uv(0), 1, 2, 3)),
		"logical mode":    raw(append(uv(1), 1, 9)),
		"ip set version":  raw(append(uv(1), 0, itemIPCIDR, 2)),
		"ip set count":    raw(append(append(uv(1), 0, itemIPCIDR, 1), 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF)),
		"ip range family": raw(ipSetBody([]byte{1, 2, 3, 4}, make([]byte, 16))),
		"ip range order":  raw(ipSetBody([]byte{10, 0, 0, 9}, []byte{10, 0, 0, 1})),
		"prefix length":   raw(append(append(uv(1), 0, itemDefaultInterfaceAddress), append(uv(1), append(uv(4), 1, 2, 3, 4, 40)...)...)),
	}
	for name, data := range cases {
		if err := Preflight(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func ipSetBody(from, to []byte) []byte {
	b := append(uv(1), 0, itemIPCIDR, 1)
	b = binary.BigEndian.AppendUint64(b, 1)
	b = append(append(b, uv(uint64(len(from)))...), from...)
	b = append(append(b, uv(uint64(len(to)))...), to...)
	return append(b, itemFinal, 0)
}

func TestPreflightRejectsAdGuard(t *testing.T) {
	// sing-box writes AdGuard conditions only when converting filter lists;
	// they have no source form.
	rule := option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{AdGuardDomain: []string{"||ads.example^"}}}
	var buf bytes.Buffer
	if err := srs.Write(&buf, option.PlainRuleSet{Rules: []option.HeadlessRule{rule}}, C.RuleSetVersion3); err != nil {
		t.Fatal(err)
	}
	if err := Preflight(buf.Bytes()); !errors.Is(err, ErrAdGuard) {
		t.Errorf("want ErrAdGuard, got %v", err)
	}
}

func TestPreflightBoundsLogicalDepth(t *testing.T) {
	inner := `{"domain": ["x.example"]}`
	for range maxLogicalDepth {
		inner = `{"type": "logical", "mode": "or", "rules": [` + inner + `]}`
	}
	if err := Preflight(encode(t, 3, `{"version": 3, "rules": [`+inner+`]}`)); !IsLimit(err) {
		t.Errorf("want a limit error, got %v", err)
	}
}

func TestPreflightBoundsInflatedSize(t *testing.T) {
	body := append(uv(1), 0, itemDomainKeyword, 1)
	body = append(body, uv(maxInflated)...)
	body = append(body, make([]byte, maxInflated)...)
	if err := Preflight(raw(body)); !IsLimit(err) {
		t.Errorf("want a limit error, got %v", err)
	}
}

func TestPreflightBoundsPrefixes(t *testing.T) {
	// Every range [::1, ffff:...:fffe] expands to 254 prefixes.
	n := maxPrefixes/254 + 1
	b := append(uv(1), 0, itemIPCIDR, 1)
	b = binary.BigEndian.AppendUint64(b, uint64(n))
	lo, hi := make([]byte, 16), bytes.Repeat([]byte{0xFF}, 16)
	lo[15], hi[15] = 1, 0xFE
	for range n {
		b = append(append(b, uv(16)...), lo...)
		b = append(append(b, uv(16)...), hi...)
	}
	b = append(b, itemFinal, 0)
	if err := Preflight(raw(b)); !IsLimit(err) {
		t.Errorf("want a limit error, got %v", err)
	}
}

func TestRangePrefixes(t *testing.T) {
	ip4 := func(a, b, c, d byte) []byte { return []byte{a, b, c, d} }
	full := bytes.Repeat([]byte{0xFF}, 16)
	lo, hi := make([]byte, 16), bytes.Repeat([]byte{0xFF}, 16)
	lo[15], hi[15] = 1, 0xFE
	cases := []struct {
		from, to []byte
		want     int
	}{
		{ip4(0, 0, 0, 0), ip4(255, 255, 255, 255), 1},
		{ip4(10, 0, 0, 0), ip4(10, 255, 255, 255), 1},
		{ip4(10, 0, 0, 1), ip4(10, 0, 0, 6), 4},
		{ip4(1, 2, 3, 4), ip4(1, 2, 3, 4), 1},
		{make([]byte, 16), full, 1},
		{lo, hi, 254},
	}
	for _, c := range cases {
		if got := rangePrefixes(c.from, c.to, 1000); got != c.want {
			t.Errorf("%v-%v: %d prefixes, want %d", c.from, c.to, got, c.want)
		}
	}
}

// trieBody is a rule with one domain item built from raw trie parts.
func trieBody(leaves, bitmap []uint64, labels string) []byte {
	b := append(uv(1), 0, itemDomain, 0)
	words := func(ws []uint64) {
		b = append(b, uv(uint64(len(ws)))...)
		for _, w := range ws {
			b = binary.BigEndian.AppendUint64(b, w)
		}
	}
	words(leaves)
	words(bitmap)
	b = append(append(b, uv(uint64(len(labels)))...), labels...)
	return append(b, itemFinal, 0)
}

func TestPreflightChecksTries(t *testing.T) {
	// One key "ab": root -a-> 1 -b-> 2, node 2 a leaf. Bitmap, node by
	// node: root 0 1, node 1 0 1, node 2 1 => bits 0,1,0,1,1 => 0b11010.
	if err := Preflight(raw(trieBody([]uint64{0b100}, []uint64{0b11010}, "ab"))); err != nil {
		t.Fatalf("a well-formed trie: %v", err)
	}
	cases := map[string][]byte{
		"empty domain":     raw(trieBody([]uint64{0b101}, []uint64{0b11010}, "ab")),
		"dangling node":    raw(trieBody([]uint64{0b000}, []uint64{0b11010}, "ab")),
		"short leaves":     raw(trieBody(nil, []uint64{0b11010}, "ab")),
		"missing labels":   raw(trieBody([]uint64{0b100}, []uint64{0b11010}, "a")),
		"extra labels":     raw(trieBody([]uint64{0b100}, []uint64{0b11010}, "abc")),
		"bitmap overrun":   raw(trieBody([]uint64{0b100}, []uint64{0b00010}, "ab")),
		"trailing bit":     raw(trieBody([]uint64{0b100}, []uint64{0b1011010}, "ab")),
		"extra leaf":       raw(trieBody([]uint64{0b1100}, []uint64{0b11010}, "ab")),
		"empty bitmap":     raw(trieBody([]uint64{0b1}, nil, "")),
		"suffix alone":     raw(trieBody([]uint64{0b10}, []uint64{0b110}, "\r")),
		"suffix mid-key":   raw(trieBody([]uint64{0b100}, []uint64{0b11010}, "\rb")),
		"declared too big": raw(append(append(uv(1), 0, itemDomain, 0), uv(1<<40)...)),
	}
	for name, data := range cases {
		if err := Preflight(data); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPreflightBoundsExpansion(t *testing.T) {
	// One chain of maxDomainLength+1 labels.
	n := maxDomainLength + 1
	leaves := make([]uint64, n/64+1)
	leaves[n/64] |= 1 << (n % 64)
	bits := make([]uint64, (2*n+1)/64+1)
	set := func(i int) { bits[i/64] |= 1 << (i % 64) }
	for i := range n {
		set(2*i + 1) // each node: one 0 bit (its child) then the 1 bit
	}
	set(2 * n)
	if err := Preflight(raw(trieBody(leaves, bits, strings.Repeat("a", n)))); !IsLimit(err) {
		t.Errorf("want a limit error, got %v", err)
	}
}

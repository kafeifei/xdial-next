package config

import (
	"context"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/schema"
)

// omitted lists the keys sing-box marks schema:"omit", which it does for
// deprecated fields; ARCHITECTURE.md 2.4 forbids every one of them.
func omitted(t reflect.Type) map[string]bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	keys := map[string]bool{}
	if t.Kind() != reflect.Struct {
		return keys
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		switch {
		case name == "" && f.Anonymous:
			for k := range omitted(f.Type) {
				keys[k] = true
			}
		case name != "" && name != "-" && f.Tag.Get("schema") == "omit":
			keys[name] = true
		}
	}
	return keys
}

// jsonKeys lists the JSON keys a sing-box option struct accepts, flattening
// embedded structs. Fields tagged json:"-" are variants merged by custom
// unmarshalling; callers that need them name them explicitly.
func jsonKeys(t reflect.Type) map[string]reflect.Type {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	keys := map[string]reflect.Type{}
	if t.Kind() != reflect.Struct {
		return keys
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := f.Tag.Get("json")
		name, _, _ := strings.Cut(tag, ",")
		switch {
		case name == "-":
		case name == "" && f.Anonymous:
			for k, v := range jsonKeys(f.Type) {
				keys[k] = v
			}
		case name != "":
			keys[name] = f.Type
		}
	}
	return keys
}

// schemaKeys lists the properties sing-box's own schema generator gives a
// type. It sees what reflection misses, such as variants merged behind
// json:"-", and misses what reflection sees, such as fields marked
// schema:"omit"; the table must classify the union of both.
func schemaKeys(t *testing.T, typ reflect.Type) map[string]bool {
	t.Helper()
	keys := map[string]bool{}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return keys
	}
	out, err := schema.Generate(context.Background(), typ)
	if err != nil {
		t.Fatalf("schema for %s: %v", typ, err)
	}
	var doc map[string]any
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	defs, _ := doc["$defs"].(map[string]any)
	var collect func(node map[string]any)
	collect = func(node map[string]any) {
		if ref, ok := node["$ref"].(string); ok {
			if def, ok := defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any); ok {
				collect(def)
			}
			return
		}
		if props, ok := node["properties"].(map[string]any); ok {
			for k := range props {
				keys[k] = true
			}
		}
		for _, branch := range []string{"anyOf", "oneOf", "allOf"} {
			if list, ok := node[branch].([]any); ok {
				for _, item := range list {
					if m, ok := item.(map[string]any); ok {
						collect(m)
					}
				}
			}
		}
	}
	collect(doc)
	return keys
}

// Keys XDial adds itself; they never reach sing-box.
var xdialOnly = map[string]bool{"id": true, "name": true, "download_via": true, "invert": true}

// compare checks that the table classifies every key of an upstream type and
// lists no key the type lacks. It recurses into fields the table lets users
// write as objects.
func compare(t *testing.T, path string, fields map[string]*Spec, typ reflect.Type, extra ...string) {
	t.Helper()
	upstream := jsonKeys(typ)
	for k := range schemaKeys(t, typ) {
		if _, ok := upstream[k]; !ok {
			upstream[k] = nil
		}
	}
	for _, k := range extra {
		upstream[k] = nil
	}
	for key := range omitted(typ) {
		if spec, ok := fields[key]; ok && spec.Class != Forbidden {
			t.Errorf("%s.%s: sing-box deprecates this field, so the table must forbid it", path, key)
		}
	}
	for key, ft := range upstream {
		spec, ok := fields[key]
		if !ok {
			t.Errorf("%s.%s: sing-box accepts this field but the table does not classify it", path, key)
			continue
		}
		if ft == nil || spec.Class == Generated || spec.Class == Forbidden {
			continue
		}
		switch spec.shape {
		case shapeObject, shapeFlag:
			compare(t, path+"."+key, spec.fields, ft)
		}
	}
	for key := range fields {
		if _, ok := upstream[key]; !ok && !xdialOnly[key] {
			t.Errorf("%s.%s: the table lists a field sing-box does not have", path, key)
		}
	}
}

func TestClassificationCoversSingBox(t *testing.T) {
	lines := lineSpec().variants
	upstream := map[string]any{
		"shadowsocks": option.ShadowsocksOutboundOptions{},
		"vmess":       option.VMessOutboundOptions{},
		"vless":       option.VLESSOutboundOptions{},
		"trojan":      option.TrojanOutboundOptions{},
		"anytls":      option.AnyTLSOutboundOptions{},
		"openconnect": option.OpenConnectEndpointOptions{},
		"tailscale":   option.TailscaleEndpointOptions{},
	}
	var allowed []string
	for name := range lines {
		allowed = append(allowed, name)
	}
	sort.Strings(allowed)
	for _, name := range allowed {
		v, ok := upstream[name]
		if !ok {
			t.Errorf("line type %s has no upstream type in this test", name)
			continue
		}
		// type and tag come from sing-box's Outbound and Endpoint wrappers.
		compare(t, name, lines[name], reflect.TypeOf(v), "type", "tag")
	}

	groups := groupSpec().variants
	compare(t, "selector", groups["selector"], reflect.TypeOf(option.SelectorOutboundOptions{}), "type", "tag")
	compare(t, "urltest", groups["urltest"], reflect.TypeOf(option.URLTestOutboundOptions{}), "type", "tag")

	// The transport's variants are merged by type behind json:"-" fields.
	transport := transportSpec().variants
	variants := map[string]any{
		"http":        option.V2RayHTTPOptions{},
		"ws":          option.V2RayWebsocketOptions{},
		"grpc":        option.V2RayGRPCOptions{},
		"httpupgrade": option.V2RayHTTPUpgradeOptions{},
	}
	for name, v := range variants {
		compare(t, "transport."+name, transport[name], reflect.TypeOf(v), "type")
	}
	// QUIC needs with_quic, which the first build leaves out.
	if _, ok := transport["quic"]; ok {
		t.Error("the quic transport needs with_quic, which ARCHITECTURE.md 2.3 leaves out")
	}

	rules := headlessRuleSpec(0).variants
	compare(t, "rule", rules["default"], reflect.TypeOf(option.DefaultHeadlessRule{}), "type")
	compare(t, "rule.logical", rules["logical"], reflect.TypeOf(option.LogicalHeadlessRule{}), "type")

	sets := ruleSetSpec().variants
	compare(t, "rule_set.inline", sets["inline"], reflect.TypeOf(option.PlainRuleSet{}), "type", "tag", "format")
	compare(t, "rule_set.remote", sets["remote"], reflect.TypeOf(option.RemoteRuleSet{}), "type", "tag", "format")
}

// TestNoXDialKeyShadowsAWritableField guards the stripping of XDial's own
// keys: one may only hide an upstream field users could not write anyway.
func TestNoXDialKeyShadowsAWritableField(t *testing.T) {
	types := []any{
		option.ShadowsocksOutboundOptions{}, option.VMessOutboundOptions{}, option.VLESSOutboundOptions{},
		option.TrojanOutboundOptions{}, option.AnyTLSOutboundOptions{}, option.OpenConnectEndpointOptions{},
		option.TailscaleEndpointOptions{}, option.SelectorOutboundOptions{}, option.URLTestOutboundOptions{},
		option.RemoteRuleSet{}, option.PlainRuleSet{},
	}
	for _, v := range types {
		for key := range jsonKeys(reflect.TypeOf(v)) {
			if xdialOnly[key] && key != "name" {
				t.Errorf("%T has a field %q that XDial's own key would hide", v, key)
			}
		}
	}
	// openconnect's name is its system interface name, forbidden with system.
	if _, ok := jsonKeys(reflect.TypeOf(option.OpenConnectEndpointOptions{}))["name"]; !ok {
		t.Log("openconnect no longer has a name field")
	}
}

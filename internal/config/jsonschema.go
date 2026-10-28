package config

import "sort"

// JSONSchema describes the configuration format as JSON Schema, generated
// from the classification table so the two cannot drift apart. Generated
// and forbidden fields are left out: they may not be written.
// `xdial schema` prints it, ARCHITECTURE.md 5.5.
func JSONSchema() map[string]any {
	root := objectSchema(documentSpec())
	root["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	root["title"] = "XDial configuration"
	return root
}

func secretRefSchema() map[string]any {
	return map[string]any{
		"type":                 "object",
		"properties":           map[string]any{"secret": map[string]any{"type": "string", "pattern": idPattern.String()}},
		"required":             []string{"secret"},
		"additionalProperties": false,
	}
}

func objectSchema(fields map[string]*Spec) map[string]any {
	props := map[string]any{}
	var required []string
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		s := fields[k]
		if s.Class == Generated || s.Class == Forbidden {
			continue
		}
		props[k] = specSchema(s)
		if s.required {
			required = append(required, k)
		}
	}
	out := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		out["required"] = required
	}
	return out
}

func specSchema(s *Spec) map[string]any {
	switch s.Class {
	case Secret:
		return secretRefSchema()
	case MaybeSecret:
		plain := *s
		plain.Class = Plain
		return map[string]any{"anyOf": []any{specSchema(&plain), secretRefSchema()}}
	}
	switch s.shape {
	case shapeString:
		out := map[string]any{"type": "string"}
		if len(s.enum) > 0 {
			out["enum"] = s.enum
		}
		if s.maxLen > 0 {
			out["maxLength"] = s.maxLen
		}
		if s.minLen > 0 {
			out["minLength"] = s.minLen
		}
		if s.pattern != "" {
			out["pattern"] = s.pattern
		}
		return out
	case shapeBool:
		return map[string]any{"type": "boolean"}
	case shapeInt:
		return map[string]any{"type": "integer", "minimum": s.min, "maximum": s.max}
	case shapeDuration:
		return map[string]any{"type": "string", "description": "正的时长，例如 30s、5m"}
	case shapeObject:
		return objectSchema(s.fields)
	case shapeFlag:
		return map[string]any{"anyOf": []any{map[string]any{"type": "boolean"}, objectSchema(s.fields)}}
	case shapeArray:
		return map[string]any{"type": "array", "items": specSchema(s.elem), "maxItems": maxItemsOf(s)}
	case shapeListable:
		elem := specSchema(s.elem)
		return map[string]any{"anyOf": []any{elem, map[string]any{"type": "array", "items": elem, "maxItems": maxItemsOf(s)}}}
	case shapeMap:
		return map[string]any{"type": "object", "additionalProperties": specSchema(s.elem)}
	case shapeUnion:
		names := make([]string, 0, len(s.variants))
		for name := range s.variants {
			names = append(names, name)
		}
		sort.Strings(names)
		var variants []any
		for _, name := range names {
			v := objectSchema(s.variants[name])
			props := v["properties"].(map[string]any)
			props["type"] = map[string]any{"const": name}
			if name != s.defaultVariant {
				v["required"] = appendUnique(v["required"], "type")
			}
			variants = append(variants, v)
		}
		return map[string]any{"oneOf": variants}
	}
	return map[string]any{}
}

func maxItemsOf(s *Spec) int {
	if s.maxItems > 0 {
		return s.maxItems
	}
	return defaultMaxItems
}

func appendUnique(list any, item string) []string {
	out, _ := list.([]string)
	for _, s := range out {
		if s == item {
			return out
		}
	}
	return append(out, item)
}

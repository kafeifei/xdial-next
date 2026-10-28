package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

// MarshalJSON writes the value as standard JSON, keeping the order object
// fields were written in. Strings go through encoding/json, so nothing in a
// value can break out of it.
func (v *Value) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	if err := v.encode(&buf, false); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (v *Value) encode(buf *bytes.Buffer, sorted bool) error {
	switch v.Kind {
	case KindNull:
		buf.WriteString("null")
	case KindBool:
		if v.Bool {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case KindNumber:
		buf.WriteString(v.Number)
	case KindString:
		b, err := json.Marshal(v.String)
		if err != nil {
			return err
		}
		buf.Write(b)
	case KindArray:
		buf.WriteByte('[')
		for i, item := range v.Items {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := item.encode(buf, sorted); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case KindObject:
		fields := v.Fields
		if sorted {
			fields = append([]*Field(nil), fields...)
			sort.Slice(fields, func(i, j int) bool { return fields[i].Key < fields[j].Key })
		}
		buf.WriteByte('{')
		for i, f := range fields {
			if i > 0 {
				buf.WriteByte(',')
			}
			key, err := json.Marshal(f.Key)
			if err != nil {
				return err
			}
			buf.Write(key)
			buf.WriteByte(':')
			if err := f.Value.encode(buf, sorted); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	}
	return nil
}

// Canonical is the form daemon stores and revisions are computed over:
// object keys sorted, no comments, no insignificant whitespace. It is
// defined here, not by sing-box's serializer, so upgrading sing-box cannot
// change a revision, ARCHITECTURE.md 4.1.
func (v *Value) Canonical() []byte {
	var buf bytes.Buffer
	_ = v.encode(&buf, true)
	return buf.Bytes()
}

// Revision is the digest of the canonical form.
func (v *Value) Revision() string {
	sum := sha256.Sum256(v.Canonical())
	return hex.EncodeToString(sum[:])
}

// Clone copies the value, replacing the nodes in replace with strings. It is
// how secret references become values: on the tree, never in text.
func (v *Value) Clone(replace map[*Value]string) *Value {
	if s, ok := replace[v]; ok {
		return &Value{Kind: KindString, String: s, Line: v.Line, Column: v.Column}
	}
	c := *v
	if v.Items != nil {
		c.Items = make([]*Value, len(v.Items))
		for i, item := range v.Items {
			c.Items[i] = item.Clone(replace)
		}
	}
	if v.Fields != nil {
		c.Fields = make([]*Field, len(v.Fields))
		for i, f := range v.Fields {
			c.Fields[i] = &Field{Key: f.Key, Value: f.Value.Clone(replace), Line: f.Line}
		}
	}
	return &c
}

// Without returns a shallow copy of an object without the given keys.
func (v *Value) Without(keys ...string) *Value {
	c := *v
	c.Fields = nil
	for _, f := range v.Fields {
		if !contains(keys, f.Key) {
			c.Fields = append(c.Fields, f)
		}
	}
	return &c
}

// With returns a shallow copy of an object with key set to value, replacing
// an existing field of that name.
func (v *Value) With(key string, value *Value) *Value {
	c := v.Without(key)
	c.Fields = append(c.Fields, &Field{Key: key, Value: value})
	return c
}

// String makes a string value.
func String(s string) *Value { return &Value{Kind: KindString, String: s} }

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/kafeifei/xdial-next/internal/cli"
	"github.com/kafeifei/xdial-next/internal/config"
	"github.com/kafeifei/xdial-next/internal/engine"
)

// The test binary doubles as the check child, as xdial itself does.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == engine.CheckCommand {
		os.Exit(engine.RunCheckChild(os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}

func execute(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, strings.NewReader(""), &out, &errOut)
	return code, out.String(), errOut.String()
}

// validate checks a document against the subset of JSON Schema that the
// schemas xdial prints use.
func validate(schema map[string]any, v any, path string) []string {
	var errs []string
	fail := func(format string, args ...any) { errs = append(errs, path+": "+fmt.Sprintf(format, args...)) }
	if c, ok := schema["const"]; ok && fmt.Sprint(c) != fmt.Sprint(v) {
		fail("want %v, got %v", c, v)
	}
	if enum, ok := schema["enum"]; ok {
		found := false
		for _, e := range toList(enum) {
			if fmt.Sprint(e) == fmt.Sprint(v) {
				found = true
			}
		}
		if !found {
			fail("%v is not in the enum", v)
		}
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		branches, ok := schema[key]
		if !ok {
			continue
		}
		matched := 0
		for _, b := range toList(branches) {
			if len(validate(toMap(b), v, path)) == 0 {
				matched++
			}
		}
		if matched == 0 || (key == "oneOf" && matched > 1) {
			fail("%d branches of %s match", matched, key)
		}
	}
	switch schema["type"] {
	case "object":
		obj, ok := v.(map[string]any)
		if !ok {
			fail("want an object")
			return errs
		}
		props := toMap(schema["properties"])
		for _, r := range toList(schema["required"]) {
			if _, ok := obj[r.(string)]; !ok {
				fail("missing %s", r)
			}
		}
		for k, item := range obj {
			if p, ok := props[k]; ok {
				errs = append(errs, validate(toMap(p), item, path+"."+k)...)
			} else if extra, ok := schema["additionalProperties"]; ok {
				if extra == false {
					fail("unexpected %s", k)
				} else if m, ok := extra.(map[string]any); ok {
					errs = append(errs, validate(m, item, path+"."+k)...)
				}
			}
		}
	case "array":
		list, ok := v.([]any)
		if !ok {
			fail("want an array")
			return errs
		}
		if items, ok := schema["items"]; ok {
			for i, item := range list {
				errs = append(errs, validate(toMap(items), item, fmt.Sprintf("%s[%d]", path, i))...)
			}
		}
	case "string":
		s, ok := v.(string)
		if !ok {
			fail("want a string")
		} else if p, ok := schema["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(s) {
			fail("%q does not match %s", s, p)
		}
	case "integer":
		if n, ok := v.(float64); !ok || n != float64(int64(n)) {
			fail("want an integer")
		}
	case "boolean":
		if _, ok := v.(bool); !ok {
			fail("want a boolean")
		}
	}
	return errs
}

func toMap(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func toList(v any) []any {
	switch l := v.(type) {
	case []any:
		return l
	case []string:
		out := make([]any, len(l))
		for i, s := range l {
			out[i] = s
		}
		return out
	}
	return nil
}

// roundTrip turns Go values into the generic form a decoded document has.
func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

// contract checks that a --json run printed exactly one document, valid
// against the schema xdial schema gives for it, and nothing on stderr.
func contract(t *testing.T, stdout, stderr string) map[string]any {
	t.Helper()
	if stderr != "" {
		t.Errorf("--json wrote to stderr: %q", stderr)
	}
	decoder := json.NewDecoder(strings.NewReader(stdout))
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		t.Fatalf("stdout is not JSON: %v: %q", err, stdout)
	}
	if decoder.More() {
		t.Errorf("stdout has more than one document: %q", stdout)
	}
	schemas := roundTrip(t, outputSchemas())
	schema, ok := schemas[fmt.Sprint(doc["schema"])]
	if !ok {
		t.Fatalf("no output schema for %v", doc["schema"])
	}
	for _, e := range validate(toMap(schema), doc, "$") {
		t.Error(e)
	}
	return doc
}

func TestUsageErrors(t *testing.T) {
	cases := [][]string{nil, {"nope"}, {"version", "--nope"}, {"version", "extra"}, {"config", "check"}, {"config", "check", "a", "b"}, {"version", "--json=1"}}
	for _, args := range cases {
		code, stdout, stderr := execute(args...)
		if code != cli.ExitUsage {
			t.Errorf("run(%q) = %d, want %d", args, code, cli.ExitUsage)
		}
		if stdout != "" || !strings.HasPrefix(stderr, "xdial: ") {
			t.Errorf("run(%q): stdout %q, stderr %q", args, stdout, stderr)
		}
		code, stdout, stderr = execute(append(args, "--json")...)
		if code != cli.ExitUsage {
			continue // --json may make the arguments valid
		}
		doc := contract(t, stdout, stderr)
		if doc["error"].(map[string]any)["code"] != cli.CodeUsage {
			t.Errorf("run(%q --json): %v", args, doc)
		}
	}
}

func TestVersion(t *testing.T) {
	code, stdout, stderr := execute("version", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	result := contract(t, stdout, stderr)["result"].(map[string]any)
	if result["os"] != runtime.GOOS || result["arch"] != runtime.GOARCH || result["sing_box"] == "" {
		t.Errorf("unexpected version info: %v", result)
	}
	code, stdout, _ = execute("version")
	if code != 0 || !strings.HasPrefix(stdout, "xdial ") {
		t.Errorf("text version: %d %q", code, stdout)
	}
}

func TestSchema(t *testing.T) {
	code, stdout, stderr := execute("schema", "--json")
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	result := contract(t, stdout, stderr)["result"].(map[string]any)
	outputs := result["outputs"].(map[string]any)
	for _, c := range result["commands"].([]any) {
		name := c.(map[string]any)["output_schema"].(string)
		if _, ok := outputs[name]; !ok {
			t.Errorf("command %v has no output schema %s", c, name)
		}
	}
	if _, ok := outputs[cli.ErrorSchema]; !ok {
		t.Error("the error envelope has no schema")
	}
	// The documented example must validate against the published format.
	data, err := os.ReadFile("../../internal/config/testdata/example.jsonc")
	if err != nil {
		t.Fatal(err)
	}
	v, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := v.MarshalJSON()
	var example any
	if err := json.Unmarshal(plain, &example); err != nil {
		t.Fatal(err)
	}
	for _, e := range validate(result["config"].(map[string]any), example, "$") {
		t.Error("example vs config schema:", e)
	}
}

func TestConfigCheck(t *testing.T) {
	example := "../../internal/config/testdata/example.jsonc"
	code, stdout, stderr := execute("config", "check", example, "--json")
	if code != 0 {
		t.Fatalf("exit %d: %s %s", code, stdout, stderr)
	}
	result := contract(t, stdout, stderr)["result"].(map[string]any)
	if len(result["secrets"].([]any)) != 5 || len(result["pending"].([]any)) == 0 {
		t.Errorf("unexpected report: %v", result)
	}
	// Options may come before the file too.
	if code, _, _ := execute("config", "check", "--json", example); code != 0 {
		t.Errorf("--json before the file: exit %d", code)
	}
	code, stdout, _ = execute("config", "check", example)
	if code != 0 || !strings.Contains(stdout, "配置没有问题") {
		t.Errorf("text check: %d %q", code, stdout)
	}
}

func TestConfigCheckProblems(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.jsonc")
	doc := `{"version": 1, "lines": [{"id": "hk", "type": "trojan", "server": "h.example", "server_port": 443, "password": "plain", "Bind_Interface": "en0\u001b[31m"}], "scenarios": [{"id": "s", "rules": [], "final": "nope"}]}`
	if err := os.WriteFile(bad, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := execute("config", "check", bad, "--json")
	if code != cli.ExitNegative {
		t.Fatalf("exit %d", code)
	}
	e := contract(t, stdout, stderr)["error"].(map[string]any)
	if e["code"] != cli.CodeConfigInvalid {
		t.Errorf("code %v", e["code"])
	}
	var got []string
	for _, p := range e["problems"].([]any) {
		got = append(got, p.(map[string]any)["code"].(string))
	}
	if s := strings.Join(got, " "); !strings.Contains(s, cli.CodeConfigSecretInline) || !strings.Contains(s, cli.CodeConfigUnknownKey) {
		t.Errorf("problems %s", s)
	}
	// Text output never carries a raw control character.
	_, _, stderr = execute("config", "check", bad)
	if strings.ContainsRune(stderr, 0x1b) {
		t.Error("text output carries an escape character")
	}
}

func TestConfigCheckInputErrors(t *testing.T) {
	code, stdout, stderr := execute("config", "check", filepath.Join(t.TempDir(), "missing.json"), "--json")
	if code != cli.ExitMissing || contract(t, stdout, stderr)["error"].(map[string]any)["code"] != cli.CodeInputRead {
		t.Errorf("missing file: exit %d %s", code, stdout)
	}
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	locked := filepath.Join(t.TempDir(), "locked.json")
	if err := os.WriteFile(locked, []byte("{}"), 0); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = execute("config", "check", locked, "--json")
	if code != cli.ExitPermission || contract(t, stdout, stderr)["error"].(map[string]any)["code"] != cli.CodeInputPermission {
		t.Errorf("unreadable file: exit %d %s", code, stdout)
	}
}

func TestEveryErrorCodeIsRegistered(t *testing.T) {
	// Fail must refuse an unregistered code rather than print it.
	var out bytes.Buffer
	code := cli.Output{Stdout: &out, JSON: true}.Fail(&cli.Error{Code: "made.up", Message: "x"})
	if code != cli.ExitInternal || !strings.Contains(out.String(), `"code":"internal"`) {
		t.Errorf("unregistered code printed: %d %s", code, out.String())
	}
}

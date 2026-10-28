package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEscape(t *testing.T) {
	cases := map[string]string{
		"plain 中文":       "plain 中文",
		"\x1b[31mred":    `\u001B[31mred`,
		"tab\there":      `tab\u0009here`,
		"bidi\u202eoops": "bidi\\u202Eoops",
		"back\\slash":    `back\\slash`,
		"bad\xffbyte":    `bad\xFFbyte`,
	}
	for in, want := range cases {
		if got := Escape(in); got != want {
			t.Errorf("Escape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFailJSON(t *testing.T) {
	var out, errOut bytes.Buffer
	o := Output{Stdout: &out, Stderr: &errOut, JSON: true}
	code := o.Fail(&Error{Code: CodeConfigInvalid, Message: "m", Problems: []Problem{{Code: CodeConfigValue, Message: "p"}, {Code: "made.up", Message: "q"}}})
	if code != ExitNegative || errOut.Len() != 0 {
		t.Fatalf("exit %d, stderr %q", code, errOut.String())
	}
	var doc struct {
		Schema string `json:"schema"`
		OK     bool   `json:"ok"`
		Error  Error  `json:"error"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != ErrorSchema || doc.OK || doc.Error.Problems[1].Code != CodeInternal {
		t.Errorf("unexpected document %+v", doc)
	}
}

func TestFailText(t *testing.T) {
	var out, errOut bytes.Buffer
	code := Output{Stdout: &out, Stderr: &errOut}.Fail(errors.New("boom"))
	if code != ExitInternal || out.Len() != 0 || !strings.HasPrefix(errOut.String(), "xdial: boom") {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}

func TestProblemCodesHaveNoExit(t *testing.T) {
	for _, c := range Codes() {
		if c.Problem == (c.Exit != 0) {
			t.Errorf("%s: problem codes carry no exit code and the others do", c.Name)
		}
	}
}

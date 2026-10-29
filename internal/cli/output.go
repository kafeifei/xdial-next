package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ErrorSchema is the schema every failure is printed with.
const ErrorSchema = "xdial.error/v1"

// Problem is one finding of a check. Path points at the offending value, as
// in lines[0].tls.server_name; Object names the object it belongs to, as in
// "line hk".
type Problem struct {
	Code    string `json:"code"`
	Path    string `json:"path,omitempty"`
	Object  string `json:"object,omitempty"`
	Message string `json:"message"`
	Hint    string `json:"hint,omitempty"`
}

// Error is what a command returns when it fails. Only registered codes may be
// printed; Fail turns anything else into an internal error.
type Error struct {
	Code     string    `json:"code"`
	Message  string    `json:"message"`
	Hint     string    `json:"hint,omitempty"`
	Problems []Problem `json:"problems,omitempty"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Message }

// Is reports whether err is an *Error with code.
func Is(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}

// Errorf builds an Error with a registered code.
func Errorf(code, hint, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...), Hint: hint}
}

type envelope struct {
	Schema string `json:"schema"`
	OK     bool   `json:"ok"`
	Result any    `json:"result,omitempty"`
	Error  *Error `json:"error,omitempty"`
}

// Output is where one command prints. In JSON mode exactly one document goes
// to stdout, for success and failure alike, and stderr stays silent.
type Output struct {
	Stdout io.Writer
	Stderr io.Writer
	JSON   bool
}

// Succeed prints a result. text prints the human form; it is not called in
// JSON mode.
func (o Output) Succeed(schema string, result any, text func(w io.Writer)) int {
	if o.JSON {
		if err := writeJSON(o.Stdout, envelope{Schema: schema, OK: true, Result: result}); err != nil {
			return ExitInternal
		}
		return ExitOK
	}
	if text != nil {
		text(o.Stdout)
	}
	return ExitOK
}

// Print writes one envelope as it is, for replies that arrive already
// enveloped, such as the daemon's.
func (o Output) Print(envelope any) int {
	if err := writeJSON(o.Stdout, envelope); err != nil {
		return ExitInternal
	}
	return ExitOK
}

// Fail prints an error and returns the exit code registered for it. An error
// that is not an *Error, or carries an unregistered code, is a defect and is
// printed as internal.
func (o Output) Fail(err error) int {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Code: CodeInternal, Message: err.Error()}
	}
	code, ok := Lookup(e.Code)
	if !ok || code.Problem {
		e = &Error{Code: CodeInternal, Message: "未登记的错误码 " + e.Code + "：" + e.Message}
		code, _ = Lookup(CodeInternal)
	}
	for i := range e.Problems {
		if p, ok := Lookup(e.Problems[i].Code); !ok || !p.Problem {
			e.Problems[i].Code = CodeInternal
		}
	}
	if e.Hint == "" {
		e.Hint = code.Hint
	}
	if o.JSON {
		if writeJSON(o.Stdout, envelope{Schema: ErrorSchema, OK: false, Error: e}) != nil {
			return ExitInternal
		}
		return code.Exit
	}
	fmt.Fprintln(o.Stderr, "xdial:", Escape(e.Message))
	for _, p := range e.Problems {
		where := p.Path
		if p.Object != "" {
			where = strings.TrimSpace(where + "（" + p.Object + "）")
		}
		if where != "" {
			fmt.Fprintf(o.Stderr, "  %s：%s\n", Escape(where), Escape(p.Message))
		} else {
			fmt.Fprintf(o.Stderr, "  %s\n", Escape(p.Message))
		}
		if p.Hint != "" {
			fmt.Fprintf(o.Stderr, "    提示：%s\n", Escape(p.Hint))
		}
	}
	if e.Hint != "" {
		fmt.Fprintln(o.Stderr, "提示："+Escape(e.Hint))
	}
	return code.Exit
}

func writeJSON(w io.Writer, v any) error {
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(v)
}

// Escape makes text that may come from outside, such as a subscription node
// name or a remote error, safe to print on a terminal: control and format
// characters become \uXXXX and invalid UTF-8 becomes \xXX, so they can neither
// rewrite the terminal nor pass for something else to an AI reading the
// output.
func Escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02X`, s[i])
		case r == '\\':
			b.WriteString(`\\`)
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r):
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

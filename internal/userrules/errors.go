package userrules

import (
	"fmt"
	"strconv"
)

// Error describes why client input was rejected. Line and Column are
// 1-based; Column counts Unicode characters, not bytes. Reason is plain
// English text that can be shown to the client.
type Error struct {
	Line   int
	Column int
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("line %d, column %d: %s", e.Line, e.Column, e.Reason)
}

type pos struct{ line, col int }

func errAt(p pos, format string, args ...any) *Error {
	return &Error{Line: p.line, Column: p.col, Reason: fmt.Sprintf(format, args...)}
}

// maxQuoted limits how much client text is echoed back in an error.
const maxQuoted = 64

// quote returns s as an ASCII-only quoted string, shortened if long, so error
// messages never carry control or invisible characters.
func quote(s string) string {
	if len(s) > maxQuoted {
		r := []rune(s)
		if len(r) > maxQuoted {
			s = string(r[:maxQuoted]) + "..."
		}
	}
	return strconv.QuoteToASCII(s)
}

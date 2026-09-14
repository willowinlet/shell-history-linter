package main

import (
	"fmt"
	"io"
	"strconv"
	"strings"
)

// printFinding renders one finding the way a compiler would: a summary
// line with file:line:col, then the offending source line with a caret
// underline under the exact span, then a help line. Position numbers on
// their own are cheap; forcing a reader to open the file and count
// columns to find a leaked key is not.
func printFinding(w io.Writer, f Finding) {
	fmt.Fprintf(w, "%s:%d:%d: %s [%s]: %s\n", f.File, f.Line, f.Col, f.Severity, f.Rule, f.Message)

	lineNoStr := strconv.Itoa(f.Line)
	gutter := strings.Repeat(" ", len(lineNoStr))

	fmt.Fprintf(w, "%s |\n", gutter)
	fmt.Fprintf(w, "%s | %s\n", lineNoStr, f.Source)

	underlineLen := f.Length
	if underlineLen < 1 {
		underlineLen = 1
	}
	pad := f.Col - 1
	if pad < 0 {
		pad = 0
	}
	caret := strings.Repeat(" ", pad) + strings.Repeat("^", underlineLen)
	fmt.Fprintf(w, "%s | %s\n", gutter, caret)

	if f.Help != "" {
		fmt.Fprintf(w, "%s = help: %s\n", gutter, f.Help)
	}
	fmt.Fprintln(w)
}

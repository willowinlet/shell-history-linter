package main

import (
	"encoding/json"
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

// jsonFinding is the wire shape for --json output. It mirrors Finding but
// spells the severity out as a string ("error"/"warning") since that's
// what a consumer parsing the output actually wants, not the underlying
// iota value.
type jsonFinding struct {
	File     string `json:"file"`
	Line     int    `json:"line"`
	Col      int    `json:"col"`
	Length   int    `json:"length"`
	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
	Help     string `json:"help,omitempty"`
	Source   string `json:"source"`
}

// printFindingsJSON writes every finding as a single JSON array, so a
// script consuming histlint output doesn't have to deal with one object
// per line or worry about the file being empty part way through.
func printFindingsJSON(w io.Writer, findings []Finding) error {
	out := make([]jsonFinding, len(findings))
	for i, f := range findings {
		out[i] = jsonFinding{
			File:     f.File,
			Line:     f.Line,
			Col:      f.Col,
			Length:   f.Length,
			Rule:     f.Rule,
			Severity: f.Severity.String(),
			Message:  f.Message,
			Help:     f.Help,
			Source:   f.Source,
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

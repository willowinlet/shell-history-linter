package main

import "sort"

type Severity int

const (
	SeverityWarning Severity = iota
	SeverityError
)

func (s Severity) String() string {
	if s == SeverityError {
		return "error"
	}
	return "warning"
}

// Finding is one reported issue. Col and Length are byte offsets into
// Source (1-based Col, to match how editors and compilers report
// position), so report.go can underline the exact span that triggered
// the rule instead of just naming a line.
type Finding struct {
	File     string
	Line     int
	Col      int
	Length   int
	Source   string
	Rule     string
	Severity Severity
	Message  string
	Help     string
}

type Rule struct {
	Name     string
	Severity Severity
	Check    func(e Entry) []Finding
}

func LintEntries(entries []Entry, file string) []Finding {
	var findings []Finding
	for _, rule := range allRules {
		for _, e := range entries {
			for _, f := range rule.Check(e) {
				f.File = file
				f.Rule = rule.Name
				f.Severity = rule.Severity
				findings = append(findings, f)
			}
		}
	}
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Col < findings[j].Col
	})
	return findings
}

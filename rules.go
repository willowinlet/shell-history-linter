package main

import (
	"regexp"
	"strings"
)

var allRules = []Rule{
	{
		Name:     "dangerous-rm",
		Severity: SeverityError,
		Check:    checkDangerousRemove,
	},
	{
		Name:     "pipe-to-shell",
		Severity: SeverityWarning,
		Check:    checkPipeToShell,
	},
	{
		Name:     "plaintext-secret",
		Severity: SeverityWarning,
		Check:    checkPlaintextSecret,
	},
}

// token is a whitespace-delimited slice of a command, with the byte
// offset it started at. Every rule needs offsets rather than plain
// strings.Fields because findings are reported at a column, and a
// dangerous token is rarely at the start of the line.
type token struct {
	text  string
	start int
}

func isSpace(b byte) bool {
	return b == ' ' || b == '\t'
}

// advancePastQuoteOrEscape looks at s[i] and, if it starts a backslash
// escape or a single/double-quoted span, returns the index just past it.
// Otherwise it returns i unchanged, leaving the caller to advance one byte
// itself. Both tokenize and splitPipe scan a command byte by byte and call
// this at every position so that whitespace or `|` inside quotes (or
// escaped with a backslash) doesn't get mistaken for a real delimiter.
func advancePastQuoteOrEscape(s string, i int) int {
	n := len(s)
	switch s[i] {
	case '\\':
		if i+1 < n {
			return i + 2
		}
		return i + 1
	case '\'':
		i++
		for i < n && s[i] != '\'' {
			i++
		}
		if i < n {
			i++
		}
		return i
	case '"':
		i++
		for i < n && s[i] != '"' {
			if s[i] == '\\' && i+1 < n {
				i += 2
				continue
			}
			i++
		}
		if i < n {
			i++
		}
		return i
	default:
		return i
	}
}

// unquoteWord strips backslash escapes and one layer of enclosing quotes,
// approximating what the shell would actually hand a program as an
// argument. It's applied before comparing a token against a fixed set like
// dangerousRemoveTargets, so that `rm -rf '/'` is still recognized even
// though the raw token text is `'/'`, not `/`.
func unquoteWord(s string) string {
	var b strings.Builder
	i, n := 0, len(s)
	for i < n {
		switch s[i] {
		case '\\':
			if i+1 < n {
				b.WriteByte(s[i+1])
				i += 2
			} else {
				i++
			}
		case '\'':
			i++
			for i < n && s[i] != '\'' {
				b.WriteByte(s[i])
				i++
			}
			if i < n {
				i++
			}
		case '"':
			i++
			for i < n && s[i] != '"' {
				if s[i] == '\\' && i+1 < n {
					b.WriteByte(s[i+1])
					i += 2
					continue
				}
				b.WriteByte(s[i])
				i++
			}
			if i < n {
				i++
			}
		default:
			b.WriteByte(s[i])
			i++
		}
	}
	return b.String()
}

func tokenize(s string) []token {
	var toks []token
	i, n := 0, len(s)
	for i < n {
		for i < n && isSpace(s[i]) {
			i++
		}
		if i >= n {
			break
		}
		start := i
		for i < n && !isSpace(s[i]) {
			if next := advancePastQuoteOrEscape(s, i); next != i {
				i = next
			} else {
				i++
			}
		}
		toks = append(toks, token{text: s[start:i], start: start})
	}
	return toks
}

// --- dangerous-rm ---------------------------------------------------

var dangerousRemoveTargets = map[string]bool{
	"/":       true,
	"/*":      true,
	"~":       true,
	"~/":      true,
	"~/*":     true,
	"$HOME":   true,
	"${HOME}": true,
	"*":       true,
}

func checkDangerousRemove(e Entry) []Finding {
	toks := tokenize(e.Command)
	var findings []Finding
	for i, t := range toks {
		base := unquoteWord(t.text)
		if idx := strings.LastIndexByte(base, '/'); idx >= 0 {
			base = base[idx+1:]
		}
		if base != "rm" {
			continue
		}

		hasRecursive, hasForce := false, false
		var args []token
		for _, t2 := range toks[i+1:] {
			if strings.HasPrefix(t2.text, "-") && t2.text != "-" && !strings.HasPrefix(t2.text, "--") {
				if strings.ContainsAny(t2.text, "rR") {
					hasRecursive = true
				}
				if strings.Contains(t2.text, "f") {
					hasForce = true
				}
				continue
			}
			switch t2.text {
			case "--recursive":
				hasRecursive = true
				continue
			case "--force":
				hasForce = true
				continue
			}
			if strings.HasPrefix(t2.text, "-") {
				continue
			}
			args = append(args, t2)
		}
		if !hasRecursive || !hasForce {
			continue
		}

		for _, a := range args {
			target := unquoteWord(a.text)
			if !dangerousRemoveTargets[target] {
				continue
			}
			line, col, source := e.resolve(a.start)
			findings = append(findings, Finding{
				Line:    line,
				Col:     col,
				Length:  len(a.text),
				Source:  source,
				Message: "recursive forced delete of " + target + " would wipe far more than one directory",
				Help:    "scope the path before rerunning this, e.g. `rm -rf -- ./specific/dir`, or drop -f and confirm each removal",
			})
		}
	}
	return findings
}

// --- pipe-to-shell ----------------------------------------------------

type segment struct {
	text   string
	offset int
}

func splitPipe(s string) []segment {
	var segs []segment
	start := 0
	i, n := 0, len(s)
	for i < n {
		if s[i] == '|' {
			segs = append(segs, segment{text: s[start:i], offset: start})
			i++
			start = i
			continue
		}
		if next := advancePastQuoteOrEscape(s, i); next != i {
			i = next
		} else {
			i++
		}
	}
	segs = append(segs, segment{text: s[start:], offset: start})
	return segs
}

var shellInterpreters = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
}

var fetchers = map[string]bool{
	"curl": true, "wget": true,
}

func checkPipeToShell(e Entry) []Finding {
	segs := splitPipe(e.Command)
	if len(segs) < 2 {
		return nil
	}

	var findings []Finding
	sawFetch := false
	for _, seg := range segs {
		toks := tokenize(seg.text)
		if len(toks) == 0 {
			continue
		}
		cmdTok := toks[0]
		if unquoteWord(cmdTok.text) == "sudo" && len(toks) > 1 {
			cmdTok = toks[1]
		}
		name := unquoteWord(cmdTok.text)
		if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
			name = name[idx+1:]
		}

		if fetchers[name] {
			sawFetch = true
			continue
		}
		if sawFetch && shellInterpreters[name] {
			line, col, source := e.resolve(seg.offset + cmdTok.start)
			findings = append(findings, Finding{
				Line:    line,
				Col:     col,
				Length:  len(cmdTok.text),
				Source:  source,
				Message: "output of curl/wget is piped straight into " + name + " without ever being inspected",
				Help:    "download to a file and read it first: the remote script can differ from what you reviewed by the time it runs again",
			})
		}
	}
	return findings
}

// --- plaintext-secret ---------------------------------------------------

var assignRe = regexp.MustCompile(`^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(\S*)`)
var secretNameRe = regexp.MustCompile(`(?i)(key|token|secret|password|passwd|credential)`)

var placeholderWords = []string{
	"changeme", "change_me", "xxx", "todo", "placeholder", "example",
	"yourkey", "your_key", "redacted", "insert_key_here", "fixme",
}

func looksLikeRealSecret(value string) bool {
	v := strings.Trim(value, `"'`)
	if len(v) < 8 {
		return false
	}
	if strings.HasPrefix(v, "$") || strings.HasPrefix(v, "<") {
		return false
	}
	lower := strings.ToLower(v)
	for _, p := range placeholderWords {
		if strings.Contains(lower, p) {
			return false
		}
	}
	return true
}

func checkPlaintextSecret(e Entry) []Finding {
	loc := assignRe.FindStringSubmatchIndex(e.Command)
	if loc == nil {
		return nil
	}
	name := e.Command[loc[2]:loc[3]]
	value := e.Command[loc[4]:loc[5]]

	if !secretNameRe.MatchString(name) {
		return nil
	}
	if !looksLikeRealSecret(value) {
		return nil
	}

	line, col, source := e.resolve(loc[4])
	return []Finding{{
		Line:    line,
		Col:     col,
		Length:  loc[5] - loc[4],
		Source:  source,
		Message: "value assigned to " + name + " looks like a live credential sitting in plaintext history",
		Help:    "history files are rarely encrypted and often synced or backed up; rotate this credential and load secrets from a gitignored env file instead",
	}}
}

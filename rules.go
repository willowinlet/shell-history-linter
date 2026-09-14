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
			i++
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
		base := t.text
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
			if !dangerousRemoveTargets[a.text] {
				continue
			}
			findings = append(findings, Finding{
				Line:    e.LineNo,
				Col:     e.CmdOffset + a.start + 1,
				Length:  len(a.text),
				Source:  e.Raw,
				Message: "recursive forced delete of " + a.text + " would wipe far more than one directory",
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
	for i := 0; i < len(s); i++ {
		if s[i] == '|' {
			segs = append(segs, segment{text: s[start:i], offset: start})
			start = i + 1
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
		if cmdTok.text == "sudo" && len(toks) > 1 {
			cmdTok = toks[1]
		}
		name := cmdTok.text
		if idx := strings.LastIndexByte(name, '/'); idx >= 0 {
			name = name[idx+1:]
		}

		if fetchers[name] {
			sawFetch = true
			continue
		}
		if sawFetch && shellInterpreters[name] {
			col := e.CmdOffset + seg.offset + cmdTok.start + 1
			findings = append(findings, Finding{
				Line:    e.LineNo,
				Col:     col,
				Length:  len(cmdTok.text),
				Source:  e.Raw,
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

	return []Finding{{
		Line:    e.LineNo,
		Col:     e.CmdOffset + loc[4] + 1,
		Length:  loc[5] - loc[4],
		Source:  e.Raw,
		Message: "value assigned to " + name + " looks like a live credential sitting in plaintext history",
		Help:    "history files are rarely encrypted and often synced or backed up; rotate this credential and load secrets from a gitignored env file instead",
	}}
}

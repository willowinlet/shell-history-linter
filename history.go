package main

import (
	"bufio"
	"io"
	"os"
	"regexp"
	"strings"
)

// Entry is one command pulled out of a history file, along with enough
// position information to point back at the exact byte in the original
// line. CmdOffset exists because zsh's extended history format prefixes
// every command with ": <epoch>:<duration>;" — findings need to point at
// a column in the command, not the raw line, but be reported against the
// raw line so the snippet in the report matches what's on disk.
//
// Command and CmdOffset always describe the first physical line, which
// covers the common case. zsh marks a command that was typed across
// several physical lines by ending every line but the last with a
// trailing backslash; those get folded into one Entry by parseHistory,
// with parts recording where each physical line landed so findings past
// the first line can still be resolved back to their own line and raw
// text.
type Entry struct {
	LineNo    int
	Raw       string
	Command   string
	CmdOffset int

	parts []linePart
}

// linePart is one physical history line that contributed to an Entry's
// Command. text is the slice of Command it contributed (zsh prefix and
// trailing continuation backslash already removed); offset is where text
// started within raw.
type linePart struct {
	lineNo int
	raw    string
	text   string
	offset int
}

// resolve maps a byte offset into e.Command back to the physical line,
// column, and raw source line it came from. Entries with a single part
// (the overwhelming majority) resolve with the same CmdOffset math the
// rules used before continuations existed; joined entries walk parts to
// find which physical line the offset actually landed on.
func (e Entry) resolve(offset int) (line int, col int, source string) {
	if len(e.parts) <= 1 {
		return e.LineNo, e.CmdOffset + offset + 1, e.Raw
	}
	start := 0
	for i, p := range e.parts {
		end := start + len(p.text)
		if offset < end || i == len(e.parts)-1 {
			return p.lineNo, p.offset + (offset - start) + 1, p.raw
		}
		start = end
	}
	last := e.parts[len(e.parts)-1]
	return last.lineNo, last.offset + 1, last.raw
}

var zshHistPrefix = regexp.MustCompile(`^: \d+:\d+;`)

func splitZshPrefix(raw string) (command string, offset int) {
	loc := zshHistPrefix.FindStringIndex(raw)
	if loc == nil {
		return raw, 0
	}
	return raw[loc[1]:], loc[1]
}

func ParseFile(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return parseHistory(f)
}

// readLines reads line by line with bufio.Reader rather than
// bufio.Scanner: history files occasionally contain single lines well
// past Scanner's default 64KB token limit (long piped commands, base64
// blobs typed at a prompt), and silently truncating those is worse than
// the small extra bookkeeping here. The final zero-length read that
// bufio.Reader produces once it hits EOF right after a trailing newline
// is not a real line and is dropped.
func readLines(r io.Reader) ([]string, error) {
	reader := bufio.NewReader(r)
	var lines []string
	for {
		raw, err := reader.ReadString('\n')
		raw = strings.TrimRight(raw, "\r\n")
		if err != nil {
			if err == io.EOF {
				if raw != "" {
					lines = append(lines, raw)
				}
				return lines, nil
			}
			return nil, err
		}
		lines = append(lines, raw)
	}
}

func parseHistory(r io.Reader) ([]Entry, error) {
	lines, err := readLines(r)
	if err != nil {
		return nil, err
	}

	var entries []Entry
	i := 0
	for i < len(lines) {
		raw := lines[i]
		lineNo := i + 1
		i++
		if raw == "" {
			continue
		}

		cmd, offset := splitZshPrefix(raw)
		parts := []linePart{{lineNo: lineNo, raw: raw, text: cmd, offset: offset}}

		for strings.HasSuffix(parts[len(parts)-1].text, "\\") && i < len(lines) {
			last := &parts[len(parts)-1]
			last.text = last.text[:len(last.text)-1]

			nextRaw := lines[i]
			nextLineNo := i + 1
			i++
			parts = append(parts, linePart{lineNo: nextLineNo, raw: nextRaw, text: nextRaw, offset: 0})
		}

		entries = append(entries, newEntry(parts))
	}
	return entries, nil
}

func newEntry(parts []linePart) Entry {
	var command strings.Builder
	for _, p := range parts {
		command.WriteString(p.text)
	}
	return Entry{
		LineNo:    parts[0].lineNo,
		Raw:       parts[0].raw,
		Command:   command.String(),
		CmdOffset: parts[0].offset,
		parts:     parts,
	}
}

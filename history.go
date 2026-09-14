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
type Entry struct {
	LineNo    int
	Raw       string
	Command   string
	CmdOffset int
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

// parseHistory reads line by line with bufio.Reader rather than
// bufio.Scanner: history files occasionally contain single lines well
// past Scanner's default 64KB token limit (long piped commands, base64
// blobs typed at a prompt), and silently truncating those is worse than
// the small extra bookkeeping here.
func parseHistory(r io.Reader) ([]Entry, error) {
	var entries []Entry
	reader := bufio.NewReader(r)
	lineNo := 0
	for {
		lineNo++
		raw, err := reader.ReadString('\n')
		raw = strings.TrimRight(raw, "\r\n")
		if raw != "" {
			cmd, offset := splitZshPrefix(raw)
			entries = append(entries, Entry{
				LineNo:    lineNo,
				Raw:       raw,
				Command:   cmd,
				CmdOffset: offset,
			})
		}
		if err != nil {
			if err == io.EOF {
				return entries, nil
			}
			return nil, err
		}
	}
}

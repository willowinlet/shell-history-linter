// Command histlint scans shell history files for things people usually
// regret leaving in them: plaintext credentials, curl-pipe-shell installs,
// and recursive forced deletes of paths like / or ~.
package main

import (
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: histlint <history-file> [more-files...]")
		os.Exit(2)
	}

	hadFindings := false
	hadError := false

	for _, path := range args {
		entries, err := ParseFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "histlint: %s: %v\n", path, err)
			hadError = true
			continue
		}

		findings := LintEntries(entries, path)
		for _, f := range findings {
			printFinding(os.Stdout, f)
		}
		if len(findings) > 0 {
			hadFindings = true
		}
	}

	switch {
	case hadError:
		os.Exit(2)
	case hadFindings:
		os.Exit(1)
	}
}

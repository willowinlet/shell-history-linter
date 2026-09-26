// Command histlint scans shell history files for things people usually
// regret leaving in them: plaintext credentials, curl-pipe-shell installs,
// and recursive forced deletes of paths like / or ~.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	jsonOutput := flag.Bool("json", false, "emit findings as a JSON array instead of compiler-style text")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: histlint [--json] <history-file> [more-files...]")
	}
	flag.Parse()

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		os.Exit(2)
	}

	hadFindings := false
	hadError := false
	allFindings := []Finding{}

	for _, path := range args {
		entries, err := ParseFile(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "histlint: %s: %v\n", path, err)
			hadError = true
			continue
		}

		findings := LintEntries(entries, path)
		if len(findings) > 0 {
			hadFindings = true
		}
		if *jsonOutput {
			allFindings = append(allFindings, findings...)
			continue
		}
		for _, f := range findings {
			printFinding(os.Stdout, f)
		}
	}

	if *jsonOutput {
		if err := printFindingsJSON(os.Stdout, allFindings); err != nil {
			fmt.Fprintf(os.Stderr, "histlint: %v\n", err)
			os.Exit(2)
		}
	}

	switch {
	case hadError:
		os.Exit(2)
	case hadFindings:
		os.Exit(1)
	}
}

// Command sast-rules-validate loads every JSON rule under one or more
// directories and reports schema/validation failures. CI gates rule PRs
// with this so a malformed rule never reaches the engine.
//
// Exits 0 when every rule loads + validates; exits 1 with a per-file
// error report otherwise.
//
//	$ sast-rules-validate internal/sast/rules/builtins
//	OK: 36 rule(s) validated
//
//	$ sast-rules-validate ./bad-rules
//	FAIL ./bad-rules/SC-X-Y-001.json: severity "urgent" is not one of critical|high|medium|low|info
//	1 of 5 rule(s) failed
//	(exit 1)
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

func main() {
	verbose := flag.Bool("v", false, "print every rule_id as it loads")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sast-rules-validate [-v] DIR [DIR...]")
		fmt.Fprintln(os.Stderr, "  Loads every *.json rule under each DIR and validates against the v2 schema.")
		fmt.Fprintln(os.Stderr, "  Exits 0 on full success, 1 if any rule fails.")
	}
	flag.Parse()

	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	totalLoaded := 0
	totalFailed := 0

	for _, dir := range flag.Args() {
		rs, err := rules.LoadFromDir(dir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %s\n", dir, err.Error())
			totalFailed++
			continue
		}

		// Stable iteration so CI logs diff cleanly run-over-run.
		sort.Slice(rs, func(i, j int) bool { return rs[i].RuleID < rs[j].RuleID })

		for _, r := range rs {
			if *verbose {
				fmt.Printf("  %s  [%s · %s · %s]\n", r.RuleID, r.Category, joinLanguages(r.Languages), r.Severity)
			}
			totalLoaded++
		}
		fmt.Printf("OK %s: %d rule(s)\n", dir, len(rs))
	}

	if totalFailed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d director(y/ies) failed validation\n", totalFailed)
		os.Exit(1)
	}
	fmt.Printf("\n%d rule(s) validated\n", totalLoaded)
}

func joinLanguages(langs []string) string {
	if len(langs) == 0 {
		return "(no language)"
	}
	out := langs[0]
	for _, l := range langs[1:] {
		out += "," + l
	}
	return out
}

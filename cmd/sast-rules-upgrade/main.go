// Command sast-rules-upgrade rewrites every JSON rule under the given
// directories in-place to the v2 on-disk shape: adds schema_version,
// category, and languages[] when they're missing, and normalizes legacy
// language aliases (js → javascript). Idempotent — running it twice is
// safe.
//
// This is a one-shot tool: once the builtins are upgraded, new rules
// should be authored as v2 from the start.
//
//	$ sast-rules-upgrade internal/sast/rules/builtins
//	upgraded: SC-JAVA-DESER-001 (added schema_version, category=deserialization)
//	upgraded: SC-JS-XSS-001    (added schema_version, category=xss)
//	already-v2: SC-PY-DESER-PICKLE-001
//	wrote 28 file(s); skipped 8 already on v2
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sentinelcore/sentinelcore/internal/sast/rules"
)

func main() {
	dryRun := flag.Bool("n", false, "dry-run: show what would change, don't write")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sast-rules-upgrade [-n] DIR [DIR...]")
		fmt.Fprintln(os.Stderr, "  Rewrites every *.json rule under DIR to v2 on-disk shape.")
		fmt.Fprintln(os.Stderr, "  Idempotent: rules already on v2 are left untouched.")
	}
	flag.Parse()
	if flag.NArg() == 0 {
		flag.Usage()
		os.Exit(2)
	}

	totalChanged := 0
	totalSkipped := 0

	for _, dir := range flag.Args() {
		var paths []string
		if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && strings.HasSuffix(p, ".json") {
				paths = append(paths, p)
			}
			return nil
		}); err != nil {
			fmt.Fprintf(os.Stderr, "walk %s: %v\n", dir, err)
			os.Exit(1)
		}
		sort.Strings(paths)

		for _, p := range paths {
			before, err := os.ReadFile(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "read %s: %v\n", p, err)
				os.Exit(1)
			}

			var rule rules.Rule
			if err := json.Unmarshal(before, &rule); err != nil {
				fmt.Fprintf(os.Stderr, "parse %s: %v\n", p, err)
				os.Exit(1)
			}
			alreadyV2 := rule.SchemaVersion == rules.CurrentSchemaVersion &&
				rule.Category != "" && len(rule.Languages) > 0

			rules.MigrateInPlace(&rule)
			// Drop the legacy `Language` field once Languages is populated so
			// the on-disk file is canonical v2 (no redundant fields).
			if len(rule.Languages) > 0 {
				rule.Language = ""
			}
			if err := rules.Validate(&rule); err != nil {
				fmt.Fprintf(os.Stderr, "validate after migrate %s: %v\n", p, err)
				os.Exit(1)
			}

			after, err := json.MarshalIndent(&rule, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "marshal %s: %v\n", p, err)
				os.Exit(1)
			}
			after = append(after, '\n')

			if alreadyV2 && string(before) == string(after) {
				fmt.Printf("already-v2: %s\n", p)
				totalSkipped++
				continue
			}

			fmt.Printf("upgraded:   %s\n", p)
			if !*dryRun {
				if err := os.WriteFile(p, after, 0o644); err != nil {
					fmt.Fprintf(os.Stderr, "write %s: %v\n", p, err)
					os.Exit(1)
				}
			}
			totalChanged++
		}
	}

	mode := "wrote"
	if *dryRun {
		mode = "would write"
	}
	fmt.Printf("\n%s %d file(s); skipped %d already on v2\n", mode, totalChanged, totalSkipped)
}

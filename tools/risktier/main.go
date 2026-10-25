// Command risktier puts a pull request into a risk tier from the paths it
// changes. The rules live in .github/risk-tiers.json; see docs/agent/loop.md.
//
//	gh pr diff 12 --name-only | go run ./tools/risktier -config .github/risk-tiers.json
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	configPath := flag.String("config", ".github/risk-tiers.json", "tier rules")
	verbose := flag.Bool("v", false, "explain each path on stderr")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "risktier:", err)
		os.Exit(1)
	}
	r, err := parseRules(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "risktier: %s: %v\n", *configPath, err)
		os.Exit(1)
	}
	paths, err := readPaths(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stderr, "risktier:", err)
		os.Exit(1)
	}

	tier, reasons := r.classify(paths)
	if *verbose {
		for _, reason := range reasons {
			fmt.Fprintln(os.Stderr, reason)
		}
	}
	fmt.Println(tier)
}

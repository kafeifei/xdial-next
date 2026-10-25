// Command reviewround decides what a run of the AI review should do and keeps
// the per-PR review record, a comment that github-actions[bot] maintains on
// the pull request. Rules: docs/agent/loop.md.
//
//	reviewround last   -comment record.md
//	reviewround decide -comment record.md -head SHA -changes N -tier T [-allow-more] [-recheck]
//	reviewround record -comment record.md -head SHA -round N -ai VERDICT -security VERDICT [-sync]
//
// -changes is 0 when the head only merged main since the last reviewed head,
// 1 when the author changed something, and -1 when that cannot be told.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: reviewround last|decide|record [flags]"))
	}
	command, args := os.Args[1], os.Args[2:]
	flags := flag.NewFlagSet(command, flag.ExitOnError)
	commentPath := flags.String("comment", "", "file holding the current review record comment, possibly empty")
	head := flags.String("head", "", "head commit of the pull request")
	changes := flags.Int("changes", -1, "0: only merged main, 1: author changes, -1: unknown")
	tier := flags.String("tier", "", "risk tier of the pull request")
	allowMore := flags.Bool("allow-more", false, "the owner allowed rounds beyond the limit")
	recheck := flags.Bool("recheck", false, "re-check the author's replies on unchanged code")
	round := flags.Int("round", 0, "round being recorded")
	ai := flags.String("ai", "", "AI review verdict being recorded")
	security := flags.String("security", "", "security review verdict being recorded")
	sync := flags.Bool("sync", false, "the head only merged main since the last record")
	if err := flags.Parse(args); err != nil {
		fail(err)
	}

	r, err := readRecord(*commentPath)
	if err != nil {
		fail(err)
	}
	switch command {
	case "last":
		fmt.Println(r.lastHead())
	case "decide":
		if *head == "" || (*tier != "low" && *tier != "medium" && *tier != "high") {
			fail(errors.New("decide needs -head and -tier low|medium|high"))
		}
		in := input{Head: *head, Changes: *changes, AllowMore: *allowMore, Recheck: *recheck, Tier: *tier}
		out, err := json.Marshal(r.decide(in))
		if err != nil {
			fail(err)
		}
		fmt.Println(string(out))
	case "record":
		e := entry{SHA: *head, Round: *round, AI: *ai, Security: *security, Sync: *sync}
		if err := e.validate(); err != nil {
			fail(err)
		}
		r.add(e)
		body, err := r.render()
		if err != nil {
			fail(err)
		}
		fmt.Print(body)
	default:
		fail(fmt.Errorf("unknown command %q", command))
	}
}

func readRecord(path string) (*record, error) {
	if path == "" {
		return &record{}, nil
	}
	body, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &record{}, nil
	}
	if err != nil {
		return nil, err
	}
	return parseRecord(string(body))
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "reviewround:", err)
	os.Exit(1)
}

package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	marker    = "<!-- xdial-review-state "
	markerEnd = " -->"

	verdictPass    = "pass"
	verdictChanges = "changes-requested"
	verdictNone    = "n/a" // security review does not apply below the high tier

	scopeFull    = "full"    // the whole pull request
	scopeSince   = "since"   // the author's changes since the last reviewed head
	scopeReplies = "replies" // same code; re-check the author's replies only
)

// maxRoundsWithoutConsent is the last round that may follow a failed round
// without the owner's allow-more-rounds label.
const maxRoundsWithoutConsent = 3

type entry struct {
	SHA      string `json:"sha"`
	Round    int    `json:"round"`
	AI       string `json:"ai"`
	Security string `json:"security"`
	Sync     bool   `json:"sync,omitempty"`
}

type record struct {
	Entries []entry `json:"entries"`
}

type decision struct {
	// Action is "review" to run at least one reviewer, "reuse" to carry
	// over the verdicts below, or "stop" when the round limit is reached.
	Action        string `json:"action"`
	Round         int    `json:"round"`
	RunAI         bool   `json:"run_ai"`
	RunSecurity   bool   `json:"run_security"`
	AIScope       string `json:"ai_scope"`
	SecurityScope string `json:"security_scope"`
	// Since is the last reviewed head that a "since" scope starts from.
	Since string `json:"since"`
	// AI and Security are the verdicts carried over for reviewers that do
	// not run.
	AI       string `json:"ai"`
	Security string `json:"security"`
	// Record is set when the caller must store an entry for this head.
	Record bool `json:"record"`
	Sync   bool `json:"sync"`
}

// input describes the pull request as the review workflow sees it.
type input struct {
	Head string
	// Changes is 0 when the head only merged main since the last reviewed
	// head, 1 when the author changed something, and -1 when that cannot be
	// told, for example after a force push.
	Changes   int
	AllowMore bool // the owner allowed rounds beyond the limit
	Recheck   bool // re-check the author's replies on unchanged code
	Tier      string
}

func parseRecord(body string) (*record, error) {
	start := strings.Index(body, marker)
	if start < 0 {
		return &record{}, nil
	}
	rest := body[start+len(marker):]
	end := strings.Index(rest, markerEnd)
	if end < 0 {
		return nil, fmt.Errorf("review record marker is not closed")
	}
	var r record
	if err := json.Unmarshal([]byte(rest[:end]), &r); err != nil {
		return nil, fmt.Errorf("review record: %w", err)
	}
	for _, e := range r.Entries {
		if err := e.validate(); err != nil {
			return nil, fmt.Errorf("review record: %w", err)
		}
	}
	return &r, nil
}

func (r *record) lastHead() string {
	if len(r.Entries) == 0 {
		return ""
	}
	return r.Entries[len(r.Entries)-1].SHA
}

// lastSecurity is the security verdict of the last reviewed head, or n/a
// when nothing was reviewed yet.
func (r *record) lastSecurity() string {
	if len(r.Entries) == 0 {
		return verdictNone
	}
	return r.Entries[len(r.Entries)-1].Security
}

func (r *record) decide(in input) decision {
	high := in.Tier == "high"
	d := r.decideAI(in)
	if !high {
		d.RunSecurity, d.SecurityScope, d.Security = false, "", verdictNone
		return d
	}
	switch {
	case d.Action == "stop":
	case d.AIScope == scopeReplies:
		// Re-checking replies re-runs security only where it is not settled.
		switch d.Security {
		case verdictNone:
			d.RunSecurity, d.SecurityScope = true, scopeFull
		case verdictChanges:
			d.RunSecurity, d.SecurityScope = true, scopeReplies
		}
	case d.RunAI:
		// A new round reviews security along with the code. When the last
		// head was not security-reviewed (the tier was below high), the
		// incremental changes do not cover what came in meanwhile, so the
		// security review covers the whole pull request.
		d.RunSecurity = true
		d.SecurityScope = d.AIScope
		if d.AIScope == scopeSince && r.lastSecurity() == verdictNone {
			d.SecurityScope = scopeFull
		}
	case d.Security == verdictNone:
		// The tier rose to high since the carried verdict was given.
		d.Action, d.Record, d.RunSecurity, d.SecurityScope = "review", true, true, scopeFull
	}
	return d
}

func (r *record) decideAI(in input) decision {
	for _, e := range r.Entries {
		if e.SHA == in.Head {
			return carry(e, in.Recheck, false)
		}
	}
	if len(r.Entries) == 0 {
		return decision{Action: "review", Round: 1, RunAI: true, AIScope: scopeFull, Record: true}
	}
	last := r.Entries[len(r.Entries)-1]
	if in.Changes == 0 {
		return carry(last, in.Recheck, true)
	}
	round := last.Round + 1
	failed := last.AI == verdictChanges || last.Security == verdictChanges
	if round > maxRoundsWithoutConsent && failed && !in.AllowMore {
		return decision{Action: "stop", Round: round, Since: last.SHA}
	}
	scope := scopeSince
	if round <= 2 || in.Changes < 0 {
		scope = scopeFull
	}
	return decision{Action: "review", Round: round, RunAI: true, AIScope: scope, Since: last.SHA, Record: true}
}

// carry reuses the verdicts of e for a head whose code e already covers,
// or re-checks the author's replies on that code when asked to.
func carry(e entry, recheck, sync bool) decision {
	d := decision{Action: "reuse", Round: e.Round, Since: e.SHA, AI: e.AI, Security: e.Security, Record: sync, Sync: sync}
	if recheck {
		d.Action, d.Record, d.RunAI, d.AIScope = "review", true, true, scopeReplies
	}
	return d
}

func (e entry) validate() error {
	if e.SHA == "" || strings.Trim(e.SHA, "0123456789abcdef") != "" || e.Round < 1 {
		return fmt.Errorf("entry needs a hex commit and a positive round: %+v", e)
	}
	if e.AI != verdictPass && e.AI != verdictChanges {
		return fmt.Errorf("AI verdict %q is not %s or %s", e.AI, verdictPass, verdictChanges)
	}
	if e.Security != verdictPass && e.Security != verdictChanges && e.Security != verdictNone {
		return fmt.Errorf("security verdict %q is not %s, %s or %s", e.Security, verdictPass, verdictChanges, verdictNone)
	}
	return nil
}

// add appends e, replacing an earlier entry for the same head.
func (r *record) add(e entry) {
	for i := range r.Entries {
		if r.Entries[i].SHA == e.SHA {
			r.Entries[i] = e
			return
		}
	}
	r.Entries = append(r.Entries, e)
}

func (r *record) render() (string, error) {
	state, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(marker + string(state) + markerEnd + "\n")
	b.WriteString("**AI 审核记录**（由审核工作流维护，请勿编辑）\n\n")
	b.WriteString("| 轮 | 提交 | AI 审核 | 安全审核 |\n|---|---|---|---|\n")
	for _, e := range r.Entries {
		commit := short(e.SHA)
		if e.Sync {
			commit += "（只同步了 main，沿用上一轮）"
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s |\n", e.Round, commit, verdictText(e.AI), verdictText(e.Security))
	}
	return b.String(), nil
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

func verdictText(verdict string) string {
	switch verdict {
	case verdictPass:
		return "通过"
	case verdictChanges:
		return "需要修改"
	default:
		return "不适用"
	}
}

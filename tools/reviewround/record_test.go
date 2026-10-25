package main

import (
	"strings"
	"testing"
)

func recordOf(entries ...entry) *record { return &record{Entries: entries} }

func TestDecide(t *testing.T) {
	failed1 := entry{SHA: "a1", Round: 1, AI: verdictChanges, Security: verdictNone}
	failed2 := entry{SHA: "b2", Round: 2, AI: verdictChanges, Security: verdictNone}
	failed3 := entry{SHA: "c3", Round: 3, AI: verdictChanges, Security: verdictNone}
	passed3 := entry{SHA: "c3", Round: 3, AI: verdictPass, Security: verdictNone}
	secured2 := entry{SHA: "b2", Round: 2, AI: verdictPass, Security: verdictChanges}
	cases := []struct {
		name string
		r    *record
		in   input
		want decision
	}{
		{"first round reviews everything", recordOf(),
			input{Head: "a1", Changes: -1, Tier: "medium"},
			decision{Action: "review", Round: 1, RunAI: true, AIScope: scopeFull, Security: verdictNone, Record: true}},
		{"first round of a high-risk PR adds a full security review", recordOf(),
			input{Head: "a1", Changes: -1, Tier: "high"},
			decision{Action: "review", Round: 1, RunAI: true, AIScope: scopeFull, RunSecurity: true, SecurityScope: scopeFull, Record: true}},
		{"same head reuses its verdict", recordOf(failed1),
			input{Head: "a1", Changes: 0, Tier: "medium"},
			decision{Action: "reuse", Round: 1, Since: "a1", AI: verdictChanges, Security: verdictNone}},
		{"syncing main reuses the last verdict", recordOf(failed1),
			input{Head: "a9", Changes: 0, Tier: "medium"},
			decision{Action: "reuse", Round: 1, Since: "a1", AI: verdictChanges, Security: verdictNone, Record: true, Sync: true}},
		{"second round still reviews everything", recordOf(failed1),
			input{Head: "b2", Changes: 1, Tier: "medium"},
			decision{Action: "review", Round: 2, RunAI: true, AIScope: scopeFull, Since: "a1", Security: verdictNone, Record: true}},
		{"third round reviews only the new changes", recordOf(failed1, failed2),
			input{Head: "c3", Changes: 1, Tier: "medium"},
			decision{Action: "review", Round: 3, RunAI: true, AIScope: scopeSince, Since: "b2", Security: verdictNone, Record: true}},
		{"rewritten history reviews everything", recordOf(failed1, failed2),
			input{Head: "c3", Changes: -1, Tier: "medium"},
			decision{Action: "review", Round: 3, RunAI: true, AIScope: scopeFull, Since: "b2", Security: verdictNone, Record: true}},
		{"a fourth round after a failed third stops", recordOf(failed1, failed2, failed3),
			input{Head: "d4", Changes: 1, Tier: "medium"},
			decision{Action: "stop", Round: 4, Since: "c3", Security: verdictNone}},
		{"a fourth round with consent goes on", recordOf(failed1, failed2, failed3),
			input{Head: "d4", Changes: 1, AllowMore: true, Tier: "medium"},
			decision{Action: "review", Round: 4, RunAI: true, AIScope: scopeSince, Since: "c3", Security: verdictNone, Record: true}},
		{"a fourth round after a passed third goes on", recordOf(failed1, failed2, passed3),
			input{Head: "d4", Changes: 1, Tier: "medium"},
			decision{Action: "review", Round: 4, RunAI: true, AIScope: scopeSince, Since: "c3", Security: verdictNone, Record: true}},
		{"syncing after three failed rounds does not stop", recordOf(failed1, failed2, failed3),
			input{Head: "c9", Changes: 0, Tier: "medium"},
			decision{Action: "reuse", Round: 3, Since: "c3", AI: verdictChanges, Security: verdictNone, Record: true, Sync: true}},
		{"a tier that rose to high gets a full security review", recordOf(failed1),
			input{Head: "a9", Changes: 0, Tier: "high"},
			decision{Action: "review", Round: 1, Since: "a1", AI: verdictChanges, Security: verdictNone, RunSecurity: true, SecurityScope: scopeFull, Record: true, Sync: true}},
		{"the first security review in a later round covers everything", recordOf(failed1, failed2),
			input{Head: "c3", Changes: 1, Tier: "high"},
			decision{Action: "review", Round: 3, RunAI: true, AIScope: scopeSince, RunSecurity: true, SecurityScope: scopeFull, Since: "b2", Record: true}},
		{"security after a stretch below high covers everything",
			recordOf(entry{SHA: "a1", Round: 1, AI: verdictChanges, Security: verdictPass}, failed2),
			input{Head: "c3", Changes: 1, Tier: "high"},
			decision{Action: "review", Round: 3, RunAI: true, AIScope: scopeSince, RunSecurity: true, SecurityScope: scopeFull, Since: "b2", Record: true}},
		{"later security reviews follow the AI scope", recordOf(failed1, secured2),
			input{Head: "c3", Changes: 1, Tier: "high"},
			decision{Action: "review", Round: 3, RunAI: true, AIScope: scopeSince, RunSecurity: true, SecurityScope: scopeSince, Since: "b2", Record: true}},
		{"a recheck re-reads the replies on the same code", recordOf(failed1, secured2),
			input{Head: "b2", Changes: 0, Recheck: true, Tier: "high"},
			decision{Action: "review", Round: 2, RunAI: true, AIScope: scopeReplies, RunSecurity: true, SecurityScope: scopeReplies, Since: "b2", AI: verdictPass, Security: verdictChanges, Record: true}},
		{"a recheck leaves a passed security review alone",
			recordOf(entry{SHA: "b2", Round: 2, AI: verdictChanges, Security: verdictPass}),
			input{Head: "b2", Changes: 0, Recheck: true, Tier: "high"},
			decision{Action: "review", Round: 2, RunAI: true, AIScope: scopeReplies, Since: "b2", AI: verdictChanges, Security: verdictPass, Record: true}},
		{"a tier that dropped no longer needs security", recordOf(secured2),
			input{Head: "b2", Changes: 0, Tier: "medium"},
			decision{Action: "reuse", Round: 2, Since: "b2", AI: verdictPass, Security: verdictNone}},
	}
	for _, c := range cases {
		if got := c.r.decide(c.in); got != c.want {
			t.Errorf("%s:\n got  %+v\n want %+v", c.name, got, c.want)
		}
	}
}

func TestRecordRoundTrip(t *testing.T) {
	r := recordOf()
	r.add(entry{SHA: "0123456789abcdef", Round: 1, AI: verdictChanges, Security: verdictNone})
	r.add(entry{SHA: "fedcba9876543210", Round: 1, AI: verdictChanges, Security: verdictNone, Sync: true})
	r.add(entry{SHA: "0123456789abcdef", Round: 1, AI: verdictPass, Security: verdictNone})
	body, err := r.render()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(body, marker) || !strings.Contains(body, "| 1 | 0123456 | 通过 | 不适用 |") || !strings.Contains(body, "只同步了 main") {
		t.Errorf("unexpected record comment:\n%s", body)
	}
	parsed, err := parseRecord(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Entries) != 2 || parsed.Entries[0].AI != verdictPass || parsed.lastHead() != "fedcba9876543210" {
		t.Errorf("round trip lost data: %+v", parsed.Entries)
	}
}

func TestParseRecordRejects(t *testing.T) {
	r, err := parseRecord("an unrelated comment")
	if err != nil || len(r.Entries) != 0 || r.lastHead() != "" {
		t.Errorf("parseRecord = %+v, %v", r, err)
	}
	for _, body := range []string{
		marker + `{"entries": [`,
		marker + `{"entries": [{"sha": "a1", "round": 1, "ai": "pass\ntier=low", "security": "n/a"}]}` + markerEnd,
		marker + `{"entries": [{"sha": "not-hex", "round": 1, "ai": "pass", "security": "n/a"}]}` + markerEnd,
	} {
		if _, err := parseRecord(body); err == nil {
			t.Errorf("parseRecord accepted %q", body)
		}
	}
}

func TestEntryValidate(t *testing.T) {
	good := entry{SHA: "a1", Round: 1, AI: verdictPass, Security: verdictNone}
	if err := good.validate(); err != nil {
		t.Errorf("valid entry rejected: %v", err)
	}
	for _, bad := range []entry{
		{Round: 1, AI: verdictPass, Security: verdictNone},
		{SHA: "a1", AI: verdictPass, Security: verdictNone},
		{SHA: "a1", Round: 1, AI: "maybe", Security: verdictNone},
		{SHA: "a1", Round: 1, AI: verdictPass, Security: ""},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("invalid entry accepted: %+v", bad)
		}
	}
}

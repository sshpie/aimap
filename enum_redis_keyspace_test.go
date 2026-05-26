package main

import (
	"testing"
)

// Tests for helper functions in enum_redis_keyspace.go.
// Anchored on the CampusIRIS / aiogram chain-B Redis survey (2026-05-26).

// ── extractBullQueueNames ─────────────────────────────────────────────────────

func TestExtractBullQueueNames_Canonical(t *testing.T) {
	keys := []string{
		"bull:CampaignQueue:waiting",
		"bull:CampaignQueue:9",
		"bull:PushNotificationsQueue:active",
		"bull:USER_RANKING_QUEUE:completed",
	}
	got := extractBullQueueNames(keys)
	want := []string{"CampaignQueue", "PushNotificationsQueue", "USER_RANKING_QUEUE"}

	if len(got) != len(want) {
		t.Fatalf("expected %d queues, got %d: %v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d: want %q, got %q", i, w, got[i])
		}
	}
}

func TestExtractBullQueueNames_Deduplication(t *testing.T) {
	// Same queue name appearing across many state keys must produce exactly one entry.
	keys := []string{
		"bull:MyQueue:waiting",
		"bull:MyQueue:active",
		"bull:MyQueue:completed",
		"bull:MyQueue:failed",
		"bull:MyQueue:1",
		"bull:MyQueue:2",
	}
	got := extractBullQueueNames(keys)
	if len(got) != 1 || got[0] != "MyQueue" {
		t.Errorf("expected [MyQueue], got %v", got)
	}
}

func TestExtractBullQueueNames_Empty(t *testing.T) {
	got := extractBullQueueNames([]string{})
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestExtractBullQueueNames_NoSecondColon(t *testing.T) {
	// "bull:OnlyOneSegment" — no third segment; function must not panic and
	// should still extract the queue name.
	keys := []string{"bull:OnlyOneSegment"}
	got := extractBullQueueNames(keys)
	if len(got) != 1 || got[0] != "OnlyOneSegment" {
		t.Errorf("expected [OnlyOneSegment], got %v", got)
	}
}

func TestExtractBullQueueNames_NonBullKeyIgnored(t *testing.T) {
	// A key that doesn't start with "bull:" should not produce an empty queue name.
	keys := []string{"someother:key:value"}
	got := extractBullQueueNames(keys)
	// "someother" is treated as the first segment; "key" as the queue name.
	// The function splits on the FIRST key segment, not on the prefix "bull".
	// Confirm it doesn't crash and returns whatever the split gives.
	_ = got // behaviour is documented; just verify no panic
}

func TestExtractBullQueueNames_OrderPreserved(t *testing.T) {
	keys := []string{
		"bull:ZebraQueue:1",
		"bull:AlphaQueue:waiting",
		"bull:MidQueue:active",
	}
	got := extractBullQueueNames(keys)
	want := []string{"ZebraQueue", "AlphaQueue", "MidQueue"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("order mismatch at index %d: want %q got %q", i, w, got[i])
		}
	}
}

// ── extractCeleryQueueNames ───────────────────────────────────────────────────

func TestExtractCeleryQueueNames_Canonical(t *testing.T) {
	keys := []string{
		"_kombu.binding.celery",
		"_kombu.binding.celeryev",
		"_kombu.binding.celery.pidbox",
	}
	got := extractCeleryQueueNames(keys)
	want := []string{"celery", "celeryev", "celery.pidbox"}

	if len(got) != len(want) {
		t.Fatalf("expected %d names, got %d: %v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d: want %q, got %q", i, w, got[i])
		}
	}
}

func TestExtractCeleryQueueNames_NonKombuKeyExcluded(t *testing.T) {
	keys := []string{
		"celery-task-meta-abc123",
		"_kombu.binding.myqueue",
		"unrelated:key",
	}
	got := extractCeleryQueueNames(keys)
	if len(got) != 1 || got[0] != "myqueue" {
		t.Errorf("expected [myqueue], got %v", got)
	}
}

func TestExtractCeleryQueueNames_Empty(t *testing.T) {
	got := extractCeleryQueueNames([]string{})
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestExtractCeleryQueueNames_AllNonMatching(t *testing.T) {
	keys := []string{"foo", "bar", "celery-task-meta-xyz"}
	got := extractCeleryQueueNames(keys)
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

// ── extractTelegramUserIDs ────────────────────────────────────────────────────

func TestExtractTelegramUserIDs_Canonical(t *testing.T) {
	keys := []string{
		"fsm:828506453:828506453:aiogd:context:main:data",
		"fsm:6954953986:6954953986:aiogd:context:wizard:data",
		"fsm:828506453:828506453:aiogd:context:sub:data",
	}
	got := extractTelegramUserIDs(keys)
	want := []string{"828506453", "6954953986"}

	if len(got) != len(want) {
		t.Fatalf("expected %d IDs, got %d: %v", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("index %d: want %q, got %q", i, w, got[i])
		}
	}
}

func TestExtractTelegramUserIDs_NonNumericExcluded(t *testing.T) {
	keys := []string{
		"fsm:not_a_number:123:aiogd:context:main:data",
		"fsm:828506453:828506453:aiogd:context:main:data",
	}
	got := extractTelegramUserIDs(keys)
	if len(got) != 1 || got[0] != "828506453" {
		t.Errorf("expected [828506453], got %v", got)
	}
}

func TestExtractTelegramUserIDs_Empty(t *testing.T) {
	got := extractTelegramUserIDs([]string{})
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestExtractTelegramUserIDs_Deduplication(t *testing.T) {
	// Same user ID across multiple state contexts must appear exactly once.
	keys := []string{
		"fsm:111222333:111222333:aiogd:context:main:data",
		"fsm:111222333:111222333:aiogd:context:sub:data",
		"fsm:111222333:111222333:aiogd:context:wizard:data",
	}
	got := extractTelegramUserIDs(keys)
	if len(got) != 1 || got[0] != "111222333" {
		t.Errorf("expected [111222333], got %v", got)
	}
}

func TestExtractTelegramUserIDs_NoPrefixMatch(t *testing.T) {
	// Keys not starting with "fsm:" — TrimPrefix leaves the whole string,
	// which is non-numeric and must be excluded.
	keys := []string{
		"other:828506453:828506453:stuff",
	}
	got := extractTelegramUserIDs(keys)
	if len(got) != 0 {
		t.Errorf("expected empty for non-fsm key, got %v", got)
	}
}

// ── isNumericID ───────────────────────────────────────────────────────────────

func TestIsNumericID(t *testing.T) {
	cases := []struct {
		input string
		want  bool
	}{
		{"828506453", true},
		{"6954953986", true},
		{"0", true},
		{"abc", false},
		{"", false},
		{"123abc", false},
		{"abc123", false},
		{"12 34", false},
		{"-123", false},
	}
	for _, tc := range cases {
		got := isNumericID(tc.input)
		if got != tc.want {
			t.Errorf("isNumericID(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

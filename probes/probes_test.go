package probes

import (
	"strings"
	"testing"
)

func TestProbesCatalog(t *testing.T) {
	all := All()
	if len(all) != 15 {
		t.Fatalf("expected 15 probes, got %d", len(all))
	}

	foundTagPlane := false
	foundAnsi := false
	foundIndirectDoc := false

	for _, p := range all {
		if p.ID == "" || p.Payload == "" || p.Description == "" {
			t.Errorf("probe %s has empty fields", p.ID)
		}
		if len(p.Signatures) == 0 {
			t.Errorf("probe %s has no signatures", p.ID)
		}
		if p.ID == "PROMPT-INJECT-004" {
			foundTagPlane = true
			if !strings.Contains(p.Description, "Unicode") {
				t.Errorf("expected Unicode description, got %s", p.Description)
			}
		}
		if p.ID == "PROMPT-INJECT-005" {
			foundIndirectDoc = true
			if !strings.Contains(p.Description, "document") {
				t.Errorf("expected document description, got %s", p.Description)
			}
		}
		if p.ID == "OUTPUT-HANDLING-002" {
			foundAnsi = true
			if !strings.Contains(p.Description, "ANSI") {
				t.Errorf("expected ANSI description, got %s", p.Description)
			}
		}
	}

	if !foundTagPlane {
		t.Error("PROMPT-INJECT-004 probe not found")
	}
	if !foundIndirectDoc {
		t.Error("PROMPT-INJECT-005 probe not found")
	}
	if !foundAnsi {
		t.Error("OUTPUT-HANDLING-002 probe not found")
	}
}

func TestTagEncode(t *testing.T) {
	plain := "HELLO"
	encoded := TagEncode(plain)
	runes := []rune(encoded)

	if len(runes) != len(plain) {
		t.Fatalf("expected %d runes, got %d", len(plain), len(runes))
	}
	for i, r := range runes {
		expected := rune(0xE0000 + int(plain[i]))
		if r != expected {
			t.Errorf("rune %d: expected 0x%X, got 0x%X", i, expected, r)
		}
	}
}

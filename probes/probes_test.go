package probes

import "testing"

func TestProbesDecryption(t *testing.T) {
	all := All()
	if len(all) == 0 {
		t.Fatal("expected probes, got 0")
	}
	for _, p := range all {
		if p.ID == "" || p.Payload == "" || p.Description == "" {
			t.Errorf("probe %s has empty fields", p.ID)
		}
		if len(p.Signatures) == 0 {
			t.Errorf("probe %s has no signatures", p.ID)
		}
	}
}
